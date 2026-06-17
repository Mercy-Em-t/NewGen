require('dotenv').config();
const express = require('express');
const fs = require('fs');
const path = require('path');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const { createClient } = require('@supabase/supabase-js');
const cookieParser = require('cookie-parser');
const xss = require('xss');
const { z } = require('zod');

const app = express();
const PORT = process.env.PORT || 3000;

// ACTIVITY LOGGER: Appends server events cleanly to a local history file
function logActivity(username, action, status = 'SUCCESS') {
    const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19);
    const logLine = `[${timestamp}] User: '${username}' | Action: ${action} | Status: ${status}\n`;
    
    const logPath = path.join(__dirname, 'logs.txt');
    
    fs.appendFile(logPath, logLine, 'utf8', (err) => {
        if (err) console.error('⚠️ Critical: Failed to write to system audit log:', err);
    });
}

// SYSTEM CONFIGURATION
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_ANON_KEY;
const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

// Cloudinary Configuration
cloudinary.config({ 
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME, 
  api_key: process.env.CLOUDINARY_API_KEY, 
  api_secret: process.env.CLOUDINARY_API_SECRET 
});

// Configure Multer to use Cloudinary
const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'nexus_cms_uploads',
    allowedFormats: ['jpg', 'png', 'jpeg', 'webp'],
  },
});
const upload = multer({ storage: storage });

// Middleware
app.use(express.json());
app.use(cookieParser());
app.use(express.static(__dirname)); // Serve HTML files

// SECURITY MIDDLEWARE: Verifies Supabase session
async function authenticateToken(req, res, next) {
    const token = req.cookies.auth_token;
    
    if (!token) {
        return res.status(401).json({ success: false, message: 'Access Denied: Log in required.' });
    }

    const { data, error } = await supabase.auth.getUser(token);
    
    if (error || !data.user) {
        return res.status(403).json({ success: false, message: 'Invalid or expired session token.' });
    }
    
    req.user = data.user;
    next();
}

// API: Handle User Login via Supabase
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body; // Using username field as email for Supabase

    const { data, error } = await supabase.auth.signInWithPassword({
        email: username, 
        password: password
    });

    if (error) {
        return res.status(400).json({ success: false, message: error.message });
    }

    // Send Supabase access token as a cookie securely to browser
    res.cookie('auth_token', data.session.access_token, {
        httpOnly: true,
        secure: false, // Set to true if running on HTTPS production site
        maxAge: 2 * 60 * 60 * 1000 // 2 hours
    });

    logActivity(data.user.id, 'USER_LOGIN', 'SUCCESS');

    res.json({ success: true, message: 'Authentication successful.', user_id: data.user.id });
});

// API: Handle User Registration (New route for multi-user)
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body; 
    
    const { data, error } = await supabase.auth.signUp({
        email: username,
        password: password
    });

    if (error) {
        return res.status(400).json({ success: false, message: error.message });
    }

    res.json({ success: true, message: 'Registration successful! You can now log in.' });
});

// Deep merge utility to ensure structurally sound data
function mergeDeep(target, source) {
    if (!source) return target;
    const output = Object.assign({}, target);
    for (const key of Object.keys(source)) {
        if (source[key] instanceof Object && !Array.isArray(source[key])) {
            if (!(key in target)) Object.assign(output, { [key]: source[key] });
            else output[key] = mergeDeep(target[key], source[key]);
        } else {
            Object.assign(output, { [key]: source[key] });
        }
    }
    return output;
}

// Data Migration for Draft vs Published and Localization Matrix
function migrateData(data) {
    if (!data || !data.draft) {
        // Legacy data format upgrade
        return {
            draft: { en: data, es: data },
            published: { en: data, es: data }
        };
    }
    return data;
}

// API: Fetch Public Data (For INDEX.HTML)
app.get('/api/data', async (req, res) => {
    const userId = req.query.user_id;
    const lang = req.query.lang || 'en';
    
    if (!userId) {
        return res.status(400).json({ success: false, message: 'Missing user_id query parameter.' });
    }

    const defaultData = JSON.parse(fs.readFileSync(path.join(__dirname, 'data.json'), 'utf8'));
    const defaultMatrix = migrateData(defaultData);

    const { data, error } = await supabase
        .from('cms_data')
        .select('data')
        .eq('user_id', userId)
        .single();

    if (error || !data) {
        return res.json(defaultMatrix.published[lang]); // Fallback to beautiful default if no data yet
    }

    const matrix = migrateData(data.data);
    res.json(mergeDeep(defaultMatrix.published[lang], matrix.published[lang]));
});

// SECURED API: Fetch Admin Data
app.get('/api/admin-data', authenticateToken, async (req, res) => {
    const defaultData = JSON.parse(fs.readFileSync(path.join(__dirname, 'data.json'), 'utf8'));
    const defaultMatrix = migrateData(defaultData);

    const { data, error } = await supabase
        .from('cms_data')
        .select('data')
        .eq('user_id', req.user.id)
        .single();

    if (error || !data) {
        return res.json(defaultMatrix); 
    }

    const matrix = migrateData(data.data);
    
    // Merge defaults recursively for en and es
    matrix.draft.en = mergeDeep(defaultMatrix.draft.en, matrix.draft.en);
    matrix.draft.es = mergeDeep(defaultMatrix.draft.es, matrix.draft.es);
    matrix.published.en = mergeDeep(defaultMatrix.published.en, matrix.published.en);
    matrix.published.es = mergeDeep(defaultMatrix.published.es, matrix.published.es);

    res.json(matrix);
});

// SECURED API: Get current user ID
app.get('/api/me', authenticateToken, (req, res) => {
    res.json({ user_id: req.user.id });
});

// API: Verify current session status for page routing
app.get('/api/verify-session', authenticateToken, (req, res) => {
    res.json({ success: true });
});

// Recursive Sanitization Function
function sanitizeData(obj) {
    if (typeof obj === 'string') {
        return xss(obj);
    } else if (Array.isArray(obj)) {
        return obj.map(item => sanitizeData(item));
    } else if (typeof obj === 'object' && obj !== null) {
        const sanitizedObj = {};
        for (const [key, value] of Object.entries(obj)) {
            sanitizedObj[key] = sanitizeData(value);
        }
        return sanitizedObj;
    }
    return obj;
}

// API: Handle User Logout
app.post('/api/logout', (req, res) => {
    logActivity('admin', 'USER_LOGOUT', 'SUCCESS');
    res.clearCookie('auth_token');
    res.json({ success: true, message: 'Logged out.' });
});

// Zod Schema Guard
const cmsSchema = z.object({
    brand: z.object({ name: z.string().min(1) }).passthrough(),
    hero: z.object({ tagline: z.string(), headline: z.string(), subtext: z.string(), bgImage: z.string().optional() }).passthrough(),
    servicesSection: z.object({ title: z.string(), items: z.array(z.any()) }).passthrough(),
    processSection: z.any(),
    projectsSection: z.any(),
    stats: z.array(z.any()),
    nav: z.array(z.any())
});

// SECURED API: Save data
app.post('/api/save-data', authenticateToken, async (req, res) => {
    const { mode, lang, payload } = req.body;

    if (!['draft', 'publish'].includes(mode) || !['en', 'es'].includes(lang)) {
        return res.status(400).json({ success: false, message: 'Invalid mode or language' });
    }

    try {
        cmsSchema.parse(payload);
    } catch (err) {
        logActivity(req.user.id, 'MUTATE_CMS_DATA', 'FAILED_VALIDATION');
        return res.status(400).json({ success: false, message: 'Data failed schema validation guards.', errors: err.errors });
    }

    const cleanData = sanitizeData(payload);

    // Fetch existing matrix
    const { data: existingData } = await supabase.from('cms_data').select('data').eq('user_id', req.user.id).single();
    let matrix = existingData ? migrateData(existingData.data) : migrateData(JSON.parse(fs.readFileSync(path.join(__dirname, 'data.json'), 'utf8')));

    // Apply updates
    matrix.draft[lang] = cleanData;
    if (mode === 'publish') {
        matrix.published[lang] = cleanData;
    }

    const { error } = await supabase
        .from('cms_data')
        .upsert({ user_id: req.user.id, data: matrix }, { onConflict: 'user_id' });
        
    if (error) {
        console.error(error);
        logActivity(req.user.id, 'MUTATE_CMS_DATA', 'FAILED_WRITE');
        return res.status(500).json({ success: false, message: 'Database write failed: ' + error.message });
    }

    logActivity(req.user.id, `MUTATE_CMS_DATA_${mode.toUpperCase()}`, 'SUCCESS');

    res.json({ success: true, message: `Website ${mode === 'publish' ? 'published live' : 'saved as draft'} securely!` });
});

// SECURED API: Image uploads
app.post('/api/upload-image', authenticateToken, upload.single('image'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ success: false, message: 'No file uploaded.' });
    }
    const imageUrl = req.file.path;
    res.json({ success: true, imageUrl });
});

// SECURED API: Read and return historically uploaded graphic files from Cloudinary
app.get('/api/media', authenticateToken, async (req, res) => {
    try {
        const result = await cloudinary.search
            .expression('folder:nexus_cms_uploads')
            .sort_by('created_at', 'desc')
            .max_results(30)
            .execute();
            
        const fileUrls = result.resources.map(file => file.secure_url);
        res.json({ success: true, media: fileUrls });
    } catch (err) {
        console.error('Cloudinary fetch error:', err);
        return res.status(500).json({ success: false, message: 'Unable to fetch media from Cloudinary.' });
    }
});

// SECURED API: Soft Delete Media Asset
app.post('/api/delete-media', authenticateToken, async (req, res) => {
    const { url } = req.body;
    try {
        const urlParts = url.split('/');
        const fileWithExt = urlParts[urlParts.length - 1];
        const folder = urlParts[urlParts.length - 2]; 
        const filename = fileWithExt.split('.')[0];
        const publicId = `${folder}/${filename}`;
        
        // Soft delete: rename/move to a trash folder so it is hidden from the UI but never lost
        const trashPublicId = `nexus_cms_trash/${filename}-${Date.now()}`;
        await cloudinary.uploader.rename(publicId, trashPublicId);
        
        logActivity(req.user.id, `SOFT_DELETE_MEDIA`, `Archived ${publicId} to trash`);
        res.json({ success: true, message: 'Asset archived safely.' });
    } catch (err) {
        console.error('Soft delete error:', err);
        logActivity(req.user.id, 'DELETE_MEDIA', 'FAILED');
        return res.status(500).json({ success: false, message: 'Failed to archive asset.' });
    }
});

app.listen(PORT, () => {
    console.log(`\n🚀 Secure CMS Server Active on http://localhost:${PORT}/login.html`);
});
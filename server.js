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

const app = express();
const PORT = process.env.PORT || 3000;

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

// API: Fetch Public Data (For INDEX.HTML)
app.get('/api/data', async (req, res) => {
    const userId = req.query.user_id;
    
    if (!userId) {
        return res.status(400).json({ success: false, message: 'Missing user_id query parameter.' });
    }

    const { data, error } = await supabase
        .from('cms_data')
        .select('data')
        .eq('user_id', userId)
        .single();

    if (error || !data) {
        return res.status(404).json({ success: false, message: 'No data found for this user.' });
    }

    res.json(data.data);
});

// SECURED API: Fetch Admin Data
app.get('/api/admin-data', authenticateToken, async (req, res) => {
    const { data, error } = await supabase
        .from('cms_data')
        .select('data')
        .eq('user_id', req.user.id)
        .single();

    if (error || !data) {
        // Return empty so the admin panel doesn't crash on new accounts
        return res.json({}); 
    }

    res.json(data.data);
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
    res.clearCookie('auth_token');
    res.json({ success: true, message: 'Logged out.' });
});

// SECURED API: Save data
app.post('/api/save-data', authenticateToken, async (req, res) => {
    const cleanData = sanitizeData(req.body);
    const { data, error } = await supabase
        .from('cms_data')
        .upsert({ user_id: req.user.id, data: cleanData }, { onConflict: 'user_id' });
        
    if (error) {
        console.error(error);
        return res.status(500).json({ success: false, message: 'Database write failed: ' + error.message });
    }
    res.json({ success: true, message: 'Website updated securely in the cloud!' });
});

// SECURED API: Image uploads
app.post('/api/upload-image', authenticateToken, upload.single('image'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ success: false, message: 'No file uploaded.' });
    }
    const imageUrl = req.file.path;
    res.json({ success: true, imageUrl });
});

app.listen(PORT, () => {
    console.log(`\n🚀 Secure CMS Server Active on http://localhost:${PORT}/login.html`);
});
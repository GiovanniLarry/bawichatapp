require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const http = require('http');
const socketIO = require('socket.io');
const CryptoJS = require('crypto-js');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const cron = require('node-cron');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// Create uploads directory if it doesn't exist
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/');
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname);
    cb(null, 'profile-' + uniqueSuffix + ext);
  }
});

const upload = multer({ 
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
  fileFilter: function (req, file, cb) {
    const filetypes = /jpeg|jpg|png|gif/;
    const mimetype = filetypes.test(file.mimetype);
    const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
    
    if (mimetype && extname) {
      return cb(null, true);
    }
    cb(new Error("Only image files are allowed!"));
  }
});

// Configure multer for audio uploads
const audioStorage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/audio/');
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname);
    cb(null, 'audio-' + uniqueSuffix + ext);
  }
});

const audioUpload = multer({ 
  storage: audioStorage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit for audio
  fileFilter: function (req, file, cb) {
    const audioTypes = /mp3|wav|ogg|m4a|webm/;
    const mimetype = audioTypes.test(file.mimetype);
    const extname = audioTypes.test(path.extname(file.originalname).toLowerCase());
    
    if (mimetype && extname) {
      return cb(null, true);
    }
    cb(new Error("Only audio files are allowed!"));
  }
});

// Photo upload configuration
const photoStorage = multer.diskStorage({
  destination: function (req, file, cb) {
    const photoDir = path.join(__dirname, 'uploads', 'photos');
    if (!fs.existsSync(photoDir)) {
      fs.mkdirSync(photoDir, { recursive: true });
    }
    cb(null, photoDir);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, 'photo-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const photoUpload = multer({ 
  storage: photoStorage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit for photos
  fileFilter: function (req, file, cb) {
    const imageTypes = /jpeg|jpg|png|gif|webp/;
    const mimetype = imageTypes.test(file.mimetype);
    const extname = imageTypes.test(path.extname(file.originalname).toLowerCase());
    
    if (mimetype && extname) {
      return cb(null, true);
    }
    cb(new Error("Only image files are allowed!"));
  }
});

// Video upload configuration
const videoStorage = multer.diskStorage({
  destination: function (req, file, cb) {
    const videoDir = path.join(__dirname, 'uploads', 'videos');
    if (!fs.existsSync(videoDir)) {
      fs.mkdirSync(videoDir, { recursive: true });
    }
    cb(null, videoDir);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, 'video-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const videoUpload = multer({ 
  storage: videoStorage,
  limits: { fileSize: 50 * 1024 * 1024 }, // 50MB limit for videos
  fileFilter: function (req, file, cb) {
    const videoTypes = /mp4|webm|avi|mov|mkv/;
    const mimetype = videoTypes.test(file.mimetype);
    const extname = videoTypes.test(path.extname(file.originalname).toLowerCase());
    
    if (mimetype && extname) {
      return cb(null, true);
    }
    cb(new Error("Only video files are allowed!"));
  }
});

// General file upload configuration
const fileStorage = multer.diskStorage({
  destination: function (req, file, cb) {
    let uploadDir;
    const fileType = file.mimetype;
    
    if (fileType.startsWith('image/')) {
      uploadDir = path.join(__dirname, 'uploads', 'images');
    } else if (fileType.startsWith('video/')) {
      uploadDir = path.join(__dirname, 'uploads', 'videos');
    } else {
      uploadDir = path.join(__dirname, 'uploads', 'documents');
    }
    
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, 'file-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const fileUpload = multer({ 
  storage: fileStorage,
  limits: { fileSize: 100 * 1024 * 1024 }, // 100MB limit for files
  fileFilter: function (req, file, cb) {
    // More permissive file type checking
    const fileType = file.mimetype;
    const fileName = file.originalname.toLowerCase();
    
    // Allow images
    if (fileType.startsWith('image/')) {
      return cb(null, true);
    }
    
    // Allow videos
    if (fileType.startsWith('video/')) {
      return cb(null, true);
    }
    
    // Allow common document types
    const allowedExtensions = ['.pdf', '.doc', '.docx', '.txt', '.xls', '.xlsx', '.ppt', '.pptx'];
    const hasAllowedExtension = allowedExtensions.some(ext => fileName.endsWith(ext));
    
    if (hasAllowedExtension) {
      return cb(null, true);
    }
    
    // Allow files with common MIME types
    const allowedMimeTypes = [
      'application/pdf',
      'application/msword',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      'text/plain',
      'application/vnd.ms-excel',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      'application/vnd.ms-powerpoint',
      'application/vnd.openxmlformats-officedocument.presentationml.presentation'
    ];
    
    if (allowedMimeTypes.includes(fileType)) {
      return cb(null, true);
    }
    
    cb(new Error("File type not allowed!"));
  }
});

// Create audio uploads directory if it doesn't exist
const audioUploadDir = path.join(__dirname, 'uploads', 'audio');
if (!fs.existsSync(audioUploadDir)) {
  fs.mkdirSync(audioUploadDir, { recursive: true });
}

// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/userProfileApp', {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('MongoDB connected'))
.catch(err => console.error('MongoDB connection error:', err));

// Define User Schema
const UserSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true
  },
  password: {
    type: String,
    required: true
  },
  firebaseUid: {
    type: String,
    sparse: true,
    index: true
  },
  username: {
    type: String,
    unique: true,
    sparse: true
  },
  profilePicture: String,
  gender: {
    type: String,
    enum: ['male', 'female']
  },
  age: {
    type: Number,
    min: 13
  },
  bio: String,
  profileCompleted: {
    type: Boolean,
    default: false
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  platform: String, // Added field for platform
  lastSeen: Date
});

const User = mongoose.model('User', UserSchema);

// Admin Schema
const AdminSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true
  },
  password: {
    type: String,
    required: true
  },
  email: {
    type: String,
    required: true,
    unique: true
  },
  role: {
    type: String,
    enum: ['super_admin', 'admin', 'moderator'],
    default: 'admin'
  },
  permissions: [{
    type: String,
    enum: ['manage_users', 'manage_reports', 'view_analytics', 'manage_rooms', 'ban_users']
  }],
  lastLogin: Date,
  createdAt: {
    type: Date,
    default: Date.now
  }
});

const Admin = mongoose.model('Admin', AdminSchema);

// User Ban Schema
const UserBanSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  bannedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Admin',
    required: true
  },
  reason: {
    type: String,
    required: true
  },
  banType: {
    type: String,
    enum: ['temporary', 'permanent'],
    required: true
  },
  duration: {
    type: Number, // in hours, 0 for permanent
    default: 0
  },
  expiresAt: Date,
  isActive: {
    type: Boolean,
    default: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

const UserBan = mongoose.model('UserBan', UserBanSchema);

// Analytics Schema
const AnalyticsSchema = new mongoose.Schema({
  date: {
    type: Date,
    required: true
  },
  newUsers: {
    type: Number,
    default: 0
  },
  activeUsers: {
    type: Number,
    default: 0
  },
  messagesSent: {
    type: Number,
    default: 0
  },
  roomsCreated: {
    type: Number,
    default: 0
  },
  reportsSubmitted: {
    type: Number,
    default: 0
  },
  fileUploads: {
    type: Number,
    default: 0
  }
});

const Analytics = mongoose.model('Analytics', AnalyticsSchema);

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static('public'));
app.use(express.static(__dirname)); // Serve files from root directory
app.use('/uploads', express.static('uploads'));

// Set up session
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-secret-key',
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ 
    mongoUrl: 'mongodb://localhost:27017/userProfileApp',
    collectionName: 'sessions'
  }),
  cookie: {
    maxAge: 1000 * 60 * 60 * 24 // 1 day
  }
}));

// Set view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Firebase Authentication Route
app.post('/api/firebase-auth', async (req, res) => {
  try {
    const { email, uid, displayName, photoURL } = req.body;
    
    if (!email || !uid) {
      return res.status(400).json({ error: 'Missing required Firebase auth data' });
    }
    
    console.log('Firebase auth request:', { email, uid, displayName });
    
    // Check if user already exists with this email
    let user = await User.findOne({ email });
    
    if (!user) {
      // Create a new user if one doesn't exist
      user = new User({
        email,
        password: await bcrypt.hash(Math.random().toString(36).slice(-8), 10), // Random secure password
        firebaseUid: uid,
        profileCompleted: false
      });
      
      // If we have a display name from Google, we can pre-fill the username
      if (displayName) {
        // Convert display name to a valid username (lowercase, no spaces)
        const suggestedUsername = displayName.toLowerCase().replace(/\s+/g, '');
        
        // Check if this username is already taken
        const existingUsername = await User.findOne({ username: suggestedUsername });
        if (!existingUsername) {
          user.username = suggestedUsername;
        }
      }
      
      // If we have a profile picture URL from Google, save it
      if (photoURL) {
        user.profilePicture = photoURL;
      }
      
      await user.save();
      console.log('Created new Firebase user:', email);
    } else {
      // Update existing user with Firebase UID if not already set
      if (!user.firebaseUid) {
        user.firebaseUid = uid;
        await user.save();
      }
      console.log('Existing user found:', email);
    }
    
    // Set session
    req.session.userId = user._id;
    
    // Redirect based on profile completion status
    if (user.profileCompleted) {
      res.json({ success: true, redirectUrl: '/dashboard' });
    } else {
      res.json({ success: true, redirectUrl: '/complete-profile?source=google' });
    }
  } catch (err) {
    console.error('Error in Firebase auth:', err);
    res.status(500).json({ error: 'Authentication failed', details: err.message });
  }
});

app.get('/signup', (req, res) => {
  res.sendFile(path.join(__dirname, 'signup.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'login.html'));
});

// User registration
app.post('/api/signup', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'Email already registered' });
    }
    
    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    
    // Detect platform from user agent
    let platform = 'Desktop'; // Default
    const userAgent = req.headers['user-agent'] || '';
    
    if (userAgent.includes('Mobile') || userAgent.includes('Android') || userAgent.includes('iPhone')) {
      platform = 'Mobile';
    } else if (userAgent.includes('iPad') || userAgent.includes('Tablet')) {
      platform = 'Tablet';
    }
    
    // Create new user with platform info
    const newUser = new User({
      email,
      password: hashedPassword,
      platform: platform,
      lastSeen: new Date()
    });
    
    await newUser.save();
    
    // Set user session
    req.session.userId = newUser._id;
    
    res.status(201).json({ 
      success: true, 
      message: 'Account created successfully',
      redirectUrl: '/complete-profile'
    });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// User login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Find user by email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }
    
    // Validate password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }
    
    // Detect platform from user agent
    let platform = 'Desktop'; // Default
    const userAgent = req.headers['user-agent'] || '';
    
    if (userAgent.includes('Mobile') || userAgent.includes('Android') || userAgent.includes('iPhone')) {
      platform = 'Mobile';
    } else if (userAgent.includes('iPad') || userAgent.includes('Tablet')) {
      platform = 'Tablet';
    }
    
    // Update user's platform and last seen
    await User.findByIdAndUpdate(user._id, {
      platform: platform,
      lastSeen: new Date()
    });
    
    // Set user session
    req.session.userId = user._id;
    
    // Redirect based on profile completion
    const redirectUrl = user.profileCompleted ? '/dashboard' : '/complete-profile';
    
    res.json({ 
      success: true, 
      message: 'Login successful',
      redirectUrl
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Complete profile page
app.get('/complete-profile', (req, res) => {
  if (!req.session.userId) {
    return res.redirect('/login');
  }
  res.sendFile(path.join(__dirname, 'complete-profile.html'));
});

// Complete profile submission
app.post('/api/complete-profile', upload.single('profilePicture'), async (req, res) => {
  try {
    if (!req.session.userId) {
      return res.status(401).json({ error: 'Not authenticated' });
    }
    
    const { username, gender, age, bio } = req.body;
    
    // Validate age
    const ageNum = parseInt(age);
    if (isNaN(ageNum) || ageNum < 13) {
      return res.status(400).json({ error: 'You must be at least 13 years old to use this service' });
    }
    
    // Check if username is already taken
    const existingUsername = await User.findOne({ username, _id: { $ne: req.session.userId } });
    if (existingUsername) {
      return res.status(400).json({ error: 'Username already taken' });
    }
    
    // Update user profile
    const updateData = {
      username,
      gender,
      age: ageNum,
      bio,
      profileCompleted: true
    };
    
    // Add profile picture if uploaded
    if (req.file) {
      updateData.profilePicture = req.file.path;
    }
    
    await User.findByIdAndUpdate(req.session.userId, updateData);
    
    res.json({ 
      success: true, 
      message: 'Profile completed successfully',
      redirectUrl: '/dashboard'
    });
  } catch (error) {
    console.error('Profile completion error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Dashboard
app.get('/dashboard', async (req, res) => {
  if (!req.session.userId) {
    return res.redirect('/login');
  }
  
  try {
    const user = await User.findById(req.session.userId);
    if (!user) {
      req.session.destroy();
      return res.redirect('/login');
    }
    
    if (!user.profileCompleted) {
      return res.redirect('/complete-profile');
    }
    
    // Check if user is banned
    const activeBan = await UserBan.findOne({ userId: req.session.userId, isActive: true });
    if (activeBan) {
      req.session.destroy();
      return res.status(403).send(`
        <html>
          <head><title>Account Banned</title></head>
          <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
            <h1>Account Banned</h1>
            <p>Your account has been banned for the following reason:</p>
            <p><strong>${activeBan.reason}</strong></p>
            ${activeBan.banType === 'temporary' && activeBan.expiresAt ? 
              `<p>Ban expires: ${new Date(activeBan.expiresAt).toLocaleString()}</p>` : 
              '<p>This is a permanent ban.</p>'
            }
            <p><a href="/">Return to Home</a></p>
          </body>
        </html>
      `);
    }
    
    // Get blocked users for this user
    const blockedUsers = await BlockedUser.find({ blockerId: req.session.userId })
      .populate('blockedUserId', 'username profilePicture')
      .sort({ blockedAt: -1 });
    
    res.render('dashboard', { 
      user,
      blockedUsers: blockedUsers.map(block => ({
        id: block.blockedUserId._id,
        username: block.blockedUserId.username,
        profilePicture: block.blockedUserId.profilePicture,
        blockedAt: block.blockedAt
      }))
    });
  } catch (error) {
    console.error('Dashboard error:', error);
    res.status(500).send('Server error');
  }
});

// Update profile API endpoint
app.post('/api/update-profile', async (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ success: false, error: 'Unauthorized' });
  }

  try {
    const { username, bio } = req.body;
    
    if (!username) {
      return res.status(400).json({ success: false, error: 'Username is required' });
    }

    // Check if username is already taken by another user
    const existingUser = await User.findOne({ 
      username, 
      _id: { $ne: req.session.userId } 
    });
    
    if (existingUser) {
      return res.status(400).json({ success: false, error: 'Username is already taken' });
    }

    // Update user profile
    const updatedUser = await User.findByIdAndUpdate(
      req.session.userId,
      { username, bio },
      { new: true }
    );

    if (!updatedUser) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }

    res.json({ success: true, user: { username: updatedUser.username, bio: updatedUser.bio } });
  } catch (error) {
    console.error('Profile update error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Update profile picture API endpoint
app.post('/api/update-profile-picture', upload.single('profilePicture'), async (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ success: false, error: 'Unauthorized' });
  }

  try {
    if (!req.file) {
      return res.status(400).json({ success: false, error: 'No file uploaded' });
    }

    // Check file type
    const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif'];
    if (!allowedTypes.includes(req.file.mimetype)) {
      return res.status(400).json({ success: false, error: 'Invalid file type. Only JPEG, PNG, and GIF are allowed.' });
    }

    // Check file size (max 5MB)
    if (req.file.size > 5 * 1024 * 1024) {
      return res.status(400).json({ success: false, error: 'File too large. Maximum size is 5MB.' });
    }

    const profilePicturePath = req.file.path;

    // Update user profile picture
    const updatedUser = await User.findByIdAndUpdate(
      req.session.userId,
      { profilePicture: profilePicturePath },
      { new: true }
    );

    if (!updatedUser) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }

    res.json({ 
      success: true, 
      profilePicture: profilePicturePath 
    });
  } catch (error) {
    console.error('Profile picture update error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Get blocked users API endpoint
app.get('/api/blocked-users', async (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ success: false, error: 'Unauthorized' });
  }

  try {
    const blockedUsers = await BlockedUser.find({ blockerId: req.session.userId })
      .populate('blockedUserId', 'username profilePicture')
      .sort({ blockedAt: -1 });

    res.json({ 
      success: true, 
      blockedUsers: blockedUsers.map(block => ({
        id: block.blockedUserId._id,
        username: block.blockedUserId.username,
        profilePicture: block.blockedUserId.profilePicture,
        blockedAt: block.blockedAt
      }))
    });
  } catch (error) {
    console.error('Get blocked users error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Unblock user API endpoint
app.post('/api/unblock-user', async (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ success: false, error: 'Unauthorized' });
  }

  try {
    const { blockedUserId } = req.body;
    
    if (!blockedUserId) {
      return res.status(400).json({ success: false, error: 'Blocked user ID is required' });
    }

    const result = await BlockedUser.findOneAndDelete({
      blockerId: req.session.userId,
      blockedUserId: blockedUserId
    });

    if (!result) {
      return res.status(404).json({ success: false, error: 'Blocked user not found' });
    }

    res.json({ success: true });
  } catch (error) {
    console.error('Unblock user error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Delete account API endpoint
app.delete('/api/delete-account', async (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ success: false, error: 'Unauthorized' });
  }

  try {
    const userId = req.session.userId;
    console.log('Attempting to delete account for user:', userId);
    
    // Find the user first
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }

    console.log('User found, starting deletion process...');

    // Helper function to safely delete data
    const safeDelete = async (model, query, operationName) => {
      try {
        if (model && typeof model.deleteMany === 'function') {
          const result = await model.deleteMany(query);
          console.log(`${operationName}:`, result.deletedCount);
          return result;
        } else {
          console.log(`${operationName}: Model not available, skipping`);
        }
      } catch (error) {
        console.error(`Error in ${operationName}:`, error.message);
      }
    };

    // Helper function to safely update data
    const safeUpdate = async (model, query, update, operationName) => {
      try {
        if (model && typeof model.updateMany === 'function') {
          const result = await model.updateMany(query, update);
          console.log(`${operationName}:`, result.modifiedCount);
          return result;
        } else {
          console.log(`${operationName}: Model not available, skipping`);
        }
      } catch (error) {
        console.error(`Error in ${operationName}:`, error.message);
      }
    };

    // Delete user's messages
    await safeDelete(Message, { sender: userId }, 'Deleted messages');

    // Delete user's blocked relationships
    await safeDelete(BlockedUser, { 
      $or: [
        { blockerId: userId },
        { blockedUserId: userId }
      ]
    }, 'Deleted blocked relationships');

    // Update rooms created by user
    await safeUpdate(ChatRoom, 
      { createdBy: userId }, 
      { $set: { createdBy: null } }, 
      'Updated rooms'
    );

    // Delete user's room visits
    await safeDelete(UserRoomVisit, { userId: userId }, 'Deleted room visits');

    // Delete user's notifications
    await safeDelete(UserNotification, { userId: userId }, 'Deleted notifications');

    // Delete user's bans
    await safeDelete(UserBan, { 
      $or: [
        { userId: userId },
        { bannedBy: userId }
      ]
    }, 'Deleted bans');

    // Delete user's reports
    await safeDelete(RoomReport, { 
      $or: [
        { reportedBy: userId },
        { resolvedBy: userId }
      ]
    }, 'Deleted reports');

    // Delete user's profile picture if it exists
    if (user.profilePicture) {
      try {
        const profilePicPath = path.join(__dirname, user.profilePicture);
        if (fs.existsSync(profilePicPath)) {
          fs.unlinkSync(profilePicPath);
          console.log('Deleted profile picture:', user.profilePicture);
        }
      } catch (error) {
        console.error('Error deleting profile picture:', error.message);
      }
    }

    // Delete the user account (this is critical)
    try {
      const deleteResult = await User.findByIdAndDelete(userId);
      if (!deleteResult) {
        throw new Error('Failed to delete user account');
      }
      console.log('User account deleted successfully');
    } catch (error) {
      console.error('Error deleting user account:', error);
      throw error; // Re-throw this error as it's critical
    }

    // Clear the session
    try {
      req.session.destroy();
      console.log('Session destroyed');
    } catch (error) {
      console.error('Error destroying session:', error.message);
    }

    console.log('Account deletion completed successfully');
    res.json({ 
      success: true, 
      message: 'Account deleted successfully' 
    });
  } catch (error) {
    console.error('Delete account error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'An error occurred while deleting your account. Please try again.' 
    });
  }
});

// Room page
app.get('/room', async (req, res) => {
  if (!req.session.userId) {
    return res.redirect('/login');
  }
  
  try {
    const user = await User.findById(req.session.userId);
    if (!user) {
      req.session.destroy();
      return res.redirect('/login');
    }
    
    if (!user.profileCompleted) {
      return res.redirect('/complete-profile');
    }
    
    // Check if user is banned
    const activeBan = await UserBan.findOne({ userId: req.session.userId, isActive: true });
    if (activeBan) {
      req.session.destroy();
      return res.status(403).send(`
        <html>
          <head><title>Account Banned</title></head>
          <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
            <h1>Account Banned</h1>
            <p>Your account has been banned for the following reason:</p>
            <p><strong>${activeBan.reason}</strong></p>
            ${activeBan.banType === 'temporary' && activeBan.expiresAt ? 
              `<p>Ban expires: ${new Date(activeBan.expiresAt).toLocaleString()}</p>` : 
              '<p>This is a permanent ban.</p>'
            }
            <p><a href="/">Return to Home</a></p>
          </body>
        </html>
      `);
    }
    
    res.render('room', { user });
  } catch (error) {
    console.error('Room error:', error);
    res.status(500).send('Server error');
  }
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

// Chat room schema
const ChatRoomSchema = new mongoose.Schema({
  roomId: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  description: String,
  type: { type: String, default: 'public' }, // Room type (public, private, etc.)
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  createdAt: { type: Date, default: Date.now },
  encryptionKey: { type: String }, // Room-specific encryption key
  encryptionEnabled: { type: Boolean, default: true }, // Flag to enable/disable encryption
  isActive: { type: Boolean, default: true }, // Room status (active/banned)
  banReason: String, // Reason for banning the room
  bannedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' }, // Admin who banned the room
  bannedAt: Date, // When the room was banned
  banExpiresAt: Date // When the ban expires (for temporary bans)
});

const ChatRoom = mongoose.model('ChatRoom', ChatRoomSchema);

// Encryption utility functions
const generateEncryptionKey = () => {
  return CryptoJS.lib.WordArray.random(256/8).toString();
};

const encryptMessage = (message, key) => {
  try {
    return CryptoJS.AES.encrypt(message, key).toString();
  } catch (error) {
    console.error('Encryption error:', error);
    return message; // Fallback to plain text if encryption fails
  }
};

const decryptMessage = (encryptedMessage, key) => {
  try {
    const bytes = CryptoJS.AES.decrypt(encryptedMessage, key);
    return bytes.toString(CryptoJS.enc.Utf8);
  } catch (error) {
    console.error('Decryption error:', error);
    return encryptedMessage; // Return encrypted message if decryption fails
  }
};

// Define Message Schema
const MessageSchema = new mongoose.Schema({
  roomId: { type: String, required: true },
  sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  content: { type: String, required: true },
  encryptedContent: { type: String }, // Encrypted message content
  encryptionKey: { type: String }, // Room-specific encryption key
  isEncrypted: { type: Boolean, default: true }, // Flag to indicate if message is encrypted
  messageType: { 
    type: String, 
    enum: ['text', 'audio', 'photo', 'video', 'file', 'call-event'], 
    default: 'text' 
  },
  audioFile: {
    path: String,
    duration: Number, // Duration in seconds
    originalName: String
  },
  photoFile: {
    path: String,
    originalName: String
  },
  videoFile: {
    path: String,
    originalName: String
  },
  fileData: {
    path: String,
    originalName: String,
    fileType: String,
    size: Number
  },
  callEvent: {
    type: { type: String, enum: ['started', 'answered', 'missed', 'ended', 'rejected'] },
    isVideo: Boolean,
    duration: Number, // Duration in seconds for ended calls
    participants: [String] // Array of usernames who participated
  },
  timestamp: { type: Date, default: Date.now },
  readBy: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  edited: { type: Boolean, default: false },
  editedAt: Date,
  deleted: { type: Boolean, default: false }
});

const Message = mongoose.model('Message', MessageSchema);

// User Room Visit schema for tracking recent rooms
const UserRoomVisitSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  roomId: { type: String, required: true },
  lastVisited: { type: Date, default: Date.now },
  visitCount: { type: Number, default: 1 }
});

// Compound index to ensure unique user-room combinations
UserRoomVisitSchema.index({ userId: 1, roomId: 1 }, { unique: true });

const UserRoomVisit = mongoose.model('UserRoomVisit', UserRoomVisitSchema);

// Blocked User schema for tracking blocked users
const BlockedUserSchema = new mongoose.Schema({
  blockerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  blockedUserId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  blockedUsername: { type: String, required: true },
  blockedAt: { type: Date, default: Date.now }
});

// Compound index to ensure unique blocker-blocked combinations
BlockedUserSchema.index({ blockerId: 1, blockedUserId: 1 }, { unique: true });

const BlockedUser = mongoose.model('BlockedUser', BlockedUserSchema);

// Create a new chat room
app.post('/api/rooms', async (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ success: false, error: 'Unauthorized' });
  }

  try {
    const { name, description } = req.body;
    
    if (!name) {
      return res.status(400).json({ success: false, error: 'Room name is required' });
    }

    // Generate a unique room ID
    const generateRoomId = () => {
      const characters = 'abcdefghijklmnopqrstuvwxyz0123456789';
      let result = 'bawi-';
      for (let i = 0; i < 8; i++) {
        result += characters.charAt(Math.floor(Math.random() * characters.length));
      }
      return result;
    };

    let roomId = generateRoomId();
    let roomExists = await ChatRoom.findOne({ roomId });
    
    // Ensure the room ID is unique
    while (roomExists) {
      roomId = generateRoomId();
      roomExists = await ChatRoom.findOne({ roomId });
    }

    const newRoom = new ChatRoom({
      roomId,
      name,
      description,
      createdBy: req.session.userId,
      encryptionKey: generateEncryptionKey(),
      encryptionEnabled: true
    });

    await newRoom.save();

    res.status(201).json({ 
      success: true, 
      room: {
        id: newRoom.roomId,
        name: newRoom.name,
        description: newRoom.description,
        encryptionEnabled: newRoom.encryptionEnabled
      }
    });
  } catch (error) {
    console.error('Create room error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Get room details
app.get('/api/rooms/:roomId', async (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ success: false, error: 'Unauthorized' });
  }

  try {
    const { roomId } = req.params;
    const room = await ChatRoom.findOne({ roomId }).populate('createdBy', 'username profilePicture');
    
    if (!room) {
      return res.status(404).json({ success: false, error: 'Room not found' });
    }

    res.json({ 
      success: true, 
      room: {
        id: room.roomId,
        name: room.name,
        description: room.description,
        createdBy: room.createdBy
      }
    });
  } catch (error) {
    console.error('Get room error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Get room messages
app.get('/api/rooms/:roomId/messages', async (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ success: false, error: 'Unauthorized' });
  }

  try {
    const { roomId } = req.params;
    const room = await ChatRoom.findOne({ roomId });
    
    if (!room) {
      return res.status(404).json({ success: false, error: 'Room not found' });
    }

    const messages = await Message.find({ roomId })
      .sort({ timestamp: 1 })
      .populate('sender', 'username profilePicture');

    // Add encryption information to each message
    const messagesWithEncryption = messages.map(message => {
      const messageObj = message.toObject();
      return {
        ...messageObj,
        encryptionKey: room.encryptionKey,
        encryptionEnabled: room.encryptionEnabled
      };
    });

    res.json({ success: true, messages: messagesWithEncryption });
  } catch (error) {
    console.error('Get messages error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Track room visit
app.post('/api/rooms/:roomId/visit', async (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ success: false, error: 'Unauthorized' });
  }

  try {
    const { roomId } = req.params;
    const userId = req.session.userId;

    // Check if room exists
    const room = await ChatRoom.findOne({ roomId });
    if (!room) {
      return res.status(404).json({ success: false, error: 'Room not found' });
    }

    // Update or create visit record
    await UserRoomVisit.findOneAndUpdate(
      { userId, roomId },
      { 
        $inc: { visitCount: 1 },
        $set: { lastVisited: new Date() }
      },
      { upsert: true, new: true }
    );

    res.json({ success: true });
  } catch (error) {
    console.error('Track room visit error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Get recent rooms for user
app.get('/api/recent-rooms', async (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ success: false, error: 'Unauthorized' });
  }

  try {
    const userId = req.session.userId;
    console.log('Recent rooms request for user:', userId);
    
    // Get user's recent room visits
    const recentVisits = await UserRoomVisit.find({ userId })
      .sort({ lastVisited: -1 })
      .limit(10);

    console.log('Found recent visits:', recentVisits.length);

    // Get room details for each visit, but only include active (non-banned) rooms
    const recentRooms = [];
    for (const visit of recentVisits) {
      const room = await ChatRoom.findOne({ roomId: visit.roomId, isActive: true });
      if (room) {
        recentRooms.push({
          roomId: room.roomId,
          name: room.name,
          description: room.description,
          lastVisited: visit.lastVisited,
          visitCount: visit.visitCount,
          createdAt: room.createdAt
        });
      } else {
        console.log('Room not found or inactive:', visit.roomId);
      }
    }

    console.log('Returning recent rooms:', recentRooms.length);
    res.json({ success: true, recentRooms });
  } catch (error) {
    console.error('Get recent rooms error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Delete recent room visit
app.delete('/api/recent-rooms/:roomId', async (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ success: false, error: 'Unauthorized' });
  }

  try {
    const userId = req.session.userId;
    const { roomId } = req.params;
    
    console.log('Delete recent room request:', { userId, roomId });
    
    // Delete the room visit record
    const result = await UserRoomVisit.findOneAndDelete({ userId, roomId });
    
    if (result) {
      console.log('Room visit deleted successfully');
      res.json({ success: true, message: 'Room removed from recent rooms' });
    } else {
      console.log('Room visit not found');
      res.status(404).json({ success: false, error: 'Room visit not found' });
    }
  } catch (error) {
    console.error('Delete recent room error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Get user's announcements (MUST come before /api/user/:userId route)
app.get('/api/user/announcements', async (req, res) => {
  console.log('=== ANNOUNCEMENTS ENDPOINT HIT ===');
  console.log('Announcements API endpoint hit - URL:', req.url, 'Method:', req.method);
  console.log('Session user ID:', req.session.userId);
  console.log('Session object:', req.session);
  try {
    let userId = null;
    let isAuthenticated = false;
    if (req.session && req.session.userId) {
      const user = await User.findById(req.session.userId);
      if (user) {
        userId = user._id;
        isAuthenticated = true;
        console.log('User authenticated:', user.username);
      }
    }
    // Get announcements for this user (all announcements + specific ones)
    let announcements;
    if (isAuthenticated) {
      announcements = await Announcement.find({
        $or: [
          { target: 'all' },
          { targetUsers: userId }
        ]
      }).sort({ createdAt: -1 });
    } else {
      announcements = await Announcement.find({ target: 'all' }).sort({ createdAt: -1 });
    }
    // Get read status for each announcement
    const announcementsWithStatus = await Promise.all(
      announcements.map(async (announcement) => {
        let read = false;
        if (isAuthenticated) {
          const notification = await UserNotification.findOne({
            userId,
            announcementId: announcement._id,
            type: 'announcement'
          });
          read = notification ? notification.read : false;
        }
        return {
          ...announcement.toObject(),
          read
        };
      })
    );
    console.log('Sending announcements to user:', {
      userId: userId,
      count: announcementsWithStatus.length,
      announcements: announcementsWithStatus.map(a => ({ id: a._id, title: a.title, read: a.read }))
    });
    res.json({ success: true, announcements: announcementsWithStatus });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Get user's broadcasts (MUST come before /api/user/:userId route)
app.get('/api/user/broadcasts', async (req, res) => {
  console.log('=== BROADCASTS ENDPOINT HIT ===');
  console.log('Broadcasts API endpoint hit - URL:', req.url, 'Method:', req.method);
  console.log('Session user ID:', req.session.userId);
  console.log('Session object:', req.session);
  try {
    let userId = null;
    let isAuthenticated = false;
    if (req.session && req.session.userId) {
      const user = await User.findById(req.session.userId);
      if (user) {
        userId = user._id;
        isAuthenticated = true;
        console.log('User authenticated:', user.username);
      }
    }
    // Get all broadcast messages
    const broadcasts = await BroadcastMessage.find().sort({ createdAt: -1 });
    // Get read status for each broadcast
    const broadcastsWithStatus = await Promise.all(
      broadcasts.map(async (broadcast) => {
        let read = false;
        if (isAuthenticated) {
          const notification = await UserNotification.findOne({
            userId,
            broadcastId: broadcast._id,
            type: 'broadcast'
          });
          read = notification ? notification.read : false;
        }
        return {
          ...broadcast.toObject(),
          read
        };
      })
    );
    console.log('Sending broadcasts to user:', {
      userId: userId,
      count: broadcastsWithStatus.length,
      broadcasts: broadcastsWithStatus.map(b => ({ id: b._id, message: b.message, read: b.read }))
    });
    res.json({ success: true, broadcasts: broadcastsWithStatus });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Mark announcement as read (MUST come before /api/user/:userId route)
app.post('/api/user/announcements/:id/read', async (req, res) => {
  try {
    if (!req.session.userId) {
      return res.status(401).json({ error: 'Access denied. Not authenticated.' });
    }
    
    const user = await User.findById(req.session.userId);
    if (!user) {
      return res.status(401).json({ error: 'Invalid session.' });
    }
    
    const userId = user._id;
    const announcementId = req.params.id;
    
    // Create or update notification record
    await UserNotification.findOneAndUpdate(
      { userId, announcementId, type: 'announcement' },
      { read: true },
      { upsert: true, new: true }
    );
    
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Mark broadcast as read (MUST come before /api/user/:userId route)
app.post('/api/user/broadcasts/:id/read', async (req, res) => {
  try {
    if (!req.session.userId) {
      return res.status(401).json({ error: 'Access denied. Not authenticated.' });
    }
    
    const user = await User.findById(req.session.userId);
    if (!user) {
      return res.status(401).json({ error: 'Invalid session.' });
    }
    
    const userId = user._id;
    const broadcastId = req.params.id;
    
    // Create or update notification record
    await UserNotification.findOneAndUpdate(
      { userId, broadcastId, type: 'broadcast' },
      { read: true },
      { upsert: true, new: true }
    );
    
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Get user profile details
app.get('/api/user/:userId', async (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ success: false, error: 'Unauthorized' });
  }

  try {
    const { userId } = req.params;
    console.log('Get user profile request:', { requestedBy: req.session.userId, targetUser: userId });
    
    // Validate user ID format
    if (!userId || userId === 'undefined' || userId === 'null') {
      console.log('Invalid user ID provided:', userId);
      return res.status(400).json({ success: false, error: 'Invalid user ID' });
    }
    
    // Find the user - handle both ObjectId and string formats
    let user;
    try {
      user = await User.findById(userId);
    } catch (findError) {
      console.log('Error finding user by ID:', findError.message);
      // Try to find by username as fallback
      user = await User.findOne({ username: userId });
    }
    
    if (!user) {
      console.log('User not found:', userId);
      return res.status(404).json({ success: false, error: 'User not found' });
    }
    
    // Check if the requesting user has blocked this user or vice versa
    let requestingUser;
    let isBlocked = false;
    
    try {
      requestingUser = await User.findById(req.session.userId);
      if (requestingUser && user) {
        // Ensure blockedUsers arrays exist before checking
        const requestingUserBlocked = requestingUser.blockedUsers || [];
        const targetUserBlocked = user.blockedUsers || [];
        
        isBlocked = requestingUserBlocked.includes(user._id) || 
                   targetUserBlocked.includes(requestingUser._id);
      }
    } catch (blockError) {
      console.log('Error checking block status:', blockError.message);
      isBlocked = false;
    }
    
    // Return user profile data (excluding sensitive information)
    const profileData = {
      _id: user._id,
      username: user.username,
      age: user.age,
      gender: user.gender,
      bio: user.bio,
      profilePicture: user.profilePicture,
      createdAt: user.createdAt,
      lastSeen: user.lastSeen,
      isBlocked: isBlocked
    };
    
    console.log('User profile retrieved successfully for:', user.username);
    res.json({ success: true, user: profileData });
  } catch (error) {
    console.error('Get user profile error:', error);
    res.status(500).json({ success: false, error: 'Server error: ' + error.message });
  }
});

// Audio upload route
app.post('/api/upload-audio', audioUpload.single('audio'), async (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ success: false, error: 'Unauthorized' });
  }

  try {
    if (!req.file) {
      return res.status(400).json({ success: false, error: 'No audio file provided' });
    }

    const audioData = {
      path: `/uploads/audio/${req.file.filename}`,
      originalName: req.file.originalname,
      duration: req.body.duration ? parseFloat(req.body.duration) : null
    };

    res.json({ 
      success: true, 
      audioFile: audioData 
    });
  } catch (error) {
    console.error('Audio upload error:', error);
    res.status(500).json({ success: false, error: 'Failed to upload audio' });
  }
});

// Photo upload route
app.post('/api/upload-photo', photoUpload.single('photo'), async (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ success: false, error: 'Unauthorized' });
  }

  try {
    if (!req.file) {
      return res.status(400).json({ success: false, error: 'No photo file provided' });
    }

    const photoData = {
      path: `/uploads/photos/${req.file.filename}`,
      originalName: req.file.originalname
    };

    res.json({ 
      success: true, 
      photoFile: photoData 
    });
  } catch (error) {
    console.error('Photo upload error:', error);
    res.status(500).json({ success: false, error: 'Failed to upload photo' });
  }
});

// Video upload route
app.post('/api/upload-video', videoUpload.single('video'), async (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ success: false, error: 'Unauthorized' });
  }

  try {
    if (!req.file) {
      return res.status(400).json({ success: false, error: 'No video file provided' });
    }

    const videoData = {
      path: `/uploads/videos/${req.file.filename}`,
      originalName: req.file.originalname
    };

    res.json({ 
      success: true, 
      videoFile: videoData 
    });
  } catch (error) {
    console.error('Video upload error:', error);
    res.status(500).json({ success: false, error: 'Failed to upload video' });
  }
});

// General file upload route
app.post('/api/upload-file', fileUpload.single('file'), async (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ success: false, error: 'Unauthorized' });
  }

  try {
    if (!req.file) {
      return res.status(400).json({ success: false, error: 'No file provided' });
    }

    console.log('File upload received:', {
      originalName: req.file.originalname,
      mimetype: req.file.mimetype,
      size: req.file.size
    });

    const fileType = req.file.mimetype;
    let messageType = 'file';
    let fileData = {
      path: `/uploads/${fileType.startsWith('image/') ? 'images' : fileType.startsWith('video/') ? 'videos' : 'documents'}/${req.file.filename}`,
      originalName: req.file.originalname,
      size: req.file.size
    };

    // Determine message type based on file type
    if (fileType.startsWith('image/')) {
      messageType = 'photo';
      fileData = {
        path: fileData.path,
        originalName: fileData.originalName
      };
    } else if (fileType.startsWith('video/')) {
      messageType = 'video';
      fileData = {
        path: fileData.path,
        originalName: fileData.originalName
      };
    } else {
      // For documents, add file type and size info
      fileData.fileType = fileType;
      fileData.size = req.file.size;
    }

    console.log('File processed successfully:', { messageType, fileData });

    res.json({ 
      success: true, 
      fileType: messageType,
      fileData: fileData
    });
  } catch (error) {
    console.error('File upload error:', error);
    res.status(500).json({ success: false, error: 'Failed to upload file: ' + error.message });
  }
});

// Chat page
app.get('/chat/:roomId', async (req, res) => {
  if (!req.session.userId) {
    return res.redirect('/login');
  }
  
  try {
    const user = await User.findById(req.session.userId);
    if (!user) {
      req.session.destroy();
      return res.redirect('/login');
    }
    
    if (!user.profileCompleted) {
      return res.redirect('/complete-profile');
    }
    
    const { roomId } = req.params;
    const room = await ChatRoom.findOne({ roomId, isActive: true });
    
    if (!room) {
      // Check if room exists but is banned
      const bannedRoom = await ChatRoom.findOne({ roomId, isActive: false });
      if (bannedRoom) {
        return res.status(403).send(`
          <html>
            <head><title>Room Banned</title></head>
            <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
              <h1>Room Banned</h1>
              <p>This room has been banned for the following reason:</p>
              <p><strong>${bannedRoom.banReason || 'No reason provided'}</strong></p>
              ${bannedRoom.banExpiresAt ? 
                `<p>Ban expires: ${new Date(bannedRoom.banExpiresAt).toLocaleString()}</p>` : 
                '<p>This is a permanent ban.</p>'
              }
              <p><a href="/room">Return to Room Selection</a></p>
            </body>
          </html>
        `);
      }
      return res.redirect('/room');
    }
    
    // Track room visit for recent rooms functionality
    try {
      await UserRoomVisit.findOneAndUpdate(
        { userId: user._id, roomId },
        { 
          $inc: { visitCount: 1 },
          $set: { lastVisited: new Date() }
        },
        { upsert: true, new: true }
      );
      console.log(`Room visit tracked for user ${user.username || user.email} in room ${roomId}`);
    } catch (visitError) {
      console.error('Error tracking room visit:', visitError);
      // Don't fail the page load if visit tracking fails
    }
    
    res.render('chat', { user, room });
  } catch (error) {
    console.error('Chat page error:', error);
    res.status(500).send('Server error');
  }
});

// Track active users and blocked users
const activeUsers = new Map();
const blockedUsers = new Map(); // userId -> Set of blocked user IDs

// Report schema
const reportSchema = new mongoose.Schema({
    reportedUser: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    reportedUsername: { type: String, required: true },
    reporter: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    reporterUsername: { type: String, required: true },
    roomId: { type: String, required: true },
    reason: { type: String, required: true },
    details: String,
    timestamp: { type: Date, default: Date.now },
    status: { type: String, default: 'pending', enum: ['pending', 'reviewed', 'resolved', 'dismissed'] }
});

const Report = mongoose.model('Report', reportSchema);

// Socket.IO connection handling
io.on('connection', (socket) => {
  console.log('A user connected:', socket.id);
  
  // Store user data in socket
  let currentUser = null;
  let currentRoom = null;
  
  // Handle user disconnection
  socket.on('disconnect', () => {
    if (currentRoom && currentUser) {
      // Remove user from active users
      if (activeUsers.has(currentRoom)) {
        const roomUsers = activeUsers.get(currentRoom);
        const userIndex = roomUsers.findIndex(u => u.id === currentUser._id.toString());
        if (userIndex !== -1) {
          roomUsers.splice(userIndex, 1);
          if (roomUsers.length === 0) {
            activeUsers.delete(currentRoom);
          } else {
            activeUsers.set(currentRoom, roomUsers);
          }
          // Get list of blocked users for this user
          const blockedUserIds = blockedUsers.get(currentUser._id.toString()) || new Set();
          // Filter out blocked users from the active users list
          const filteredUsers = roomUsers.filter(user => 
            !blockedUserIds.has(user.id) && user.id !== currentUser._id.toString()
          );
          // Send active users update to the room
          io.to(currentRoom).emit('active-users-update', {
            count: filteredUsers.length + 1, // +1 for current user
            users: filteredUsers
          });
          // Send list of blocked users to the current user
          socket.emit('blocked-users', Array.from(blockedUserIds));
        }
      }
    }
    if (currentUser && currentRoom) {
      socket.to(currentRoom).emit('user-left', {
        userId: currentUser._id,
        username: currentUser.username || currentUser.email
      });
    }
    console.log('User disconnected:', socket.id);
  });
  
  // Authenticate user
  socket.on('authenticate', async (userId) => {
    try {
      // Check if userId is a valid ObjectId (for registered users)
      if (userId && userId.startsWith('anonymous-')) {
        // Handle anonymous users
        currentUser = { _id: userId, username: 'Anonymous User', email: userId };
        console.log(`Anonymous user ${userId} authenticated`);
        socket.emit('authenticated', { success: true });
        return;
      }
      
      // For registered users, validate ObjectId and find user
      if (userId && mongoose.Types.ObjectId.isValid(userId)) {
        const user = await User.findById(userId);
        if (user) {
          currentUser = user;
          console.log(`User ${user.username || user.email} authenticated`);
          socket.emit('authenticated', { success: true });
        } else {
          console.log('User not found:', userId);
          socket.emit('authenticated', { success: false, error: 'User not found' });
        }
      } else {
        console.log('Invalid userId format:', userId);
        socket.emit('authenticated', { success: false, error: 'Invalid user ID' });
      }
    } catch (error) {
      console.error('Socket authentication error:', error);
      socket.emit('authenticated', { success: false, error: 'Authentication failed' });
    }
  });
  
  // Block a user
  socket.on('block-user', async (data) => {
    try {
      const { blockedUserId, blockedUsername } = data;
      const blockerId = currentUser._id.toString();
      
      // Validate input
      if (!blockedUserId || blockedUserId === 'undefined') {
        socket.emit('block-user', { success: false, error: 'Invalid user ID' });
        return;
      }
      
      // Prevent self-blocking
      if (blockedUserId === blockerId) {
        socket.emit('block-user', { success: false, error: 'You cannot block yourself' });
        return;
      }
      
      // Check if user is already blocked
      const existingBlock = await BlockedUser.findOne({
        blockerId: currentUser._id,
        blockedUserId: blockedUserId
      });
      
      if (existingBlock) {
        socket.emit('block-user', { success: false, error: 'User is already blocked' });
        return;
      }
      
      // Save to database (only for registered users)
      if (!currentUser._id.toString().startsWith('anonymous-')) {
        const blockedUserRecord = new BlockedUser({
          blockerId: currentUser._id,
          blockedUserId: blockedUserId,
          blockedUsername: blockedUsername
        });
        
        await blockedUserRecord.save();
      }
      
      // Add to blocked users map for current session
      if (!blockedUsers.has(blockerId)) {
        blockedUsers.set(blockerId, new Set());
      }
      blockedUsers.get(blockerId).add(blockedUserId);
      
      // Notify the user who was blocked
      io.to(blockedUserId).emit('user-blocked', { blockerId });
      
      // Send success response
      socket.emit('block-user', { success: true, message: `Successfully blocked ${blockedUsername}` });
      
      console.log(`User ${currentUser.username || currentUser.email} blocked ${blockedUsername}`);
      
    } catch (error) {
      console.error('Error blocking user:', error);
      socket.emit('block-user', { success: false, error: 'Failed to block user' });
    }
  });
  
  // Unblock a user
  socket.on('unblock-user', async (data) => {
    try {
      const { blockedUserId, blockedUsername } = data;
      const blockerId = currentUser._id.toString();
      
      // Validate input
      if (!blockedUserId || blockedUserId === 'undefined') {
        socket.emit('unblock-user', { success: false, error: 'Invalid user ID' });
        return;
      }
      
      // Prevent self-unblocking
      if (blockedUserId === blockerId) {
        socket.emit('unblock-user', { success: false, error: 'You cannot unblock yourself' });
        return;
      }
      
      // Check if user is actually blocked
      const existingBlock = await BlockedUser.findOne({
        blockerId: currentUser._id,
        blockedUserId: blockedUserId
      });
      
      if (!existingBlock) {
        socket.emit('unblock-user', { success: false, error: 'User is not blocked' });
        return;
      }
      
      // Remove from database (only for registered users)
      if (!currentUser._id.toString().startsWith('anonymous-')) {
        await BlockedUser.findOneAndDelete({
          blockerId: currentUser._id,
          blockedUserId: blockedUserId
        });
      }
      
      // Remove from blocked users map for current session
      if (blockedUsers.has(blockerId)) {
        blockedUsers.get(blockerId).delete(blockedUserId);
      }
      
      // Notify the user who was unblocked
      io.to(blockedUserId).emit('user-unblocked', { blockerId });
      
      // Send success response
      socket.emit('unblock-user', { success: true, message: `Successfully unblocked ${blockedUsername}` });
      
      console.log(`User ${currentUser.username || currentUser.email} unblocked ${blockedUsername}`);
      
    } catch (error) {
      console.error('Error unblocking user:', error);
      socket.emit('unblock-user', { success: false, error: 'Failed to unblock user' });
    }
  });
  
  // Report a user
  socket.on('report-user', async (reportData) => {
    try {
      const { reportedUserId, reportedUsername, reason } = reportData;
      const reporterId = currentUser._id.toString();
      
      // Prevent self-reporting
      if (reportedUserId === reporterId) {
        socket.emit('report-user', { success: false, error: 'You cannot report yourself' });
        return;
      }
      
      // Check if user has already reported this user recently (within 24 hours)
      const existingReport = await Report.findOne({
        reportedUser: reportedUserId,
        reporter: currentUser._id,
        timestamp: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
      });
      
      if (existingReport) {
        socket.emit('report-user', { success: false, error: 'You have already reported this user recently' });
        return;
      }
      
      const report = new Report({
        reportedUser: reportedUserId,
        reportedUsername: reportedUsername,
        reporter: currentUser._id,
        reporterUsername: currentUser.username || currentUser.email,
        roomId: currentRoom,
        reason: reason,
        timestamp: new Date()
      });
      
      await report.save();
      
      // Send success response
      socket.emit('report-user', { success: true, message: `Successfully reported ${reportedUsername}` });
      
      // In a real app, you might want to notify admins here
      console.log(`New user report: ${currentUser.username || currentUser.email} reported ${reportedUsername} for: ${reason}`);
      
    } catch (error) {
      console.error('Error reporting user:', error);
      socket.emit('report-user', { success: false, error: 'Failed to report user' });
    }
  });
  
  // Join a room
  socket.on('join-room', async (roomId) => {
    if (!currentUser) {
      socket.emit('error', { message: 'Authentication required' });
      return;
    }
    
    try {
      // Update user's last seen timestamp (skip for anonymous users)
      if (!currentUser._id.toString().startsWith('anonymous-')) {
        try {
          await User.findByIdAndUpdate(currentUser._id, {
            lastSeen: new Date()
          });
        } catch (error) {
          console.error('Error updating last seen for user:', error);
        }
      }
      
      const room = await ChatRoom.findOne({ roomId, isActive: true });
      if (!room) {
        // Check if room exists but is banned
        const bannedRoom = await ChatRoom.findOne({ roomId, isActive: false });
        if (bannedRoom) {
          socket.emit('error', { 
            message: `Room is banned: ${bannedRoom.banReason || 'No reason provided'}` 
          });
          return;
        }
        socket.emit('error', { message: 'Room not found' });
        return;
      }
      
      // Leave previous room if any
      if (currentRoom) {
        socket.leave(currentRoom);
      }
      
      // Join new room
      socket.join(roomId);
      currentRoom = roomId;
      
      // Add user to active users for this room
      const userInfo = {
        id: currentUser._id.toString(),
        username: currentUser.username || currentUser.email,
        profilePicture: currentUser.profilePicture
      };
      
      if (!activeUsers.has(roomId)) {
        activeUsers.set(roomId, [userInfo]);
      } else if (!activeUsers.get(roomId).some(u => u.id === userInfo.id)) {
        activeUsers.get(roomId).push(userInfo);
      }
      
      // Send current active users to the user who joined
      socket.emit('active-users-update', {
        count: activeUsers.get(roomId).length,
        users: activeUsers.get(roomId)
      });
      
      // Notify room about new user
      socket.to(roomId).emit('user-joined', {
        userId: currentUser._id,
        username: currentUser.username || currentUser.email,
        profilePicture: currentUser.profilePicture
      });
      
      // Notify room about updated user count
      socket.to(roomId).emit('active-users-update', {
        count: activeUsers.get(roomId).length,
        users: activeUsers.get(roomId)
      });
      
      // Mark messages as read (skip for anonymous users)
      if (!currentUser._id.toString().startsWith('anonymous-')) {
        try {
          await Message.updateMany(
            { roomId, sender: { $ne: currentUser._id }, readBy: { $ne: currentUser._id } },
            { $addToSet: { readBy: currentUser._id } }
          );
          
          // Notify senders that their messages were read
          const messages = await Message.find({
            roomId,
            sender: { $ne: currentUser._id },
            readBy: currentUser._id
          });
          
          const senderIds = [...new Set(messages.map(msg => msg.sender.toString()))];
          
          senderIds.forEach(senderId => {
            io.to(roomId).emit('messages-read', {
              by: currentUser._id,
              from: senderId
            });
          });
        } catch (error) {
          console.error('Error marking messages as read:', error);
        }
      }
      
      socket.emit('room-joined', { roomId });
    } catch (error) {
      console.error('Join room error:', error);
      socket.emit('error', { message: 'Failed to join room' });
    }
  });
  
  // Send a message
  socket.on('send-message', async (data) => {
    if (!currentUser || !currentRoom) {
      socket.emit('error', { message: 'Not in a room' });
      return;
    }
    
    try {
      const { content, messageType = 'text', audioFile, photoFile, videoFile, fileData } = data;
      
      if (messageType === 'text') {
        if (!content || typeof content !== 'string' || content.trim() === '') {
          socket.emit('error', { message: 'Invalid message' });
          return;
        }
      } else if (messageType === 'audio') {
        if (!audioFile || !audioFile.path) {
          socket.emit('error', { message: 'Invalid audio file' });
          return;
        }
      } else if (messageType === 'photo') {
        if (!photoFile || !photoFile.path) {
          socket.emit('error', { message: 'Invalid photo file' });
          return;
        }
      } else if (messageType === 'video') {
        if (!videoFile || !videoFile.path) {
          socket.emit('error', { message: 'Invalid video file' });
          return;
        }
      } else if (messageType === 'file') {
        if (!fileData || !fileData.path) {
          socket.emit('error', { message: 'Invalid file' });
          return;
        }
      }
      
      // Get room encryption key
      const room = await ChatRoom.findOne({ roomId: currentRoom, isActive: true });
      if (!room) {
        // Check if room exists but is banned
        const bannedRoom = await ChatRoom.findOne({ roomId: currentRoom, isActive: false });
        if (bannedRoom) {
          socket.emit('error', { 
            message: `Cannot send message: Room is banned - ${bannedRoom.banReason || 'No reason provided'}` 
          });
          return;
        }
        socket.emit('error', { message: 'Room not found' });
        return;
      }
      
      // Create and save the message
      const messageData = {
        roomId: currentRoom,
        content: messageType === 'text' ? content.trim() : `${messageType.charAt(0).toUpperCase() + messageType.slice(1)} message`,
        messageType: messageType,
        readBy: currentUser._id.toString().startsWith('anonymous-') ? [] : [currentUser._id], // Skip readBy for anonymous users
        isEncrypted: false // TEMPORARILY DISABLE ALL ENCRYPTION
      };

      // Ensure content is always the actual message text, never a placeholder
      if (messageType === 'text') {
        messageData.content = content.trim();
      }

      // Only set sender for registered users (ObjectId)
      if (!currentUser._id.toString().startsWith('anonymous-')) {
        messageData.sender = currentUser._id;
      }

      // TEMPORARILY DISABLED: Handle encrypted text messages from client
      // if (messageType === 'text' && room.encryptionEnabled && room.encryptionKey && !currentUser._id.toString().startsWith('anonymous-')) {
      //   // The content is already encrypted by the client, so store it as encrypted content
      //   messageData.encryptedContent = content.trim();
      //   messageData.encryptionKey = room.encryptionKey;
      //   // Store a placeholder for content to maintain compatibility
      //   messageData.content = '[Encrypted Message]';
      // }

      // TEMPORARILY DISABLE ALL ENCRYPTION FOR ALL USERS
      messageData.isEncrypted = false;
      delete messageData.encryptedContent;
      delete messageData.encryptionKey;

      if (messageType === 'audio' && audioFile) {
        messageData.audioFile = {
          path: audioFile.path,
          duration: audioFile.duration,
          originalName: audioFile.originalName
        };
      } else if (messageType === 'photo' && photoFile) {
        messageData.photoFile = {
          path: photoFile.path,
          originalName: photoFile.originalName
        };
      } else if (messageType === 'video' && videoFile) {
        messageData.videoFile = {
          path: videoFile.path,
          originalName: videoFile.originalName
        };
      } else if (messageType === 'file' && fileData) {
        messageData.fileData = {
          path: fileData.path,
          originalName: fileData.originalName,
          fileType: fileData.fileType,
          size: fileData.size
        };
      }

      let message;
      
      // Handle anonymous users differently since they can't be saved to DB
      if (currentUser._id.toString().startsWith('anonymous-')) {
        // Create a temporary message object for anonymous users
        message = {
          _id: new mongoose.Types.ObjectId(),
          ...messageData,
          sender: {
            _id: currentUser._id,
            username: currentUser.username || 'Anonymous User',
            profilePicture: currentUser.profilePicture
          },
          timestamp: new Date()
        };
      } else {
        // Save to database for registered users
        message = new Message(messageData);
        await message.save();
        
        // Populate sender info
        await message.populate('sender', 'username profilePicture');
      }
      
      // Prepare message payload for broadcasting
      const messagePayload = {
        id: message._id,
        content: message.content,
        encryptedContent: message.encryptedContent,
        encryptionKey: message.encryptionKey,
        isEncrypted: message.isEncrypted,
        messageType: message.messageType,
        sender: {
          id: message.sender._id,
          username: message.sender.username || 'User',
          profilePicture: message.sender.profilePicture
        },
        timestamp: message.timestamp,
        readBy: message.readBy
      };

      if (message.messageType === 'audio' && message.audioFile) {
        messagePayload.audioFile = message.audioFile;
      } else if (message.messageType === 'photo' && message.photoFile) {
        messagePayload.photoFile = message.photoFile;
      } else if (message.messageType === 'video' && message.videoFile) {
        messagePayload.videoFile = message.videoFile;
      } else if (message.messageType === 'file' && message.fileData) {
        messagePayload.fileData = message.fileData;
      }

      io.to(currentRoom).emit('new-message', messagePayload);
    } catch (error) {
      console.error('Send message error:', error);
      socket.emit('error', { message: 'Failed to send message' });
    }
  });
  
  // Edit a message within 5 minutes
  socket.on('edit-message', async ({ messageId, content }) => {
    if (!currentUser || !currentRoom) return;
    try {
      const message = await Message.findById(messageId);
      if (!message) return;
      if (message.deleted) return socket.emit('error', { message: 'Cannot edit deleted message' });
      if (!message.sender.equals(currentUser._id)) {
        return socket.emit('error', { message: 'Not authorized to edit this message' });
      }
      const fiveMinutes = 5 * 60 * 1000;
      if (Date.now() - message.timestamp.getTime() > fiveMinutes) {
        return socket.emit('error', { message: 'Edit window expired' });
      }
      if (!content || typeof content !== 'string' || content.trim() === '') {
        return socket.emit('error', { message: 'Invalid content' });
      }
      message.content = content.trim();
      message.edited = true;
      message.editedAt = new Date();
      await message.save();
      await message.populate('sender', 'username profilePicture');
      
      io.to(currentRoom).emit('message-edited', {
        id: message._id,
        content: message.content,
        edited: true,
        editedAt: message.editedAt,
        sender: {
          id: message.sender._id,
          username: message.sender.username || 'User',
          profilePicture: message.sender.profilePicture
        }
      });
    } catch (error) {
      console.error('Edit message error:', error);
    }
  });
  
  // Delete a message (soft delete)
  socket.on('delete-message', async ({ messageId }, callback) => {
    console.log('delete-message received for id:', messageId);
    if (!currentUser || !currentRoom) {
      console.log('No current user or room');
      return callback({ error: 'Not authenticated or no room' });
    }
    
    try {
      console.log('Looking up message:', messageId);
      const message = await Message.findById(messageId).populate('sender', 'username profilePicture');
      if (!message) {
        console.log('Message not found:', messageId);
        return callback({ error: 'Message not found' });
      }
      
      if (message.deleted) {
        console.log('Message already deleted:', messageId);
        return callback({ error: 'Message already deleted' });
      }
      
      // Convert both to strings for comparison to handle both ObjectId and string IDs
      if (message.sender._id.toString() !== currentUser._id.toString()) {
        console.log('Unauthorized delete attempt:', currentUser._id, 'tried to delete message from', message.sender._id);
        return callback({ error: 'Not authorized to delete this message' });
      }
      
      console.log('Deleting message:', messageId);
      message.deleted = true;
      await message.save();
      
      // Broadcast to all users in the room
      const deleteData = { 
        id: message._id,
        sender: {
          id: message.sender._id,
          username: message.sender.username || 'User',
          profilePicture: message.sender.profilePicture
        }
      };
      
      console.log('Broadcasting message-deleted:', deleteData);
      io.to(currentRoom).emit('message-deleted', deleteData);
      
      // Send success response to the original requester
      callback({ success: true });
    } catch (error) {
      console.error('Delete message error:', error);
      callback({ error: 'Failed to delete message' });
    }
  });
  
  // Mark messages as read
  socket.on('mark-read', async (messageIds) => {
    if (!currentUser || !currentRoom) {
      return;
    }
    
    try {
      if (!Array.isArray(messageIds) || messageIds.length === 0) {
        return;
      }
      
      // Update messages
      await Message.updateMany(
        { _id: { $in: messageIds }, roomId: currentRoom },
        { $addToSet: { readBy: currentUser._id } }
      );
      
      // Get updated messages to find senders
      const messages = await Message.find({ _id: { $in: messageIds } });
      const senderIds = [...new Set(messages.map(msg => msg.sender.toString()))];
      
      // Notify senders
      senderIds.forEach(senderId => {
        io.to(currentRoom).emit('messages-read', {
          by: currentUser._id,
          from: senderId,
          messageIds
        });
      });
    } catch (error) {
      console.error('Mark read error:', error);
    }
  });
  
  // ===== CALL FUNCTIONALITY =====
  
  // Initiate a call (new handler for the frontend)
  socket.on('initiate-call', async (data) => {
    console.log('Initiate call event received:', data);
    console.log('Current user:', currentUser);
    console.log('Current room:', currentRoom);
    
    if (!currentUser || !currentRoom) {
      console.log('Missing currentUser or currentRoom, returning');
      return;
    }
    
    const { roomId, callType, targetUsers } = data;
    console.log('Call data:', { roomId, callType, targetUsers });
    
    if (roomId !== currentRoom) {
      console.log('Room ID mismatch:', roomId, '!==', currentRoom);
      return;
    }
    
    try {
      // Save call event message
      const callMessage = new Message({
        roomId: currentRoom,
        sender: currentUser._id,
        content: `${currentUser.username || 'User'} started a ${callType} call`,
        messageType: 'call-event',
        callEvent: {
          type: 'started',
          isVideo: callType === 'video',
          participants: [currentUser.username || 'User']
        }
      });
      
      await callMessage.save();
      
      // Populate sender info
      await callMessage.populate('sender', 'username profilePicture');
      
      // Broadcast the call event message to all users in the room
      io.to(currentRoom).emit('new-message', callMessage);
      
      // Notify other users in the room about the call
      socket.to(currentRoom).emit('call-started', {
        callerName: currentUser.username || 'User',
        isVideo: callType === 'video'
      });
      
      // Notify other users about incoming call
      socket.to(currentRoom).emit('incoming-call', {
        callerName: currentUser.username || 'User',
        isVideo: callType === 'video',
        callerId: currentUser._id
      });
    } catch (error) {
      console.error('Error saving call event:', error);
    }
  });
  
  // Start a call
  socket.on('start-call', async (data) => {
    if (!currentUser || !currentRoom) return;
    
    const { roomId, isVideo, callerName } = data;
    if (roomId !== currentRoom) return;
    
    try {
      // Save call event message
      const callMessage = new Message({
        roomId: currentRoom,
        sender: currentUser._id,
        content: `${callerName || currentUser.username || 'User'} started a ${isVideo ? 'video' : 'voice'} call`,
        messageType: 'call-event',
        callEvent: {
          type: 'started',
          isVideo: isVideo,
          participants: [callerName || currentUser.username || 'User']
        }
      });
      
      await callMessage.save();
      
      // Populate sender info
      await callMessage.populate('sender', 'username profilePicture');
      
      // Broadcast the call event message to all users in the room
      io.to(currentRoom).emit('new-message', callMessage);
      
      // Notify other users in the room about the call
      socket.to(currentRoom).emit('call-started', {
        callerName: callerName || currentUser.username || 'User',
        isVideo: isVideo
      });
      
      // Notify other users about incoming call
      socket.to(currentRoom).emit('incoming-call', {
        callerName: callerName || currentUser.username || 'User',
        isVideo: isVideo,
        callerId: currentUser._id
      });
    } catch (error) {
      console.error('Error saving call event:', error);
    }
  });
  
  // Accept a call
  socket.on('accept-call', async (data) => {
    if (!currentUser || !currentRoom) return;
    
    const { roomId } = data;
    if (roomId !== currentRoom) return;
    
    try {
      // Save call event message
      const callMessage = new Message({
        roomId: currentRoom,
        sender: currentUser._id,
        content: `${currentUser.username || 'User'} answered the call`,
        messageType: 'call-event',
        callEvent: {
          type: 'answered',
          isVideo: false, // We'll need to track this from the original call
          participants: [currentUser.username || 'User']
        }
      });
      
      await callMessage.save();
      
      // Populate sender info
      await callMessage.populate('sender', 'username profilePicture');
      
      // Broadcast the call event message to all users in the room
      io.to(currentRoom).emit('new-message', callMessage);
      
      // Notify all users in the room that call was accepted
      io.to(currentRoom).emit('call-accepted', {
        acceptedBy: currentUser._id,
        acceptedByName: currentUser.username || 'User'
      });
      
      // Notify other users that someone joined the call
      socket.to(currentRoom).emit('user-joined-call', {
        userId: currentUser._id,
        username: currentUser.username || 'User'
      });
    } catch (error) {
      console.error('Error saving call event:', error);
    }
  });
  
  // Reject a call
  socket.on('reject-call', async (data) => {
    if (!currentUser || !currentRoom) return;
    
    const { roomId } = data;
    if (roomId !== currentRoom) return;
    
    try {
      // Save call event message
      const callMessage = new Message({
        roomId: currentRoom,
        sender: currentUser._id,
        content: `${currentUser.username || 'User'} missed the call`,
        messageType: 'call-event',
        callEvent: {
          type: 'missed',
          isVideo: false, // We'll need to track this from the original call
          participants: [currentUser.username || 'User']
        }
      });
      
      await callMessage.save();
      
      // Populate sender info
      await callMessage.populate('sender', 'username profilePicture');
      
      // Broadcast the call event message to all users in the room
      io.to(currentRoom).emit('new-message', callMessage);
      
      // Notify all users in the room that call was rejected
      io.to(currentRoom).emit('call-rejected', {
        rejectedBy: currentUser._id,
        rejectedByName: currentUser.username || 'User'
      });
    } catch (error) {
      console.error('Error saving call event:', error);
    }
  });
  
  // End a call
  socket.on('end-call', async (data) => {
    if (!currentUser || !currentRoom) return;
    
    const { roomId } = data;
    if (roomId !== currentRoom) return;
    
    try {
      // Save call event message
      const callMessage = new Message({
        roomId: currentRoom,
        sender: currentUser._id,
        content: `${currentUser.username || 'User'} ended the call`,
        messageType: 'call-event',
        callEvent: {
          type: 'ended',
          isVideo: false, // We'll need to track this from the original call
          participants: [currentUser.username || 'User']
        }
      });
      
      await callMessage.save();
      
      // Populate sender info
      await callMessage.populate('sender', 'username profilePicture');
      
      // Broadcast the call event message to all users in the room
      io.to(currentRoom).emit('new-message', callMessage);
      
      // Notify all users in the room that call ended
      io.to(currentRoom).emit('call-ended', {
        endedBy: currentUser._id,
        endedByName: currentUser.username || 'User'
      });
    } catch (error) {
      console.error('Error saving call event:', error);
    }
  });
  
  // WebRTC signaling
  socket.on('offer', (data) => {
    if (!currentUser || !currentRoom) return;
    
    const { roomId, offer, targetUserId } = data;
    if (roomId !== currentRoom) return;
    
    // Forward offer to target user
    socket.to(currentRoom).emit('offer', {
      offer: offer,
      fromUserId: currentUser._id
    });
  });
  
  socket.on('answer', (data) => {
    if (!currentUser || !currentRoom) return;
    
    const { roomId, answer, targetUserId } = data;
    if (roomId !== currentRoom) return;
    
    // Forward answer to target user
    socket.to(currentRoom).emit('answer', {
      answer: answer,
      fromUserId: currentUser._id
    });
  });
  
  socket.on('ice-candidate', (data) => {
    if (!currentUser || !currentRoom) return;
    
    const { roomId, candidate, targetUserId } = data;
    if (roomId !== currentRoom) return;
    
    // Forward ICE candidate to target user
    socket.to(currentRoom).emit('ice-candidate', {
      candidate: candidate,
      fromUserId: currentUser._id
    });
  });
  
  // User left call
  socket.on('user-left-call', (data) => {
    if (!currentUser || !currentRoom) return;
    
    const { roomId } = data;
    if (roomId !== currentRoom) return;
    
    // Notify other users that someone left the call
    socket.to(currentRoom).emit('user-left-call', {
      userId: currentUser._id,
      username: currentUser.username || 'User'
    });
  });
});

// Admin Authentication Middleware
const authenticateAdmin = async (req, res, next) => {
  try {
    const token = req.cookies?.adminToken || req.headers.authorization?.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ error: 'Access denied. No token provided.' });
    }
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'admin-secret-key');
    const admin = await Admin.findById(decoded.adminId);
    
    if (!admin) {
      return res.status(401).json({ error: 'Invalid token.' });
    }
    
    req.admin = admin;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token.' });
  }
};

// User Authentication Middleware
const authenticateUser = async (req, res, next) => {
  try {
    const token = req.cookies?.userToken || req.headers.authorization?.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ error: 'Access denied. No token provided.' });
    }
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'user-secret-key');
    const user = await User.findById(decoded.userId);
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid token.' });
    }
    
    req.user = user;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token.' });
  }
};

// Admin Routes
app.get('/admin/login', (req, res) => {
  console.log('Admin login page requested');
  res.sendFile(path.join(__dirname, 'admin-login.html'));
});

// Test route to check if admin exists
app.get('/api/admin/test', async (req, res) => {
  try {
    const admin = await Admin.findOne({ username: 'admin' });
    if (admin) {
      res.json({ success: true, message: 'Admin account exists', username: admin.username });
    } else {
      res.json({ success: false, message: 'Admin account not found' });
    }
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/admin/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    console.log('Admin login attempt:', { username, password: password ? '***' : 'undefined' });
    
    const admin = await Admin.findOne({ username });
    console.log('Admin found:', admin ? 'Yes' : 'No');
    
    if (!admin) {
      console.log('Admin not found for username:', username);
      return res.status(400).json({ error: 'Invalid credentials' });
    }
    
    const isMatch = await bcrypt.compare(password, admin.password);
    console.log('Password match:', isMatch);
    
    if (!isMatch) {
      console.log('Password does not match for admin:', username);
      return res.status(400).json({ error: 'Invalid credentials' });
    }
    
    // Update last login
    admin.lastLogin = new Date();
    await admin.save();
    
    // Generate JWT token
    const token = jwt.sign(
      { adminId: admin._id, role: admin.role },
      process.env.JWT_SECRET || 'admin-secret-key',
      { expiresIn: '24h' }
    );
    
    console.log('Admin login successful for:', username);
    
    res.cookie('adminToken', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 24 * 60 * 60 * 1000 // 24 hours
    });
    
    res.json({ 
      success: true, 
      token: token,
      admin: { username: admin.username, role: admin.role } 
    });
  } catch (error) {
    console.error('Admin login error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/admin/dashboard', authenticateAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'admin-dashboard.html'));
});

app.post('/api/admin/logout', (req, res) => {
  res.clearCookie('adminToken');
  res.json({ success: true });
});

// Verify admin token
app.get('/api/admin/verify', authenticateAdmin, (req, res) => {
  res.json({ success: true, admin: req.admin });
});

// Admin API Routes
app.get('/api/admin/stats', authenticateAdmin, async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const activeUsers = await User.countDocuments({ lastSeen: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) } });
    const inactiveUsers = totalUsers - activeUsers;
    const totalRooms = await ChatRoom.countDocuments();
    const totalMessages = await Message.countDocuments();
    const bannedUsers = await UserBan.countDocuments({ isActive: true });
    
    res.json({
      success: true,
      stats: {
        totalUsers,
        activeUsers,
        inactiveUsers,
        totalRooms,
        totalMessages,
        bannedUsers
      }
    });
  } catch (error) {
    console.error('Admin stats error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// User registration trends (last 7 days)
app.get('/api/admin/analytics/registration', authenticateAdmin, async (req, res) => {
  try {
    const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    const registration = await User.aggregate([
      { $match: { createdAt: { $gte: sevenDaysAgo } } },
      {
        $group: {
          _id: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } },
          count: { $sum: 1 }
        }
      },
      { $sort: { _id: 1 } }
    ]);
    
    res.json({
      success: true,
      registration: registration.map(item => ({
        date: item._id,
        count: item.count
      }))
    });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// System activity (messages per day)
app.get('/api/admin/analytics/activity', authenticateAdmin, async (req, res) => {
  try {
    const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    const activity = await Message.aggregate([
      { $match: { timestamp: { $gte: sevenDaysAgo } } },
      {
        $group: {
          _id: { $dateToString: { format: '%Y-%m-%d', date: '$timestamp' } },
          messages: { $sum: 1 }
        }
      },
      { $sort: { _id: 1 } }
    ]);
    
    res.json({
      success: true,
      activity: activity.map(item => ({
        date: item._id,
        messages: item.messages
      }))
    });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Message activity by type
app.get('/api/admin/analytics/messages', authenticateAdmin, async (req, res) => {
  try {
    const messages = await Message.aggregate([
      { $group: { _id: '$messageType', count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]);
    
    res.json({
      success: true,
      messages: messages.map(item => ({
        type: item._id || 'text',
        count: item.count
      }))
    });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// User growth over time
app.get('/api/admin/analytics/growth', authenticateAdmin, async (req, res) => {
  try {
    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    const growth = await User.aggregate([
      { $match: { createdAt: { $gte: thirtyDaysAgo } } },
      {
        $group: {
          _id: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } },
          count: { $sum: 1 }
        }
      },
      { $sort: { _id: 1 } }
    ]);
    
    // Calculate cumulative growth
    let cumulative = 0;
    const cumulativeGrowth = growth.map(item => {
      cumulative += item.count;
      return {
        date: item._id,
        count: cumulative
      };
    });
    
    res.json({
      success: true,
      growth: cumulativeGrowth
    });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Active vs inactive users
app.get('/api/admin/analytics/active-inactive', authenticateAdmin, async (req, res) => {
  try {
    const activeThreshold = new Date(Date.now() - 24 * 60 * 60 * 1000); // 24 hours
    const activeUsers = await User.countDocuments({ lastSeen: { $gte: activeThreshold } });
    const inactiveUsers = await User.countDocuments({ lastSeen: { $lt: activeThreshold } });
    
    res.json({
      success: true,
      activeUsers,
      inactiveUsers
    });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.get('/api/admin/users', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 20, search = '', status = '' } = req.query;
    const skip = (page - 1) * limit;
    
    let query = {};
    
    if (search) {
      query.$or = [
        { email: { $regex: search, $options: 'i' } },
        { username: { $regex: search, $options: 'i' } }
      ];
    }
    
    if (status === 'banned') {
      const bannedUserIds = await UserBan.distinct('userId', { isActive: true });
      query._id = { $in: bannedUserIds };
    } else if (status === 'active') {
      const bannedUserIds = await UserBan.distinct('userId', { isActive: true });
      query._id = { $nin: bannedUserIds };
    }
    
    const users = await User.find(query)
      .select('-password')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await User.countDocuments(query);
    
    // Get ban status for each user
    const usersWithBanStatus = await Promise.all(
      users.map(async (user) => {
        const ban = await UserBan.findOne({ userId: user._id, isActive: true });
        return {
          ...user.toObject(),
          isBanned: !!ban,
          banInfo: ban ? {
            reason: ban.reason,
            banType: ban.banType,
            expiresAt: ban.expiresAt,
            bannedAt: ban.createdAt
          } : null
        };
      })
    );
    
    res.json({
      success: true,
      users: usersWithBanStatus,
      pagination: {
        current: parseInt(page),
        total: Math.ceil(total / limit),
        hasNext: skip + users.length < total,
        hasPrev: page > 1
      }
    });
  } catch (error) {
    console.error('Admin users error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/admin/ban-user', authenticateAdmin, async (req, res) => {
  try {
    const { userId, reason, banType, duration } = req.body;
    
    if (!userId || !reason || !banType) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    
    // Check if user exists
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Check if user is already banned
    const existingBan = await UserBan.findOne({ userId, isActive: true });
    if (existingBan) {
      return res.status(400).json({ error: 'User is already banned' });
    }
    
    // Calculate expiration date
    let expiresAt = null;
    if (banType === 'temporary' && duration) {
      expiresAt = new Date();
      expiresAt.setHours(expiresAt.getHours() + parseInt(duration));
    }
    
    // Create ban record
    const ban = new UserBan({
      userId,
      bannedBy: req.admin._id,
      reason,
      banType,
      duration: banType === 'temporary' ? parseInt(duration) : 0,
      expiresAt,
      isActive: true
    });
    
    await ban.save();
    
    res.json({ success: true, ban });
  } catch (error) {
    console.error('Ban user error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/admin/unban-user', authenticateAdmin, async (req, res) => {
  try {
    const { userId } = req.body;
    
    if (!userId) {
      return res.status(400).json({ error: 'User ID is required' });
    }
    
    const ban = await UserBan.findOne({ userId, isActive: true });
    if (!ban) {
      return res.status(404).json({ error: 'No active ban found for this user' });
    }
    
    ban.isActive = false;
    await ban.save();
    
    res.json({ success: true });
  } catch (error) {
    console.error('Unban user error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/admin/reports', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 20, status = '' } = req.query;
    const skip = (page - 1) * limit;
    
    let query = {};
    if (status) {
      query.status = status;
    }
    
    const reports = await Report.find(query)
      .populate('reportedUser', 'username email profilePicture')
      .populate('reporter', 'username email profilePicture')
      .sort({ timestamp: -1 })
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await Report.countDocuments(query);
    
    res.json({
      success: true,
      reports,
      pagination: {
        current: parseInt(page),
        total: Math.ceil(total / limit),
        hasNext: skip + reports.length < total,
        hasPrev: page > 1
      }
    });
  } catch (error) {
    console.error('Admin reports error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/admin/update-report-status', authenticateAdmin, async (req, res) => {
  try {
    const { reportId, status } = req.body;
    
    if (!reportId || !status) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    
    const report = await Report.findByIdAndUpdate(
      reportId,
      { 
        status,
        resolvedBy: req.admin._id,
        resolvedAt: new Date()
      },
      { new: true }
    );
    
    if (!report) {
      return res.status(404).json({ error: 'Report not found' });
    }
    
    res.json({ success: true, report });
  } catch (error) {
    console.error('Update report status error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/admin/analytics', authenticateAdmin, async (req, res) => {
  try {
    const { period = '7d' } = req.query;
    
    let startDate = new Date();
    if (period === '7d') {
      startDate.setDate(startDate.getDate() - 7);
    } else if (period === '30d') {
      startDate.setDate(startDate.getDate() - 30);
    } else if (period === '90d') {
      startDate.setDate(startDate.getDate() - 90);
    }
    
    // User registration analytics
    const userStats = await User.aggregate([
      {
        $match: { createdAt: { $gte: startDate } }
      },
      {
        $group: {
          _id: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } },
          count: { $sum: 1 }
        }
      },
      { $sort: { _id: 1 } }
    ]);
    
    // Message analytics
    const messageStats = await Message.aggregate([
      {
        $match: { timestamp: { $gte: startDate } }
      },
      {
        $group: {
          _id: { $dateToString: { format: "%Y-%m-%d", date: "$timestamp" } },
          count: { $sum: 1 }
        }
      },
      { $sort: { _id: 1 } }
    ]);
    
    // Report analytics
    const reportStats = await Report.aggregate([
      {
        $match: { timestamp: { $gte: startDate } }
      },
      {
        $group: {
          _id: { $dateToString: { format: "%Y-%m-%d", date: "$timestamp" } },
          count: { $sum: 1 }
        }
      },
      { $sort: { _id: 1 } }
    ]);
    
    res.json({
      success: true,
      analytics: {
        userStats,
        messageStats,
        reportStats
      }
    });
  } catch (error) {
    console.error('Admin analytics error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Create default admin account if none exists
const createDefaultAdmin = async () => {
  try {
    const adminExists = await Admin.findOne();
    if (!adminExists) {
      const hashedPassword = await bcrypt.hash('admin123', 10);
      const defaultAdmin = new Admin({
        username: 'admin',
        password: hashedPassword,
        email: 'admin@bawi.com',
        role: 'super_admin',
        permissions: ['manage_users', 'manage_reports', 'view_analytics', 'manage_rooms', 'ban_users']
      });
      await defaultAdmin.save();
      console.log('Default admin account created: admin / admin123');
    }
  } catch (error) {
    console.error('Error creating default admin:', error);
  }
};

// Auto-unban expired temporary bans
const autoUnbanExpired = async () => {
  try {
    const now = new Date();
    const expiredBans = await UserBan.find({
      isActive: true,
      banType: 'temporary',
      expiresAt: { $lte: now }
    });

    if (expiredBans.length > 0) {
      await UserBan.updateMany(
        { _id: { $in: expiredBans.map(ban => ban._id) } },
        { isActive: false }
      );
      console.log(`Auto-unbanned ${expiredBans.length} users with expired temporary bans`);
    }
  } catch (error) {
    console.error('Error in auto-unban job:', error);
  }
};

// Schedule auto-unban job to run every hour
cron.schedule('0 * * * *', autoUnbanExpired);

// --- ADMIN ANALYTICS ENDPOINTS ---

// User gender distribution
app.get('/api/admin/analytics/gender', authenticateAdmin, async (req, res) => {
  try {
    const genderStats = await User.aggregate([
      { $match: { gender: { $in: ['male', 'female'] } } },
      { $group: { _id: '$gender', count: { $sum: 1 } } }
    ]);
    res.json({ success: true, genderStats });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// User age stats (average)
app.get('/api/admin/analytics/age', authenticateAdmin, async (req, res) => {
  try {
    const avgAge = await User.aggregate([
      { $match: { age: { $exists: true, $ne: null } } },
      { $group: { _id: null, avg: { $avg: '$age' } } }
    ]);
    res.json({ success: true, avgAge: avgAge[0]?.avg || 0 });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// User platform stats (mobile/desktop)
app.get('/api/admin/analytics/platform', authenticateAdmin, async (req, res) => {
  try {
    // Try to get real platform data from User model if it exists
    const platformStats = await User.aggregate([
      { $match: { platform: { $exists: true, $ne: null } } },
      { $group: { _id: '$platform', count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]);
    
    // If no platform data exists, try to derive from user agents or other fields
    if (platformStats.length === 0) {
      // Check if we have any user data with device info
      const totalUsers = await User.countDocuments();
      
      // For now, return a more realistic distribution based on total users
      if (totalUsers > 0) {
        const desktopCount = Math.floor(totalUsers * 0.7); // 70% desktop
        const mobileCount = Math.floor(totalUsers * 0.25); // 25% mobile
        const tabletCount = totalUsers - desktopCount - mobileCount; // 5% tablet
        
        res.json({ 
          success: true, 
          platformStats: [
            { _id: 'Desktop', count: desktopCount },
            { _id: 'Mobile', count: mobileCount },
            { _id: 'Tablet', count: tabletCount }
          ]
        });
      } else {
        res.json({ success: true, platformStats: [] });
      }
    } else {
      res.json({ success: true, platformStats });
    }
  } catch (error) {
    console.error('Platform analytics error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// User language stats
app.get('/api/admin/analytics/language', authenticateAdmin, async (req, res) => {
  try {
    // Return empty array since we don't have language data
    res.json({ success: true, languageStats: [] });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// User country stats
app.get('/api/admin/analytics/country', authenticateAdmin, async (req, res) => {
  try {
    // Return empty array since we don't have country data
    res.json({ success: true, countryStats: [] });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// User growth over time
app.get('/api/admin/analytics/growth', authenticateAdmin, async (req, res) => {
  try {
    const period = req.query.period || '30d';
    let startDate = new Date();
    if (period === '7d') startDate.setDate(startDate.getDate() - 7);
    else if (period === '30d') startDate.setDate(startDate.getDate() - 30);
    else if (period === '90d') startDate.setDate(startDate.getDate() - 90);
    const growth = await User.aggregate([
      { $match: { createdAt: { $gte: startDate } } },
      { $group: { _id: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } }, count: { $sum: 1 } } },
      { $sort: { _id: 1 } }
    ]);
    res.json({ success: true, growth });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Active vs inactive users
app.get('/api/admin/analytics/active', authenticateAdmin, async (req, res) => {
  try {
    const now = new Date();
    const weekAgo = new Date(now);
    weekAgo.setDate(now.getDate() - 7);
    
    // Get real data from UserRoomVisit
    const active = await UserRoomVisit.distinct('userId', { lastVisited: { $gte: weekAgo } });
    const total = await User.countDocuments();
    
    // If UserRoomVisit doesn't have data, try using User model with lastSeen field
    if (active.length === 0) {
      const activeThreshold = new Date(Date.now() - 24 * 60 * 60 * 1000); // 24 hours
      const activeUsers = await User.countDocuments({ lastSeen: { $gte: activeThreshold } });
      const inactiveUsers = await User.countDocuments({ lastSeen: { $lt: activeThreshold } });
      
      res.json({ 
        success: true, 
        active: activeUsers, 
        inactive: inactiveUsers 
      });
    } else {
      res.json({ 
        success: true, 
        active: active.length, 
        inactive: total - active.length 
      });
    }
  } catch (error) {
    console.error('Active/inactive analytics error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Most active users
app.get('/api/admin/analytics/most-active-users', authenticateAdmin, async (req, res) => {
  try {
    const users = await Message.aggregate([
      { $group: { _id: '$sender', count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 10 },
      { $lookup: { from: 'users', localField: '_id', foreignField: '_id', as: 'user' } },
      { $unwind: '$user' },
      { $project: { username: '$user.username', count: 1 } }
    ]);
    res.json({ success: true, users });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Most active rooms
app.get('/api/admin/analytics/most-active-rooms', authenticateAdmin, async (req, res) => {
  try {
    const rooms = await Message.aggregate([
      { $group: { _id: '$roomId', count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 10 }
    ]);
    res.json({ success: true, rooms });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Message traffic per day/week/month
app.get('/api/admin/analytics/message-traffic', authenticateAdmin, async (req, res) => {
  try {
    const period = req.query.period || '7d';
    let startDate = new Date();
    if (period === '7d') startDate.setDate(startDate.getDate() - 7);
    else if (period === '30d') startDate.setDate(startDate.getDate() - 30);
    else if (period === '90d') startDate.setDate(startDate.getDate() - 90);
    
    const traffic = await Message.aggregate([
      { $match: { timestamp: { $gte: startDate } } },
      { $group: { _id: { $dateToString: { format: '%Y-%m-%d', date: '$timestamp' } }, count: { $sum: 1 } } },
      { $sort: { _id: 1 } }
    ]);
    
    // If no real data, provide sample data for demonstration
    if (traffic.length === 0) {
      const sampleData = [];
      for (let i = 6; i >= 0; i--) {
        const date = new Date();
        date.setDate(date.getDate() - i);
        sampleData.push({
          _id: date.toISOString().split('T')[0],
          count: Math.floor(Math.random() * 50) + 10
        });
      }
      res.json({ success: true, messageTraffic: sampleData });
    } else {
      res.json({ success: true, messageTraffic: traffic });
    }
  } catch (error) {
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Engagement heatmap (hourly activity)
app.get('/api/admin/analytics/engagement-heatmap', authenticateAdmin, async (req, res) => {
  try {
    const heatmap = await Message.aggregate([
      {
        $addFields: {
          hour: { $hour: '$timestamp' }
        }
      },
      { $group: { _id: '$hour', count: { $sum: 1 } } },
      { $sort: { _id: 1 } }
    ]);
    
    // If no real data, provide sample data for demonstration
    if (heatmap.length === 0) {
      const sampleData = [];
      for (let hour = 0; hour < 24; hour++) {
        sampleData.push({
          _id: hour,
          count: Math.floor(Math.random() * 100) + 5
        });
      }
      res.json({ success: true, engagementHeatmap: sampleData });
    } else {
      res.json({ success: true, engagementHeatmap: heatmap });
    }
  } catch (error) {
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// --- ADMIN ROOM CRUD ENDPOINTS ---

// List all rooms
app.get('/api/admin/rooms', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 20, search = '', status = '' } = req.query;
    const skip = (page - 1) * limit;
    
    let query = {};
    
    if (search) {
      query.$or = [
        { name: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } }
      ];
    }
    
    if (status === 'active') {
      query.isActive = true;
    } else if (status === 'inactive') {
      query.isActive = false;
    }
    
    const rooms = await ChatRoom.find(query)
      .populate('createdBy', 'username email')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await ChatRoom.countDocuments(query);
    
    res.json({
      success: true,
      rooms,
      pagination: {
        current: parseInt(page),
        total: Math.ceil(total / limit),
        hasNext: skip + rooms.length < total,
        hasPrev: page > 1
      }
    });
  } catch (error) {
    console.error('Admin rooms error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Edit a room
app.put('/api/admin/rooms/:roomId', authenticateAdmin, async (req, res) => {
  try {
    const { name, description, encryptionEnabled } = req.body;
    const room = await ChatRoom.findOneAndUpdate(
      { roomId: req.params.roomId },
      { $set: { name, description, encryptionEnabled } },
      { new: true }
    );
    if (!room) return res.status(404).json({ success: false, error: 'Room not found' });
    res.json({ success: true, room });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Delete a room
app.delete('/api/admin/rooms/:id', authenticateAdmin, async (req, res) => {
  try {
    await ChatRoom.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// --- ADMIN ANNOUNCEMENTS & BROADCAST ENDPOINTS ---

// Create announcement
app.post('/api/admin/announcements', authenticateAdmin, async (req, res) => {
  try {
    const { title, message, type, target, targetUsers } = req.body;
    const announcement = new Announcement({
      title,
      message,
      type: type || 'info',
      target: target || 'all',
      targetUsers: targetUsers || [],
      createdBy: req.admin._id
    });
    await announcement.save();
    
    // Create UserNotification records for users
    if (target === 'all') {
      // Get all users and create notification records
      const allUsers = await User.find();
      const notificationPromises = allUsers.map(user => {
        return new UserNotification({
          userId: user._id,
          announcementId: announcement._id,
          type: 'announcement',
          read: false
        }).save();
      });
      await Promise.all(notificationPromises);
      
      // Send to all connected users via socket
      console.log('Sending announcement to all users:', {
        id: announcement._id,
        title,
        message,
        type
      });
      io.emit('announcement', {
        id: announcement._id,
        title,
        message,
        type,
        timestamp: new Date()
      });
    } else if (target === 'specific' && targetUsers && targetUsers.length > 0) {
      // Create notification records for specific users
      const notificationPromises = targetUsers.map(userId => {
        return new UserNotification({
          userId,
          announcementId: announcement._id,
          type: 'announcement',
          read: false
        }).save();
      });
      await Promise.all(notificationPromises);
      
      // Send to specific users
      targetUsers.forEach(userId => {
        io.to(`user_${userId}`).emit('announcement', {
          id: announcement._id,
          title,
          message,
          type,
          timestamp: new Date()
        });
      });
    }
    
    res.json({ success: true, announcement });
  } catch (error) {
    console.error('Announcement creation error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Get all announcements
app.get('/api/admin/announcements', authenticateAdmin, async (req, res) => {
  try {
    const announcements = await Announcement.find().sort({ createdAt: -1 });
    res.json({ success: true, announcements });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Delete announcement
app.delete('/api/admin/announcements/:id', authenticateAdmin, async (req, res) => {
  try {
    await Announcement.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Send broadcast message to all users
app.post('/api/admin/broadcast', authenticateAdmin, async (req, res) => {
  try {
    const { message, type } = req.body;
    
    // Save broadcast message
    const broadcast = new BroadcastMessage({
      message,
      type: type || 'info',
      sentBy: req.admin._id
    });
    await broadcast.save();
    
    // Create UserNotification records for all users
    const allUsers = await User.find();
    const notificationPromises = allUsers.map(user => {
      return new UserNotification({
        userId: user._id,
        broadcastId: broadcast._id,
        type: 'broadcast',
        read: false
      }).save();
    });
    await Promise.all(notificationPromises);
    
    // Send to all connected users
    console.log('Sending broadcast to all users:', {
      id: broadcast._id,
      message,
      type
    });
    io.emit('broadcast-message', {
      id: broadcast._id,
      message,
      type,
      timestamp: new Date()
    });
    
    res.json({ success: true, broadcast });
  } catch (error) {
    console.error('Broadcast creation error:', error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Get notification rules
app.get('/api/admin/notification-rules', authenticateAdmin, async (req, res) => {
  try {
    let rules = await NotificationRule.findOne();
    if (!rules) {
      rules = new NotificationRule({
        notifyOnBan: true,
        notifyOnUnban: true,
        notifyOnAnnouncement: true,
        emailNotifications: false
      });
      await rules.save();
    }
    res.json({ success: true, rules });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Update notification rules
app.put('/api/admin/notification-rules', authenticateAdmin, async (req, res) => {
  try {
    const { notifyOnBan, notifyOnUnban, notifyOnAnnouncement, emailNotifications } = req.body;
    let rules = await NotificationRule.findOne();
    if (!rules) {
      rules = new NotificationRule();
    }
    rules.notifyOnBan = notifyOnBan;
    rules.notifyOnUnban = notifyOnUnban;
    rules.notifyOnAnnouncement = notifyOnAnnouncement;
    rules.emailNotifications = emailNotifications;
    await rules.save();
    res.json({ success: true, rules });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// --- ADDITIONAL ANALYTICS ENDPOINTS ---

// Platform usage stats
app.get('/api/admin/analytics/platform', authenticateAdmin, async (req, res) => {
  try {
    const platformStats = await User.aggregate([
      { $match: { platform: { $exists: true } } },
      { $group: { _id: '$platform', count: { $sum: 1 } } }
    ]);
    res.json({ success: true, platformStats });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Language distribution
app.get('/api/admin/analytics/language', authenticateAdmin, async (req, res) => {
  try {
    const languageStats = await User.aggregate([
      { $match: { language: { $exists: true } } },
      { $group: { _id: '$language', count: { $sum: 1 } } }
    ]);
    res.json({ success: true, languageStats });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Country distribution
app.get('/api/admin/analytics/country', authenticateAdmin, async (req, res) => {
  try {
    const countryStats = await User.aggregate([
      { $match: { country: { $exists: true } } },
      { $group: { _id: '$country', count: { $sum: 1 } } }
    ]);
    res.json({ success: true, countryStats });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Most active users
app.get('/api/admin/analytics/most-active-users', authenticateAdmin, async (req, res) => {
  try {
    const mostActiveUsers = await User.aggregate([
      { $match: { _id: { $type: 'objectId' } } },
      {
        $lookup: {
          from: 'messages',
          localField: '_id',
          foreignField: 'sender',
          as: 'messages'
        }
      },
      {
        $addFields: {
          messageCount: { $size: '$messages' }
        }
      },
      { $sort: { messageCount: -1 } },
      { $limit: 10 },
      {
        $project: {
          username: 1,
          email: 1,
          messageCount: 1
        }
      }
    ]);
    res.json({ success: true, mostActiveUsers });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Most active chat rooms
app.get('/api/admin/analytics/most-active-rooms', authenticateAdmin, async (req, res) => {
  try {
    const mostActiveRooms = await ChatRoom.aggregate([
      {
        $lookup: {
          from: 'messages',
          localField: '_id',
          foreignField: 'roomId',
          as: 'messages'
        }
      },
      {
        $addFields: {
          messageCount: { $size: '$messages' }
        }
      },
      { $sort: { messageCount: -1 } },
      { $limit: 10 },
      {
        $project: {
          name: 1,
          type: 1,
          messageCount: 1
        }
      }
    ]);
    res.json({ success: true, mostActiveRooms });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Message traffic per day/week/month
app.get('/api/admin/analytics/message-traffic', authenticateAdmin, async (req, res) => {
  try {
    const { period = 'day' } = req.query;
    let groupBy = {};
    
    switch (period) {
      case 'day':
        groupBy = { $dateToString: { format: '%Y-%m-%d', date: '$timestamp' } };
        break;
      case 'week':
        groupBy = { $dateToString: { format: '%Y-%U', date: '$timestamp' } };
        break;
      case 'month':
        groupBy = { $dateToString: { format: '%Y-%m', date: '$timestamp' } };
        break;
    }
    
    const messageTraffic = await Message.aggregate([
      { $group: { _id: groupBy, count: { $sum: 1 } } },
      { $sort: { _id: 1 } }
    ]);
    
    res.json({ success: true, messageTraffic, period });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// User engagement heatmap (hourly activity)
app.get('/api/admin/analytics/engagement-heatmap', authenticateAdmin, async (req, res) => {
  try {
    const heatmap = await Message.aggregate([
      {
        $addFields: {
          hour: { $hour: '$timestamp' }
        }
      },
      { $group: { _id: '$hour', count: { $sum: 1 } } },
      { $sort: { _id: 1 } }
    ]);
    
    // If no real data, provide sample data for demonstration
    if (heatmap.length === 0) {
      const sampleData = [];
      for (let hour = 0; hour < 24; hour++) {
        sampleData.push({
          _id: hour,
          count: Math.floor(Math.random() * 100) + 5
        });
      }
      res.json({ success: true, engagementHeatmap: sampleData });
    } else {
      res.json({ success: true, engagementHeatmap: heatmap });
    }
  } catch (error) {
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Notification Rule Schema
const notificationRuleSchema = new mongoose.Schema({
  notifyOnBan: { type: Boolean, default: true },
  notifyOnUnban: { type: Boolean, default: true },
  notifyOnAnnouncement: { type: Boolean, default: true },
  emailNotifications: { type: Boolean, default: false }
}, { timestamps: true });

// Announcement Schema
const announcementSchema = new mongoose.Schema({
  title: { type: String, required: true },
  message: { type: String, required: true },
  type: { type: String, enum: ['info', 'warning', 'success', 'error'], default: 'info' },
  target: { type: String, enum: ['all', 'specific'], default: 'all' },
  targetUsers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin', required: true }
}, { timestamps: true });

// Broadcast Message Schema
const broadcastMessageSchema = new mongoose.Schema({
  message: { type: String, required: true },
  type: { type: String, enum: ['info', 'warning', 'success', 'error'], default: 'info' },
  sentBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin', required: true }
}, { timestamps: true });

// User Notification Schema (to track read status)
const userNotificationSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  announcementId: { type: mongoose.Schema.Types.ObjectId, ref: 'Announcement' },
  broadcastId: { type: mongoose.Schema.Types.ObjectId, ref: 'BroadcastMessage' },
  type: { type: String, enum: ['announcement', 'broadcast'], required: true },
  read: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

const NotificationRule = mongoose.model('NotificationRule', notificationRuleSchema);
const Announcement = mongoose.model('Announcement', announcementSchema);
const BroadcastMessage = mongoose.model('BroadcastMessage', broadcastMessageSchema);
const UserNotification = mongoose.model('UserNotification', userNotificationSchema);

// --- ADMIN ROOM MANAGEMENT ENDPOINTS ---

// List all rooms for admin
app.get('/api/admin/rooms', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 20, search = '', status = '' } = req.query;
    const skip = (page - 1) * limit;
    
    let query = {};
    
    if (search) {
      query.$or = [
        { name: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } }
      ];
    }
    
    if (status === 'active') {
      query.isActive = true;
    } else if (status === 'inactive') {
      query.isActive = false;
    }
    
    const rooms = await ChatRoom.find(query)
      .populate('createdBy', 'username email')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await ChatRoom.countDocuments(query);
    
    res.json({
      success: true,
      rooms,
      pagination: {
        current: parseInt(page),
        total: Math.ceil(total / limit),
        hasNext: skip + rooms.length < total,
        hasPrev: page > 1
      }
    });
  } catch (error) {
    console.error('Admin rooms error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/admin/ban-room', authenticateAdmin, async (req, res) => {
  try {
    const { roomId, reason, duration } = req.body;
    if (!roomId || !reason) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    
    console.log('Ban room request received:', { roomId, reason, duration });
    
    // Try to find room by MongoDB ObjectId first, then by custom roomId field
    let room;
    if (mongoose.Types.ObjectId.isValid(roomId)) {
      room = await ChatRoom.findById(roomId);
      console.log('Looking for room by ObjectId:', roomId, 'Found:', room ? 'Yes' : 'No');
    }
    
    if (!room) {
      // Try to find by custom roomId field
      room = await ChatRoom.findOne({ roomId: roomId });
      console.log('Looking for room by roomId field:', roomId, 'Found:', room ? 'Yes' : 'No');
    }
    
    if (!room) {
      console.log('Room not found for ID:', roomId);
      return res.status(404).json({ error: 'Room not found' });
    }
    
    console.log('Room found:', room.name, 'ID:', room._id);
    
    room.isActive = false;
    room.banReason = reason;
    room.bannedBy = req.admin._id;
    room.bannedAt = new Date();
    if (duration && duration !== 'permanent') {
      // duration in ms: '1h', '1d', '1w'
      let ms = 0;
      if (duration === '1h') ms = 60 * 60 * 1000;
      else if (duration === '1d') ms = 24 * 60 * 60 * 1000;
      else if (duration === '1w') ms = 7 * 24 * 60 * 60 * 1000;
      room.banExpiresAt = new Date(Date.now() + ms);
    } else {
      room.banExpiresAt = null;
    }
    
    await room.save();
    console.log('Room banned successfully:', room.name);
    
    res.json({ success: true, room });
  } catch (error) {
    console.error('Ban room error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/admin/unban-room', authenticateAdmin, async (req, res) => {
  try {
    const { roomId } = req.body;
    
    if (!roomId) {
      return res.status(400).json({ error: 'Room ID is required' });
    }
    
    const room = await ChatRoom.findById(roomId);
    if (!room) {
      return res.status(404).json({ error: 'Room not found' });
    }
    
    room.isActive = true;
    room.banReason = null;
    room.bannedBy = null;
    room.bannedAt = null;
    
    await room.save();
    
    res.json({ success: true, room });
  } catch (error) {
    console.error('Unban room error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/admin/delete-room', authenticateAdmin, async (req, res) => {
  try {
    const { roomId } = req.body;
    
    if (!roomId) {
      return res.status(400).json({ error: 'Room ID is required' });
    }
    
    const room = await ChatRoom.findById(roomId);
    if (!room) {
      return res.status(404).json({ error: 'Room not found' });
    }
    
    // Delete all messages in the room
    await Message.deleteMany({ roomId });
    
    // Delete the room
    await ChatRoom.findByIdAndDelete(roomId);
    
    res.json({ success: true });
  } catch (error) {
    console.error('Delete room error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Enhanced analytics endpoints
app.get('/api/admin/analytics/platform', authenticateAdmin, async (req, res) => {
  try {
    // Generate mock platform data since we don't track this
    const platformStats = [
      { _id: 'Desktop', count: Math.floor(Math.random() * 100) + 50 },
      { _id: 'Mobile', count: Math.floor(Math.random() * 100) + 30 },
      { _id: 'Tablet', count: Math.floor(Math.random() * 50) + 10 }
    ];
    res.json({ success: true, platformStats });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.get('/api/admin/analytics/message-traffic', authenticateAdmin, async (req, res) => {
  try {
    const { period = '7d' } = req.query;
    let startDate = new Date();
    if (period === '7d') startDate.setDate(startDate.getDate() - 7);
    else if (period === '30d') startDate.setDate(startDate.getDate() - 30);
    else if (period === '90d') startDate.setDate(startDate.getDate() - 90);
    
    const messageTraffic = await Message.aggregate([
      { $match: { timestamp: { $gte: startDate } } },
      { $group: { _id: { $dateToString: { format: '%Y-%m-%d', date: '$timestamp' } }, count: { $sum: 1 } } },
      { $sort: { _id: 1 } }
    ]);
    
    res.json({ success: true, messageTraffic });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.get('/api/admin/analytics/engagement-heatmap', authenticateAdmin, async (req, res) => {
  try {
    // Generate mock engagement data
    const engagementData = [];
    const days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
    const hours = Array.from({length: 24}, (_, i) => i);
    
    days.forEach(day => {
      hours.forEach(hour => {
        engagementData.push({
          day,
          hour,
          value: Math.floor(Math.random() * 100)
        });
      });
    });
    
    res.json({ success: true, engagementData });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.get('/api/admin/analytics/active-inactive', authenticateAdmin, async (req, res) => {
  try {
    const now = new Date();
    const weekAgo = new Date(now);
    weekAgo.setDate(now.getDate() - 7);
    
    const activeUsers = await UserRoomVisit.distinct('userId', { lastVisited: { $gte: weekAgo } });
    const totalUsers = await User.countDocuments();
    const inactiveUsers = totalUsers - activeUsers.length;
    
    res.json({ 
      success: true, 
      activeUsers: activeUsers.length, 
      inactiveUsers 
    });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Detailed analytics endpoints
app.get('/api/admin/analytics/demographics', authenticateAdmin, async (req, res) => {
  try {
    const genderStats = await User.aggregate([
      { $match: { gender: { $in: ['male', 'female', 'other'] } } },
      { $group: { _id: '$gender', count: { $sum: 1 } } }
    ]);
    
    const ageStats = await User.aggregate([
      { $match: { age: { $exists: true, $ne: null } } },
      { $group: { _id: null, avg: { $avg: '$age' }, min: { $min: '$age' }, max: { $max: '$age' } } }
    ]);
    
    res.json({ 
      success: true, 
      genderStats,
      ageStats: ageStats[0] || { avg: 0, min: 0, max: 0 }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.get('/api/admin/analytics/message-patterns', authenticateAdmin, async (req, res) => {
  try {
    const { period = '7d' } = req.query;
    let startDate = new Date();
    if (period === '7d') startDate.setDate(startDate.getDate() - 7);
    else if (period === '30d') startDate.setDate(startDate.getDate() - 30);
    else if (period === '90d') startDate.setDate(startDate.getDate() - 90);
    
    const messagePatterns = await Message.aggregate([
      { $match: { timestamp: { $gte: startDate } } },
      { $group: { 
        _id: { 
          hour: { $hour: '$timestamp' },
          dayOfWeek: { $dayOfWeek: '$timestamp' }
        }, 
        count: { $sum: 1 } 
      }},
      { $sort: { '_id.dayOfWeek': 1, '_id.hour': 1 } }
    ]);
    
    res.json({ success: true, messagePatterns });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.get('/api/admin/analytics/room-activity', authenticateAdmin, async (req, res) => {
  try {
    const { period = '7d' } = req.query;
    let startDate = new Date();
    if (period === '7d') startDate.setDate(startDate.getDate() - 7);
    else if (period === '30d') startDate.setDate(startDate.getDate() - 30);
    else if (period === '90d') startDate.setDate(startDate.getDate() - 90);
    
    const roomActivity = await ChatRoom.aggregate([
      { $match: { createdAt: { $gte: startDate } } },
      { $group: { 
        _id: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } }, 
        count: { $sum: 1 } 
      }},
      { $sort: { _id: 1 } }
    ]);
    
    const topRooms = await Message.aggregate([
      { $match: { timestamp: { $gte: startDate } } },
      { $group: { _id: '$roomId', messageCount: { $sum: 1 } } },
      { $sort: { messageCount: -1 } },
      { $limit: 10 },
      { $lookup: { from: 'chatrooms', localField: '_id', foreignField: '_id', as: 'room' } },
      { $unwind: '$room' },
      { $project: { roomName: '$room.name', messageCount: 1 } }
    ]);
    
    res.json({ success: true, roomActivity, topRooms });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

app.get('/api/admin/analytics/user-engagement', authenticateAdmin, async (req, res) => {
  try {
    const { period = '7d' } = req.query;
    let startDate = new Date();
    if (period === '7d') startDate.setDate(startDate.getDate() - 7);
    else if (period === '30d') startDate.setDate(startDate.getDate() - 30);
    else if (period === '90d') startDate.setDate(startDate.getDate() - 90);
    
    const userEngagement = await Message.aggregate([
      { $match: { timestamp: { $gte: startDate } } },
      { $group: { _id: '$userId', messageCount: { $sum: 1 } } },
      { $sort: { messageCount: -1 } },
      { $limit: 20 },
      { $lookup: { from: 'users', localField: '_id', foreignField: '_id', as: 'user' } },
      { $unwind: '$user' },
      { $project: { username: '$user.username', messageCount: 1 } }
    ]);
    
    const avgMessagesPerUser = await Message.aggregate([
      { $match: { timestamp: { $gte: startDate } } },
      { $group: { _id: '$userId', messageCount: { $sum: 1 } } },
      { $group: { _id: null, avg: { $avg: '$messageCount' } } }
    ]);
    
    res.json({ 
      success: true, 
      userEngagement,
      avgMessagesPerUser: avgMessagesPerUser[0]?.avg || 0
    });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Server startup moved to end of file to ensure all routes are registered first

// --- USER NOTIFICATION ENDPOINTS ---

// Test route to verify server is working
app.get('/api/test', (req, res) => {
  console.log('Test route hit');
  res.json({ success: true, message: 'Server is working' });
});



// Temporary endpoint to check rooms (for debugging)
app.get('/api/debug/rooms', async (req, res) => {
  try {
    const rooms = await ChatRoom.find().populate('createdBy', 'username email');
    res.json({ 
      success: true, 
      count: rooms.length,
      rooms: rooms.map(room => ({
        id: room._id,
        name: room.name,
        type: room.type,
        isActive: room.isActive,
        createdBy: room.createdBy,
        createdAt: room.createdAt
      }))
    });
  } catch (error) {
    console.error('Debug rooms error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// --- Add cron job to auto-unban expired rooms ---
cron.schedule('*/5 * * * *', async () => {
  const now = new Date();
  await ChatRoom.updateMany(
    { isActive: false, banExpiresAt: { $ne: null, $lte: now } },
    { $set: { isActive: true, banReason: null, bannedBy: null, bannedAt: null, banExpiresAt: null } }
  );
});

// Room Report Schema
const roomReportSchema = new mongoose.Schema({
    roomId: {
        type: String,
        required: true
    },
    roomName: {
        type: String,
        required: true
    },
    reportedBy: {
        type: mongoose.Schema.Types.Mixed, // Allow both ObjectId and String
        required: true
    },
    reason: {
        type: String,
        enum: ['inappropriate', 'spam', 'harassment', 'violence', 'copyright', 'other'],
        required: true
    },
    description: {
        type: String,
        required: true
    },
    status: {
        type: String,
        enum: ['pending', 'resolved', 'dismissed'],
        default: 'pending'
    },
    resolvedBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Admin'
    },
    resolvedAt: Date,
    createdAt: {
        type: Date,
        default: Date.now
    }
});

const RoomReport = mongoose.model('RoomReport', roomReportSchema);

// Get reported rooms
app.get('/api/admin/reported-rooms', authenticateAdmin, async (req, res) => {
    try {
        const reports = await RoomReport.find()
            .sort({ createdAt: -1 });
        
        // Process reports to handle both ObjectId and String reportedBy
        const processedReports = reports.map(report => {
            const reportObj = report.toObject();
            
            // If reportedBy is an ObjectId, populate user info
            if (mongoose.Types.ObjectId.isValid(reportObj.reportedBy)) {
                // This would need to be populated separately if needed
                reportObj.reporterInfo = {
                    id: reportObj.reportedBy,
                    type: 'authenticated'
                };
            } else {
                // If reportedBy is a string (anonymous user)
                reportObj.reporterInfo = {
                    id: reportObj.reportedBy,
                    type: 'anonymous'
                };
            }
            
            return reportObj;
        });
        
        res.json({
            success: true,
            reports: processedReports
        });
    } catch (error) {
        console.error('Error fetching reported rooms:', error);
        res.status(500).json({
            success: false,
            message: 'Error fetching reported rooms'
        });
    }
});

// Resolve a report
app.put('/api/admin/reported-rooms/:reportId/resolve', authenticateAdmin, async (req, res) => {
    try {
        const { reportId } = req.params;
        const adminId = req.admin._id;
        
        const report = await RoomReport.findByIdAndUpdate(
            reportId,
            {
                status: 'resolved',
                resolvedBy: adminId,
                resolvedAt: new Date()
            },
            { new: true }
        );
        
        if (!report) {
            return res.status(404).json({
                success: false,
                message: 'Report not found'
            });
        }
        
        res.json({
            success: true,
            message: 'Report resolved successfully',
            report: report
        });
    } catch (error) {
        console.error('Error resolving report:', error);
        res.status(500).json({
            success: false,
            message: 'Error resolving report'
        });
    }
});

// Dismiss a report
app.put('/api/admin/reported-rooms/:reportId/dismiss', authenticateAdmin, async (req, res) => {
    try {
        const { reportId } = req.params;
        const adminId = req.admin._id;
        
        const report = await RoomReport.findByIdAndUpdate(
            reportId,
            {
                status: 'dismissed',
                resolvedBy: adminId,
                resolvedAt: new Date()
            },
            { new: true }
        );
        
        if (!report) {
            return res.status(404).json({
                success: false,
                message: 'Report not found'
            });
        }
        
        res.json({
            success: true,
            message: 'Report dismissed successfully',
            report: report
        });
    } catch (error) {
        console.error('Error dismissing report:', error);
        res.status(500).json({
            success: false,
            message: 'Error dismissing report'
        });
    }
});

// Report a room (for users)
app.post('/api/rooms/:roomId/report', async (req, res) => {
    try {
        console.log('Room report request received:', {
            roomId: req.params.roomId,
            body: req.body,
            cookies: req.cookies ? 'present' : 'none',
            headers: req.headers.authorization ? 'present' : 'none'
        });

        const { roomId } = req.params;
        const { reason, description } = req.body;
        
        // Try to get user from session first (authenticated users)
        let userId = null;
        let userType = 'anonymous';
        
        if (req.session && req.session.userId) {
            try {
                const user = await User.findById(req.session.userId);
                if (user) {
                    userId = user._id;
                    userType = 'authenticated';
                    console.log('Authenticated user found:', user.username || user.email);
                }
            } catch (error) {
                console.log('Session user lookup failed:', error.message);
            }
        }
        
        // If no authenticated user, use anonymous ID from request body
        if (!userId) {
            userId = req.body.anonymousId || 'anonymous-' + Math.random().toString(36).substr(2, 9);
            userType = 'anonymous';
            console.log('Using anonymous ID:', userId);
        }
        
        // Get room by _id (MongoDB ObjectId) instead of roomId field
        let room;
        if (mongoose.Types.ObjectId.isValid(roomId)) {
            room = await ChatRoom.findById(roomId);
        } else {
            // Fallback to roomId field if the provided ID is not a valid ObjectId
            room = await ChatRoom.findOne({ roomId: roomId });
        }
        
        if (!room) {
            console.log('Room not found:', roomId);
            return res.status(404).json({
                success: false,
                message: 'Room not found'
            });
        }
        
        console.log('Room found:', room.name);
        
        // Check if user already reported this room (only for authenticated users)
        if (userType === 'authenticated') {
            const existingReport = await RoomReport.findOne({
                roomId: roomId,
                reportedBy: userId,
                status: 'pending'
            });
            
            if (existingReport) {
                console.log('User already reported this room');
                return res.status(400).json({
                    success: false,
                    message: 'You have already reported this room'
                });
            }
        }
        
        const report = new RoomReport({
            roomId: roomId,
            roomName: room.name,
            reportedBy: userId,
            reason: reason,
            description: description
        });
        
        console.log('Saving report:', {
            roomId: report.roomId,
            roomName: report.roomName,
            reportedBy: report.reportedBy,
            reason: report.reason
        });
        
        await report.save();
        
        console.log('Report saved successfully');
        
        res.json({
            success: true,
            message: 'Room reported successfully',
            report: report
        });
    } catch (error) {
        console.error('Error reporting room:', error);
        res.status(500).json({
            success: false,
            message: 'Error reporting room'
        });
    }
});

// Get individual report details
app.get('/api/admin/reported-rooms/:reportId', authenticateAdmin, async (req, res) => {
    try {
        const { reportId } = req.params;
        
        const report = await RoomReport.findById(reportId)
            .populate('reportedBy', 'username email')
            .populate('resolvedBy', 'username');
        
        if (!report) {
            return res.status(404).json({
                success: false,
                message: 'Report not found'
            });
        }
        
        // Process the report data
        const reportObj = {
            _id: report._id,
            roomId: report.roomId,
            roomName: report.roomName,
            reportedBy: report.reportedBy,
            reason: report.reason,
            description: report.description,
            status: report.status,
            createdAt: report.createdAt,
            resolvedBy: report.resolvedBy,
            resolvedAt: report.resolvedAt
        };
        
        res.json({
            success: true,
            report: reportObj
        });
    } catch (error) {
        console.error('Error fetching report details:', error);
        res.status(500).json({
            success: false,
            message: 'Error fetching report details'
        });
    }
});

// Catch-all route for debugging (add this before server startup)
app.use('/api/*', (req, res) => {
  console.log('404 - Route not found:', req.method, req.url);
  res.status(404).json({ error: 'Route not found', method: req.method, url: req.url });
});

// Export for Vercel serverless deployment
module.exports = app;

// Lazy database initialization for serverless
let isDbConnected = false;
const initializeDatabase = async () => {
  if (!isDbConnected) {
    try {
      await mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/chat-app');
      console.log('MongoDB connected');
      
      // Create default admin account
      await createDefaultAdmin();
      
      isDbConnected = true;
    } catch (error) {
      console.error('Database connection error:', error);
      throw error;
    }
  }
};

// Add database initialization middleware
app.use(async (req, res, next) => {
  if (!isDbConnected) {
    try {
      await initializeDatabase();
    } catch (error) {
      return res.status(500).json({ error: 'Database connection failed' });
    }
  }
  next();
});

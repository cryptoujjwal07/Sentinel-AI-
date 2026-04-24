/**
 * Auth Controller
 * Handles user registration, login (local + Google), and profile operations
 */

const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { verifyGoogleToken } = require('../config/firebaseAdmin');

/**
 * Generate JWT token
 */
const generateToken = (userId) => {
  return jwt.sign({ id: userId }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || '7d',
  });
};

/**
 * Format user object for API response (consistent shape)
 */
const formatUserResponse = (user) => ({
  id: user._id,
  username: user.username,
  name: user.name,
  email: user.email,
  role: user.role,
  authType: user.authType,
  avatar: user.avatar,
  lastLogin: user.lastLogin,
});

/**
 * @route   POST /api/auth/register
 * @desc    Register a new local user
 * @access  Public
 */
const register = async (req, res) => {
  try {
    const { username, email, password, role } = req.body;

    // Validation is handled by express-validator middleware, but double-check
    if (!username || !email || !password) {
      return res.status(400).json({ success: false, message: 'All fields are required' });
    }

    // Check for existing user
    const existing = await User.findOne({ $or: [{ email }, { username }] });
    if (existing) {
      return res.status(409).json({
        success: false,
        message: 'User with this email or username already exists',
      });
    }

    const user = await User.create({
      username,
      email,
      password,
      authType: 'local',
      role: role || 'analyst',
    });

    const token = generateToken(user._id);

    res.status(201).json({
      success: true,
      message: 'Account created successfully',
      token,
      user: formatUserResponse(user),
    });
  } catch (error) {
    console.error('[AuthController] register error:', error.message);
    res.status(500).json({ success: false, message: error.message });
  }
};

/**
 * @route   POST /api/auth/login
 * @desc    Login with email and password (local auth)
 * @access  Public
 */
const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'Email and password are required' });
    }

    // Find user with password field included
    const user = await User.findOne({ email }).select('+password');
    if (!user) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    // Prevent local login for Google-only accounts
    if (user.authType === 'google') {
      return res.status(400).json({
        success: false,
        message: 'This account uses Google Sign-In. Please login with Google.',
      });
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    // Update last login
    user.lastLogin = new Date();
    await user.save({ validateBeforeSave: false });

    const token = generateToken(user._id);

    res.status(200).json({
      success: true,
      message: 'Login successful',
      token,
      user: formatUserResponse(user),
    });
  } catch (error) {
    console.error('[AuthController] login error:', error.message);
    res.status(500).json({ success: false, message: error.message });
  }
};

/**
 * @route   POST /api/auth/google
 * @desc    Login or register with Google (Firebase ID token)
 * @access  Public
 */
const googleLogin = async (req, res) => {
  try {
    const { idToken } = req.body;

    if (!idToken) {
      return res.status(400).json({ success: false, message: 'Google ID token is required' });
    }

    // Verify the Firebase ID token
    const decoded = await verifyGoogleToken(idToken);
    const { uid, email, name, picture } = decoded;

    if (!email) {
      return res.status(400).json({ success: false, message: 'Google account must have an email' });
    }

    // Check if user exists by email
    let user = await User.findOne({ email });

    if (user) {
      // User exists — check auth type
      if (user.authType === 'local') {
        return res.status(400).json({
          success: false,
          message: 'An account with this email already exists. Please login with your password.',
        });
      }

      // Existing Google user — update last login and avatar if changed
      user.lastLogin = new Date();
      if (picture && picture !== user.avatar) {
        user.avatar = picture;
      }
      if (name && name !== user.name) {
        user.name = name;
      }
      await user.save({ validateBeforeSave: false });
    } else {
      // New user — create account with Google auth
      // Generate a unique username from email prefix
      let baseUsername = email.split('@')[0].replace(/[^a-zA-Z0-9_]/g, '_');
      let username = baseUsername;
      let counter = 1;

      // Ensure unique username
      while (await User.findOne({ username })) {
        username = `${baseUsername}_${counter}`;
        counter++;
      }

      user = await User.create({
        username,
        name: name || username,
        email,
        googleId: uid,
        authType: 'google',
        avatar: picture || null,
        lastLogin: new Date(),
        role: 'analyst',
      });
    }

    const token = generateToken(user._id);

    res.status(200).json({
      success: true,
      message: user.createdAt === user.updatedAt ? 'Account created via Google' : 'Google login successful',
      token,
      user: formatUserResponse(user),
    });
  } catch (error) {
    console.error('[AuthController] googleLogin error:', error.message);

    // Specific error for invalid/expired tokens
    if (error.message.includes('Invalid or expired Google token')) {
      return res.status(401).json({ success: false, message: 'Google authentication failed. Please try again.' });
    }

    res.status(500).json({ success: false, message: 'Google login failed. Please try again.' });
  }
};

/**
 * @route   GET /api/auth/me
 * @desc    Get current user profile
 * @access  Private
 */
const getMe = async (req, res) => {
  res.status(200).json({
    success: true,
    user: formatUserResponse(req.user),
  });
};

/**
 * @route   PUT /api/auth/change-password
 * @desc    Change user password (local auth only)
 * @access  Private
 */
const changePassword = async (req, res) => {
  try {
    // Prevent password change for Google auth users
    if (req.user.authType === 'google') {
      return res.status(400).json({
        success: false,
        message: 'Cannot change password for Google-authenticated accounts.',
      });
    }

    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ success: false, message: 'Current and new passwords are required' });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({ success: false, message: 'New password must be at least 6 characters' });
    }

    const user = await User.findById(req.user._id).select('+password');
    const isMatch = await user.comparePassword(currentPassword);

    if (!isMatch) {
      return res.status(400).json({ success: false, message: 'Current password is incorrect' });
    }

    user.password = newPassword;
    await user.save();

    res.status(200).json({ success: true, message: 'Password changed successfully' });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

module.exports = { register, login, googleLogin, getMe, changePassword };

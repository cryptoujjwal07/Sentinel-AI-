const express = require('express');
const router = express.Router();
const { register, login, googleLogin, getMe, changePassword } = require('../controllers/authController');
const { protect } = require('../middleware/authMiddleware');
const { authRateLimiter } = require('../middleware/rateLimiter');
const { registerRules, loginRules, googleLoginRules, validate } = require('../middleware/validators');

// Public routes (with stricter rate limiting + input validation)
router.post('/register', authRateLimiter, registerRules, validate, register);
router.post('/login', authRateLimiter, loginRules, validate, login);
router.post('/google', authRateLimiter, googleLoginRules, validate, googleLogin);

// Protected routes
router.get('/me', protect, getMe);
router.put('/change-password', protect, changePassword);

module.exports = router;

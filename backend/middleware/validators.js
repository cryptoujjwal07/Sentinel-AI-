/**
 * Input Validation Middleware
 * Uses express-validator to sanitize and validate request data
 * Prevents injection attacks and ensures data integrity
 */

const { body, validationResult } = require('express-validator');

/**
 * Generic validation result checker middleware
 * Place after validation chains to catch and return errors
 */
const validate = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors: errors.array().map((e) => ({ field: e.path, message: e.msg })),
    });
  }
  next();
};

// ── Registration validation rules ─────────────────────────────────────────────
const registerRules = [
  body('username')
    .trim()
    .notEmpty().withMessage('Username is required')
    .isLength({ min: 3, max: 30 }).withMessage('Username must be 3-30 characters')
    .matches(/^[a-zA-Z0-9_]+$/).withMessage('Username can only contain letters, numbers, and underscores')
    .escape(),
  body('email')
    .trim()
    .notEmpty().withMessage('Email is required')
    .isEmail().withMessage('Please enter a valid email')
    .normalizeEmail(),
  body('password')
    .notEmpty().withMessage('Password is required')
    .isLength({ min: 6 }).withMessage('Password must be at least 6 characters')
    .matches(/^(?=.*[a-zA-Z])(?=.*\d)/).withMessage('Password must contain at least one letter and one number'),
];

// ── Login validation rules ────────────────────────────────────────────────────
const loginRules = [
  body('email')
    .trim()
    .notEmpty().withMessage('Email is required')
    .isEmail().withMessage('Please enter a valid email')
    .normalizeEmail(),
  body('password')
    .notEmpty().withMessage('Password is required'),
];

// ── Google login validation rules ─────────────────────────────────────────────
const googleLoginRules = [
  body('idToken')
    .notEmpty().withMessage('Google ID token is required')
    .isString().withMessage('Invalid token format'),
];

module.exports = {
  validate,
  registerRules,
  loginRules,
  googleLoginRules,
};

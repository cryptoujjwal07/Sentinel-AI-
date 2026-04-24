/**
 * Rate Limiter Middleware
 * Prevents abuse and brute-force attacks using express-rate-limit
 */

const rateLimit = require('express-rate-limit');
const Alert = require('../models/Alert');

const rateLimiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,
  standardHeaders: true,  // Return rate limit info in `RateLimit-*` headers
  legacyHeaders: false,
  message: {
    success: false,
    error: 'RATE_LIMITED',
    message: '⚠️ Too many requests from this IP. Please wait and try again.',
  },
  handler: async (req, res, next, options) => {
    const ip =
      req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
      req.ip ||
      '0.0.0.0';

    // Create a rate-limit alert
    Alert.create({
      title: `Rate Limit Exceeded: ${ip}`,
      description: `IP ${ip} exceeded ${options.max} requests in ${options.windowMs / 60000} minutes.`,
      severity: 'MEDIUM',
      type: 'RATE_LIMIT_EXCEEDED',
      ipAddress: ip,
      attackType: 'RATE_LIMIT',
    }).catch(() => {});

    console.warn(`⚠️   [RateLimiter] IP: ${ip} exceeded rate limit`);

    res.status(options.statusCode).json(options.message);
  },
  skip: (req) => {
    // Skip rate limiting for health check, auth, and internal dashboard API routes
    // Dashboard routes are already auth-protected and poll frequently
    if (req.path === '/health') return true;
    if (req.path.startsWith('/api/auth')) return true;
    if (req.path.startsWith('/api/stats')) return true;
    if (req.path.startsWith('/api/logs')) return true;
    if (req.path.startsWith('/api/ip')) return true;
    if (req.path.startsWith('/api/scanner')) return true;
    if (req.path.startsWith('/api/profiles')) return true;
    return false;
  },
});

// Stricter limiter for auth endpoints
const authRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30, // 30 login attempts per 15 minutes
  message: {
    success: false,
    error: 'AUTH_RATE_LIMITED',
    message: '🔐 Too many login attempts. Please wait 15 minutes.',
  },
});

module.exports = rateLimiter;
module.exports.authRateLimiter = authRateLimiter;

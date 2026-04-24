/**
 * SentinelAI - AI-Powered Web Application Firewall
 * Main server entry point
 */

require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const morgan = require('morgan');

const connectDB = require('./config/db');
const rateLimiter = require('./middleware/rateLimiter');
const wafMiddleware = require('./middleware/wafMiddleware');

// Route imports
const authRoutes = require('./routes/authRoutes');
const logRoutes = require('./routes/logRoutes');
const statsRoutes = require('./routes/statsRoutes');
const ipRoutes = require('./routes/ipRoutes');
const scannerRoutes = require('./routes/scannerRoutes');
const profileRoutes = require('./routes/profileRoutes');
const threatDetectorRoutes = require('./routes/threatDetectorRoutes');
const riskScoreRoutes = require('./routes/riskScoreRoutes');

const app = express();
const PORT = process.env.PORT || 5000;

// ─── Connect to MongoDB ────────────────────────────────────────────────────────
connectDB();

// ─── Security Headers (Helmet) ────────────────────────────────────────────────
app.use(helmet({
  crossOriginResourcePolicy: { policy: 'cross-origin' },
}));

// ─── CORS Configuration ───────────────────────────────────────────────────────
const allowedOrigins = (process.env.FRONTEND_URL || 'http://localhost:5173')
  .split(',')
  .map((origin) => origin.trim());

app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (mobile apps, Postman, server-to-server)
    if (!origin) return callback(null, true);
    // In development, allow any localhost port (Vite may pick 5173, 5174, 5176, etc.)
    if (process.env.NODE_ENV === 'development' && /^http:\/\/localhost:\d+$/.test(origin)) {
      return callback(null, true);
    }
    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    callback(new Error(`CORS policy: Origin ${origin} not allowed`));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

// ─── Body Parsers ─────────────────────────────────────────────────────────────
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ─── HTTP Request Logger ──────────────────────────────────────────────────────
if (process.env.NODE_ENV === 'development') {
  app.use(morgan('dev'));
}

// ─── Global Rate Limiter ──────────────────────────────────────────────────────
app.use(rateLimiter);

// ─── WAF Middleware (AI Threat Detection) ─────────────────────────────────
// Internal dashboard APIs (/api/*) are already auth-protected.
// WAF is applied to non-API routes to detect attacks on the main application.
// Scanner is excluded because it intentionally sends attack payloads for analysis.
// To add WAF protection to specific external routes, apply wafMiddleware selectively.

// ─── Root Route ───────────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  res.status(200).json({
    success: true,
    message: '🛡️ SentinelAI WAF API is live',
    version: '1.0.0',
    endpoints: {
      health: '/health',
      auth: '/api/auth',
      logs: '/api/logs',
      stats: '/api/stats',
      ip: '/api/ip',
      scanner: '/api/scanner',
      profiles: '/api/profiles',
      threatDetector: '/api/threat-detector',
      riskScore: '/api/risk-score',
    },
  });
});

// ─── Health Check ─────────────────────────────────────────────────────────────
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'OK',
    message: 'SentinelAI WAF is running',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
  });
});

// ─── API Routes ───────────────────────────────────────────────────────────────
app.use('/api/auth', authRoutes);
app.use('/api/logs', logRoutes);
app.use('/api/stats', statsRoutes);
app.use('/api/ip', ipRoutes);
app.use('/api/scanner', scannerRoutes);
app.use('/api/profiles', profileRoutes);
app.use('/api/threat-detector', threatDetectorRoutes);
app.use('/api/risk-score', riskScoreRoutes);

// ─── 404 Handler ──────────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: `Route ${req.originalUrl} not found`,
  });
});

// ─── Global Error Handler ─────────────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error('[ERROR]', err.stack);
  res.status(err.status || 500).json({
    success: false,
    message: err.message || 'Internal Server Error',
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack }),
  });
});

// ─── Start Server (only when run directly, not when imported for testing) ─────
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`\n🛡️  SentinelAI WAF Server`);
    console.log(`📡  Running on: http://localhost:${PORT}`);
    console.log(`🌍  Environment: ${process.env.NODE_ENV}`);
    console.log(`⏱️   Started at: ${new Date().toLocaleString()}\n`);
  });
}

module.exports = app;

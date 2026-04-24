/**
 * Log Model
 * Stores all intercepted HTTP requests with AI threat classification
 */

const mongoose = require('mongoose');

const logSchema = new mongoose.Schema(
  {
    // ── Request Info ──────────────────────────────────────────────────────────
    requestId: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },
    method: {
      type: String,
      enum: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'],
      required: true,
    },
    path: {
      type: String,
      required: true,
    },
    fullUrl: {
      type: String,
    },
    ipAddress: {
      type: String,
      required: true,
      index: true,
    },
    userAgent: {
      type: String,
      default: 'Unknown',
    },
    headers: {
      type: mongoose.Schema.Types.Mixed,
      default: {},
    },
    queryParams: {
      type: mongoose.Schema.Types.Mixed,
      default: {},
    },
    requestBody: {
      type: mongoose.Schema.Types.Mixed,
      default: {},
    },

    // ── AI Analysis ───────────────────────────────────────────────────────────
    classification: {
      type: String,
      enum: ['SAFE', 'SUSPICIOUS', 'MALICIOUS', 'ERROR', 'BYPASSED'],
      required: true,
      index: true,
    },
    confidence: {
      type: Number,
      min: 0,
      max: 100,
      default: 0,
    },
    attackType: {
      type: String,
      enum: [
        'SQL_INJECTION',
        'XSS',
        'CSRF',
        'PATH_TRAVERSAL',
        'COMMAND_INJECTION',
        'RATE_LIMIT',
        'BRUTE_FORCE',
        'SUSPICIOUS_HEADERS',
        'MALFORMED_REQUEST',
        'ENCODED_ATTACK',
        'NONE',
        'UNKNOWN',
      ],
      default: 'NONE',
    },
    aiReason: {
      type: String,
      default: '',
    },

    // ── Response Info ─────────────────────────────────────────────────────────
    statusCode: {
      type: Number,
      default: null,
    },
    responseTime: {
      type: Number, // milliseconds
      default: null,
    },

    // ── Action Taken ──────────────────────────────────────────────────────────
    action: {
      type: String,
      enum: ['ALLOWED', 'BLOCKED', 'FLAGGED', 'RATE_LIMITED'],
      default: 'ALLOWED',
    },
    blocked: {
      type: Boolean,
      default: false,
    },

    // ── Geo / Context ─────────────────────────────────────────────────────────
    country: {
      type: String,
      default: 'Unknown',
    },
    isBot: {
      type: Boolean,
      default: false,
    },
  },
  {
    timestamps: true,
  }
);

// Compound index for efficient querying
logSchema.index({ createdAt: -1, classification: 1 });
logSchema.index({ ipAddress: 1, createdAt: -1 });
logSchema.index({ attackType: 1, createdAt: -1 });

module.exports = mongoose.model('Log', logSchema);

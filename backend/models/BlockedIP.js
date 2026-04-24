/**
 * BlockedIP Model  
 * Tracks all IP addresses that have been blocked by the WAF
 */

const mongoose = require('mongoose');

const blockedIPSchema = new mongoose.Schema(
  {
    ipAddress: {
      type: String,
      required: [true, 'IP address is required'],
      unique: true,
      index: true,
    },
    reason: {
      type: String,
      required: true,
      default: 'Exceeded malicious request threshold',
    },
    attackTypes: [
      {
        type: String,
        enum: [
          'SQL_INJECTION', 'XSS', 'CSRF', 'PATH_TRAVERSAL',
          'COMMAND_INJECTION', 'RATE_LIMIT', 'BRUTE_FORCE',
          'SUSPICIOUS_HEADERS', 'MALFORMED_REQUEST', 'UNKNOWN',
        ],
      },
    ],
    maliciousCount: {
      type: Number,
      default: 1,
    },
    isActive: {
      type: Boolean,
      default: true,
      index: true,
    },
    blockedBy: {
      type: String,
      enum: ['AI', 'MANUAL', 'RATE_LIMIT', 'SYSTEM'],
      default: 'AI',
    },
    blockedAt: {
      type: Date,
      default: Date.now,
    },
    unblockedAt: {
      type: Date,
      default: null,
    },
    unblockedBy: {
      type: String,
      default: null,
    },
    expiresAt: {
      type: Date,
      default: null, // null = permanent block
    },
    notes: {
      type: String,
      default: '',
    },
    userAgent: {
      type: String,
      default: 'Unknown',
    },
    country: {
      type: String,
      default: 'Unknown',
    },
  },
  {
    timestamps: true,
  }
);

// Auto-expire blocks using MongoDB TTL (if expiresAt is set)
blockedIPSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0, sparse: true });

module.exports = mongoose.model('BlockedIP', blockedIPSchema);

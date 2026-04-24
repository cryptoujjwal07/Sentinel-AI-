/**
 * AttackerProfile Model
 * Tracks behavioral patterns of each IP address over time
 * Used for rule-based attacker profiling and risk scoring
 */

const mongoose = require('mongoose');

const attackerProfileSchema = new mongoose.Schema(
  {
    // ── Identity ────────────────────────────────────────────────────────────
    ip: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },

    // ── Request Counts ──────────────────────────────────────────────────────
    totalRequests: {
      type: Number,
      default: 0,
    },
    suspiciousRequests: {
      type: Number,
      default: 0,
    },
    maliciousRequests: {
      type: Number,
      default: 0,
    },
    safeRequests: {
      type: Number,
      default: 0,
    },

    // ── Attack Breakdown ────────────────────────────────────────────────────
    // Stores each attack type with its count, e.g. { "SQL_INJECTION": 5, "XSS": 2 }
    attackTypes: {
      type: Map,
      of: Number,
      default: {},
    },

    // ── Endpoint Tracking ───────────────────────────────────────────────────
    // Unique endpoints this IP has hit (capped to last 50)
    endpoints: {
      type: [String],
      default: [],
    },

    // ── Payload Tracking ────────────────────────────────────────────────────
    // Stores hashes of payloads to detect repetition
    payloadHashes: {
      type: [String],
      default: [],
    },
    repeatedPayloadCount: {
      type: Number,
      default: 0,
    },

    // ── Timing ──────────────────────────────────────────────────────────────
    firstSeen: {
      type: Date,
      default: Date.now,
    },
    lastSeen: {
      type: Date,
      default: Date.now,
    },

    // ── Frequency ───────────────────────────────────────────────────────────
    // Calculated requests per minute since firstSeen
    requestFrequency: {
      type: Number,
      default: 0,
    },

    // ── Profiling ───────────────────────────────────────────────────────────
    profileType: {
      type: String,
      enum: ['normal', 'scanner', 'repetitive attacker', 'aggressive attacker', 'suspicious bot'],
      default: 'normal',
    },
    riskScore: {
      type: Number,
      default: 0,
      min: 0,
      max: 100,
    },

    // ── Context ─────────────────────────────────────────────────────────────
    userAgent: {
      type: String,
      default: 'Unknown',
    },
    isBlocked: {
      type: Boolean,
      default: false,
    },
  },
  {
    timestamps: true,
  }
);

// Compound indexes for efficient dashboard queries
attackerProfileSchema.index({ riskScore: -1 });
attackerProfileSchema.index({ profileType: 1, riskScore: -1 });
attackerProfileSchema.index({ lastSeen: -1 });

module.exports = mongoose.model('AttackerProfile', attackerProfileSchema);

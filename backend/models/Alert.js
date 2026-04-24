/**
 * Alert Model
 * High-severity events that require immediate attention
 */

const mongoose = require('mongoose');

const alertSchema = new mongoose.Schema(
  {
    title: {
      type: String,
      required: true,
    },
    description: {
      type: String,
      required: true,
    },
    severity: {
      type: String,
      enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
      required: true,
      index: true,
    },
    type: {
      type: String,
      enum: [
        'IP_BLOCKED',
        'ATTACK_DETECTED',
        'RATE_LIMIT_EXCEEDED',
        'ANOMALY_DETECTED',
        'SYSTEM_WARNING',
        'BRUTE_FORCE',
      ],
      required: true,
    },
    ipAddress: {
      type: String,
      default: null,
      index: true,
    },
    attackType: {
      type: String,
      default: 'UNKNOWN',
    },
    relatedLogId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Log',
      default: null,
    },
    isRead: {
      type: Boolean,
      default: false,
      index: true,
    },
    isResolved: {
      type: Boolean,
      default: false,
    },
    resolvedAt: {
      type: Date,
      default: null,
    },
    resolvedBy: {
      type: String,
      default: null,
    },
    metadata: {
      type: mongoose.Schema.Types.Mixed,
      default: {},
    },
  },
  {
    timestamps: true,
  }
);

// Index for unread critical alerts
alertSchema.index({ isRead: 1, severity: 1, createdAt: -1 });

module.exports = mongoose.model('Alert', alertSchema);

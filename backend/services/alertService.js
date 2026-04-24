/**
 * Alert Service
 * Creates and manages security alerts for high-severity events
 */

const Alert = require('../models/Alert');

/**
 * Create a new alert
 */
const createAlert = async ({ title, description, severity, type, ipAddress, attackType, relatedLogId, metadata }) => {
  try {
    const alert = await Alert.create({
      title,
      description,
      severity,
      type,
      ipAddress,
      attackType,
      relatedLogId,
      metadata,
    });
    return alert;
  } catch (error) {
    console.error('[AlertService] createAlert error:', error.message);
  }
};

/**
 * Get unread alerts count
 */
const getUnreadCount = async () => {
  return await Alert.countDocuments({ isRead: false });
};

/**
 * Mark alerts as read
 */
const markAsRead = async (alertIds) => {
  return await Alert.updateMany(
    { _id: { $in: alertIds } },
    { isRead: true }
  );
};

/**
 * Create an attack-detected alert based on classification
 */
const createAttackAlert = async (classification, attackType, ipAddress, logId) => {
  if (classification === 'MALICIOUS') {
    await createAlert({
      title: `${attackType.replace(/_/g, ' ')} Attack Detected`,
      description: `A ${attackType.replace(/_/g, ' ')} attack was detected from IP ${ipAddress} and blocked.`,
      severity: 'HIGH',
      type: 'ATTACK_DETECTED',
      ipAddress,
      attackType,
      relatedLogId: logId,
    });
  } else if (classification === 'SUSPICIOUS') {
    await createAlert({
      title: `Suspicious Activity from ${ipAddress}`,
      description: `Suspicious request pattern detected. Possible ${attackType.replace(/_/g, ' ')}.`,
      severity: 'MEDIUM',
      type: 'ANOMALY_DETECTED',
      ipAddress,
      attackType,
      relatedLogId: logId,
    });
  }
};

module.exports = { createAlert, getUnreadCount, markAsRead, createAttackAlert };

/**
 * IP Block Service
 * Tracks malicious request counts per IP and auto-blocks after threshold
 * Uses in-memory cache + MongoDB persistence for speed
 */

const BlockedIP = require('../models/BlockedIP');
const Alert = require('../models/Alert');

// In-memory tracker: { ip: { count, attackTypes: Set, firstSeen, lastSeen } }
const ipTracker = new Map();

const BLOCK_THRESHOLD = parseInt(process.env.MALICIOUS_THRESHOLD) || 3;

/**
 * Check if an IP is currently blocked (fast in-memory + DB fallback)
 * @param {string} ip
 * @returns {Object|null} Block record or null if not blocked
 */
const isIPBlocked = async (ip) => {
  try {
    const blocked = await BlockedIP.findOne({ ipAddress: ip, isActive: true });
    return blocked || null;
  } catch (error) {
    console.error('[IPBlockService] isIPBlocked error:', error.message);
    return null;
  }
};

/**
 * Record a malicious request from an IP and block if threshold exceeded
 * @param {string} ip
 * @param {string} attackType
 * @param {string} userAgent
 * @returns {boolean} true if IP was newly blocked
 */
const recordMaliciousRequest = async (ip, attackType = 'UNKNOWN', userAgent = '') => {
  // Update in-memory tracker
  if (!ipTracker.has(ip)) {
    ipTracker.set(ip, {
      count: 0,
      attackTypes: new Set(),
      firstSeen: new Date(),
      lastSeen: new Date(),
    });
  }

  const tracker = ipTracker.get(ip);
  tracker.count += 1;
  tracker.attackTypes.add(attackType);
  tracker.lastSeen = new Date();

  // Check if threshold is reached
  if (tracker.count >= BLOCK_THRESHOLD) {
    // Avoid blocking twice
    const alreadyBlocked = await isIPBlocked(ip);
    if (!alreadyBlocked) {
      await blockIP(
        ip,
        `Exceeded malicious request threshold (${tracker.count} attacks detected)`,
        [...tracker.attackTypes],
        'AI',
        userAgent
      );
      ipTracker.delete(ip); // Reset tracker after blocking
      return true; // Newly blocked
    }
  }

  return false;
};

/**
 * Block an IP address
 * @param {string} ip
 * @param {string} reason
 * @param {string[]} attackTypes
 * @param {string} blockedBy - 'AI' | 'MANUAL' | 'RATE_LIMIT'
 * @param {string} userAgent
 */
const blockIP = async (ip, reason, attackTypes = [], blockedBy = 'AI', userAgent = '') => {
  try {
    await BlockedIP.findOneAndUpdate(
      { ipAddress: ip },
      {
        ipAddress: ip,
        reason,
        attackTypes,
        blockedBy,
        isActive: true,
        blockedAt: new Date(),
        unblockedAt: null,
        userAgent,
        maliciousCount: ipTracker.get(ip)?.count || 1,
      },
      { upsert: true, new: true }
    );

    // Create a critical alert
    await Alert.create({
      title: `IP Blocked: ${ip}`,
      description: `${reason}. Attack types: ${attackTypes.join(', ')}`,
      severity: 'CRITICAL',
      type: 'IP_BLOCKED',
      ipAddress: ip,
      attackType: attackTypes[0] || 'UNKNOWN',
      metadata: { blockedBy, attackTypes, userAgent },
    });

    console.log(`🚫  [IPBlockService] Blocked IP: ${ip} | Reason: ${reason}`);
  } catch (error) {
    console.error('[IPBlockService] blockIP error:', error.message);
  }
};

/**
 * Unblock an IP address
 * @param {string} ip
 * @param {string} unblockedBy - Username who unblocked
 */
const unblockIP = async (ip, unblockedBy = 'system') => {
  try {
    const result = await BlockedIP.findOneAndUpdate(
      { ipAddress: ip, isActive: true },
      {
        isActive: false,
        unblockedAt: new Date(),
        unblockedBy,
      },
      { new: true }
    );

    // Clear from in-memory tracker too
    ipTracker.delete(ip);

    return result;
  } catch (error) {
    console.error('[IPBlockService] unblockIP error:', error.message);
    throw error;
  }
};

/**
 * Get current malicious request count for an IP (from memory)
 */
const getIPStats = (ip) => {
  return ipTracker.get(ip) || { count: 0, attackTypes: new Set(), firstSeen: null };
};

/**
 * Get all blocked IPs from DB
 */
const getAllBlockedIPs = async (activeOnly = true) => {
  const filter = activeOnly ? { isActive: true } : {};
  return await BlockedIP.find(filter).sort({ blockedAt: -1 });
};

module.exports = {
  isIPBlocked,
  recordMaliciousRequest,
  blockIP,
  unblockIP,
  getIPStats,
  getAllBlockedIPs,
};

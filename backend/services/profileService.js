/**
 * Profile Service
 * Rule-based attacker behavior profiling engine
 * Updates attacker profiles after each request, calculates risk scores,
 * and classifies attacker behavior patterns
 */

const crypto = require('crypto');
const AttackerProfile = require('../models/AttackerProfile');

// ── Constants ─────────────────────────────────────────────────────────────────
const MAX_ENDPOINTS = 50;       // Cap stored endpoints per profile
const MAX_PAYLOAD_HASHES = 100; // Cap stored payload hashes
const REPEATED_PAYLOAD_THRESHOLD = 5;  // Times a payload must repeat to flag
const SCANNER_ENDPOINT_THRESHOLD = 5;  // Min unique endpoints to flag as scanner
const SCANNER_TIME_WINDOW_MS = 5 * 60 * 1000; // 5 minutes
const AGGRESSIVE_REQUEST_THRESHOLD = 10;
const AGGRESSIVE_RISK_THRESHOLD = 70;
const BOT_FREQUENCY_THRESHOLD = 60;    // Requests per minute

/**
 * Generate a simple hash of a payload for repetition tracking
 * @param {*} payload - Request body or query params
 * @returns {string} Hash string
 */
const hashPayload = (payload) => {
  if (!payload || (typeof payload === 'object' && Object.keys(payload).length === 0)) {
    return null;
  }
  const data = typeof payload === 'string' ? payload : JSON.stringify(payload);
  return crypto.createHash('md5').update(data).digest('hex');
};

/**
 * Calculate requests per minute based on time window
 * @param {number} totalRequests
 * @param {Date} firstSeen
 * @returns {number} Requests per minute (rounded to 2 decimals)
 */
const calcFrequency = (totalRequests, firstSeen) => {
  const elapsedMs = Date.now() - new Date(firstSeen).getTime();
  const elapsedMinutes = elapsedMs / 60000;
  if (elapsedMinutes < 0.1) return totalRequests; // Avoid division by near-zero
  return Math.round((totalRequests / elapsedMinutes) * 100) / 100;
};

/**
 * Calculate a behavior risk score (0–100) based on profile data
 * Simple additive point system
 * @param {Object} profile - The attacker profile document
 * @returns {number} Risk score capped at 100
 */
const calculateRiskScore = (profile) => {
  let score = 0;

  // +10 per suspicious request
  score += profile.suspiciousRequests * 10;

  // +25 per malicious request
  score += profile.maliciousRequests * 25;

  // +15 per repeated payload (after threshold)
  if (profile.repeatedPayloadCount > 3) {
    score += (profile.repeatedPayloadCount - 3) * 15;
  }

  // +20 per unique attack type (beyond the first)
  const attackTypeCount = profile.attackTypes instanceof Map
    ? profile.attackTypes.size
    : Object.keys(profile.attackTypes || {}).length;
  if (attackTypeCount > 1) {
    score += (attackTypeCount - 1) * 20;
  }

  // +30 if frequency > 60 req/min
  if (profile.requestFrequency > BOT_FREQUENCY_THRESHOLD) {
    score += 30;
  }

  // +50 if frequency > 120 req/min (extremely fast)
  if (profile.requestFrequency > 120) {
    score += 50;
  }

  // +10 if blocked
  if (profile.isBlocked) {
    score += 10;
  }

  // Cap at 100
  return Math.min(100, Math.max(0, score));
};

/**
 * Classify the attacker profile type based on behavior rules
 * @param {Object} profile - The attacker profile document
 * @returns {string} Profile type
 */
const classifyProfile = (profile) => {
  const suspiciousPlusMalicious = profile.suspiciousRequests + profile.maliciousRequests;
  const elapsedMs = Date.now() - new Date(profile.firstSeen).getTime();
  const uniqueEndpoints = profile.endpoints?.length || 0;

  // "suspicious bot" → very fast repeated requests (> 60/min)
  if (profile.requestFrequency > BOT_FREQUENCY_THRESHOLD) {
    return 'suspicious bot';
  }

  // "scanner" → many unique endpoints hit in a short time window
  if (uniqueEndpoints >= SCANNER_ENDPOINT_THRESHOLD && elapsedMs <= SCANNER_TIME_WINDOW_MS) {
    return 'scanner';
  }

  // "repetitive attacker" → same payload repeated many times
  if (profile.repeatedPayloadCount >= REPEATED_PAYLOAD_THRESHOLD) {
    return 'repetitive attacker';
  }

  // "aggressive attacker" → high suspicious/malicious count OR high risk
  if (suspiciousPlusMalicious >= AGGRESSIVE_REQUEST_THRESHOLD || profile.riskScore >= AGGRESSIVE_RISK_THRESHOLD) {
    return 'aggressive attacker';
  }

  // Default
  return 'normal';
};

/**
 * Update (or create) the attacker profile for a given IP after a request
 * This is the main entry point called from the WAF middleware
 *
 * @param {Object} logData - Data from the processed request
 * @param {string} logData.ipAddress - Client IP
 * @param {string} logData.classification - SAFE | SUSPICIOUS | MALICIOUS | ERROR
 * @param {string} logData.attackType - Detected attack type
 * @param {string} logData.path - Request endpoint path
 * @param {Object} logData.requestBody - Request body
 * @param {Object} logData.queryParams - Query parameters
 * @param {string} logData.userAgent - User agent string
 * @param {boolean} logData.blocked - Whether the request was blocked
 */
const updateProfile = async (logData) => {
  try {
    const {
      ipAddress,
      classification,
      attackType,
      path,
      requestBody,
      queryParams,
      userAgent,
      blocked,
    } = logData;

    if (!ipAddress) return;

    // ── Find or create the profile ───────────────────────────────────────
    let profile = await AttackerProfile.findOne({ ip: ipAddress });

    if (!profile) {
      profile = new AttackerProfile({
        ip: ipAddress,
        firstSeen: new Date(),
        lastSeen: new Date(),
        userAgent: userAgent || 'Unknown',
      });
    }

    // ── Increment request counts ─────────────────────────────────────────
    profile.totalRequests += 1;
    profile.lastSeen = new Date();

    if (classification === 'SUSPICIOUS') {
      profile.suspiciousRequests += 1;
    } else if (classification === 'MALICIOUS') {
      profile.maliciousRequests += 1;
    } else if (classification === 'SAFE') {
      profile.safeRequests += 1;
    }

    // ── Track attack types ───────────────────────────────────────────────
    if (attackType && attackType !== 'NONE' && attackType !== 'UNKNOWN') {
      const currentCount = profile.attackTypes.get(attackType) || 0;
      profile.attackTypes.set(attackType, currentCount + 1);
    }

    // ── Track endpoints (capped) ─────────────────────────────────────────
    if (path && !profile.endpoints.includes(path)) {
      if (profile.endpoints.length >= MAX_ENDPOINTS) {
        profile.endpoints.shift(); // Remove oldest
      }
      profile.endpoints.push(path);
    }

    // ── Track payload repetition ─────────────────────────────────────────
    const payloadHash = hashPayload(requestBody) || hashPayload(queryParams);
    if (payloadHash) {
      const existingCount = profile.payloadHashes.filter(h => h === payloadHash).length;
      if (existingCount > 0) {
        profile.repeatedPayloadCount += 1;
      }
      if (profile.payloadHashes.length >= MAX_PAYLOAD_HASHES) {
        profile.payloadHashes.shift(); // Remove oldest
      }
      profile.payloadHashes.push(payloadHash);
    }

    // ── Update context ───────────────────────────────────────────────────
    if (userAgent && userAgent !== 'Unknown') {
      profile.userAgent = userAgent;
    }
    if (blocked) {
      profile.isBlocked = true;
    }

    // ── Calculate frequency ──────────────────────────────────────────────
    profile.requestFrequency = calcFrequency(profile.totalRequests, profile.firstSeen);

    // ── Calculate risk score ─────────────────────────────────────────────
    profile.riskScore = calculateRiskScore(profile);

    // ── Classify profile type ────────────────────────────────────────────
    profile.profileType = classifyProfile(profile);

    // ── Save ─────────────────────────────────────────────────────────────
    await profile.save();

    return profile;
  } catch (error) {
    console.error('[ProfileService] updateProfile error:', error.message);
  }
};

module.exports = {
  updateProfile,
  calculateRiskScore,
  classifyProfile,
  hashPayload,
};

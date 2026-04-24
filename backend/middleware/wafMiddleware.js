/**
 * WAF Middleware — Core Threat Detection Engine
 * Intercepts ALL HTTP requests, extracts data, runs the ThreatDetector
 * (fast, deterministic pre-filter), then optionally sends to Gemini AI,
 * and blocks malicious requests before they reach route handlers.
 */

const { v4: uuidv4 } = require('uuid');
const { analyzeRequest } = require('../services/geminiService');
const { isIPBlocked, recordMaliciousRequest } = require('../services/ipBlockService');
const { createAttackAlert } = require('../services/alertService');
const { updateProfile } = require('../services/profileService');
const threatDetector = require('../services/threatDetector');
const Log = require('../models/Log');

const getClientIP = require('../utils/getClientIP');

/**
 * Sanitizes headers by removing sensitive values before logging
 */
const sanitizeHeaders = (headers) => {
  const sensitive = ['authorization', 'cookie', 'x-api-key'];
  const sanitized = { ...headers };
  sensitive.forEach((key) => {
    if (sanitized[key]) sanitized[key] = '[REDACTED]';
  });
  return sanitized;
};

/**
 * Checks if User-Agent looks like an automated scanner/bot
 */
const isBot = (userAgent = '') => {
  const botSignatures = [
    'sqlmap', 'nikto', 'nmap', 'masscan', 'zgrab', 'nuclei',
    'dirbuster', 'gobuster', 'wfuzz', 'burpsuite', 'acunetix',
    'nessus', 'openvas', 'python-requests', 'curl/', 'wget/',
  ];
  const ua = userAgent.toLowerCase();
  return botSignatures.some((sig) => ua.includes(sig));
};

/**
 * Builds a combined payload string from all user-controlled request fields.
 * Used as input for the ThreatDetector pre-filter.
 */
const buildCombinedPayload = (req) => {
  const parts = [];

  // URL path + query string
  if (req.originalUrl) parts.push(req.originalUrl);

  // Query params as string
  if (req.query && Object.keys(req.query).length > 0) {
    parts.push(JSON.stringify(req.query));
  }

  // Body
  if (req.body && Object.keys(req.body).length > 0) {
    parts.push(typeof req.body === 'string' ? req.body : JSON.stringify(req.body));
  }

  return parts.join(' ');
};

/**
 * Main WAF Middleware
 */
const wafMiddleware = async (req, res, next) => {
  const startTime = Date.now();
  const requestId = uuidv4();
  const ip = getClientIP(req);
  const userAgent = req.headers['user-agent'] || 'Unknown';

  // ── Fast Path: Check if IP is already blocked ─────────────────────────────
  const blockRecord = await isIPBlocked(ip);
  if (blockRecord) {
    const logEntry = {
      requestId,
      method: req.method,
      path: req.path,
      fullUrl: `${req.protocol}://${req.get('host')}${req.originalUrl}`,
      ipAddress: ip,
      userAgent,
      headers: sanitizeHeaders(req.headers),
      queryParams: req.query,
      requestBody: req.body,
      classification: 'MALICIOUS',
      confidence: 100,
      attackType: blockRecord.attackTypes?.[0] || 'UNKNOWN',
      aiReason: `IP is on block list: ${blockRecord.reason}`,
      action: 'BLOCKED',
      blocked: true,
      statusCode: 403,
      responseTime: Date.now() - startTime,
      isBot: isBot(userAgent),
    };

    // Save log asynchronously (don't await to keep response fast)
    Log.create(logEntry).catch((e) => console.error('[WAF] Log save error:', e.message));

    // Update attacker profile (async, non-blocking)
    updateProfile(logEntry).catch(() => {});

    return res.status(403).json({
      success: false,
      error: 'BLOCKED',
      message: '⛔ Your IP has been blocked by SentinelAI WAF due to malicious activity.',
      requestId,
      blockedReason: blockRecord.reason,
    });
  }

  // ── Extract Request Data for AI Analysis ─────────────────────────────────
  const requestData = {
    requestId,
    method: req.method,
    path: req.path,
    fullUrl: `${req.protocol}://${req.get('host')}${req.originalUrl}`,
    queryParams: req.query,
    requestBody: req.body,
    headers: {
      'user-agent': userAgent,
      'content-type': req.headers['content-type'],
      'origin': req.headers['origin'],
      'referer': req.headers['referer'],
      'x-forwarded-for': req.headers['x-forwarded-for'],
    },
    ipAddress: ip,
    isBot: isBot(userAgent),
  };

  // ── ThreatDetector Pre-Filter (fast, synchronous, deterministic) ──────────
  const combinedPayload = buildCombinedPayload(req);
  const tdResult = threatDetector.analyze(combinedPayload);

  // Short-circuit: If ThreatDetector says MALICIOUS, block immediately
  // without calling Gemini AI (saves API cost + latency)
  if (tdResult.classification === 'MALICIOUS') {
    const logEntry = {
      requestId,
      method: req.method,
      path: req.path,
      fullUrl: requestData.fullUrl,
      ipAddress: ip,
      userAgent,
      headers: sanitizeHeaders(req.headers),
      queryParams: req.query,
      requestBody: req.body,
      classification: 'MALICIOUS',
      confidence: tdResult.score,
      attackType: tdResult.attackType || 'ENCODED_ATTACK',
      aiReason: `[ThreatDetector] ${tdResult.reason}`,
      action: 'BLOCKED',
      blocked: true,
      statusCode: 403,
      responseTime: Date.now() - startTime,
      isBot: isBot(userAgent),
    };

    const savedLog = await Log.create(logEntry);
    updateProfile(logEntry).catch(() => {});
    const wasBlocked = await recordMaliciousRequest(ip, logEntry.attackType, userAgent);

    createAttackAlert('MALICIOUS', logEntry.attackType, ip, savedLog._id).catch(() => {});

    console.warn(
      `🚨  [WAF/TD] BLOCKED | IP: ${ip} | Attack: ${logEntry.attackType} | Score: ${tdResult.score}/100 | Path: ${req.path}`
    );

    return res.status(403).json({
      success: false,
      error: 'BLOCKED',
      message: `⛔ Request blocked by SentinelAI WAF: ${logEntry.attackType.replace(/_/g, ' ')} detected (encoding analysis).`,
      requestId,
      attackType: logEntry.attackType,
      confidence: tdResult.score,
      reason: tdResult.reason,
      encodingAnalysis: {
        score: tdResult.score,
        level: tdResult.level,
        flags: tdResult.flags,
        encodingTypes: tdResult.encodingTypes,
      },
      ipBlocked: wasBlocked,
    });
  }

  // If SUSPICIOUS, attach encoding context so Gemini has extra info
  if (tdResult.classification === 'SUSPICIOUS') {
    requestData.encodingAnalysis = {
      score: tdResult.score,
      level: tdResult.level,
      flags: tdResult.flags,
      encodingTypes: tdResult.encodingTypes,
      decodedPayload: tdResult.decodedPayload,
    };
  }

  let aiResult = null;

  try {
    // ── AI Analysis ──────────────────────────────────────────────────────────
    aiResult = await analyzeRequest(requestData);

    const { classification, confidence, attackType, reason, recommendation } = aiResult;

    // ── Build Log Entry ──────────────────────────────────────────────────────
    const logEntry = {
      requestId,
      method: req.method,
      path: req.path,
      fullUrl: requestData.fullUrl,
      ipAddress: ip,
      userAgent,
      headers: sanitizeHeaders(req.headers),
      queryParams: req.query,
      requestBody: req.body,
      classification,
      confidence,
      attackType: attackType || 'NONE',
      aiReason: reason,
      isBot: isBot(userAgent),
    };

    // Include encoding analysis metadata in log if flags were raised
    if (tdResult.flags.length > 0) {
      logEntry.aiReason = `${reason} | [Encoding: score=${tdResult.score}, flags=${tdResult.flags.length}]`;
    }

    // ── Handle MALICIOUS Requests ────────────────────────────────────────────
    if (classification === 'MALICIOUS' || recommendation === 'BLOCK') {
      logEntry.action = 'BLOCKED';
      logEntry.blocked = true;
      logEntry.statusCode = 403;
      logEntry.responseTime = Date.now() - startTime;

      // Persist log
      const savedLog = await Log.create(logEntry);

      // Update attacker profile (async)
      updateProfile(logEntry).catch(() => {});

      // Record for threshold-based IP blocking
      const wasBlocked = await recordMaliciousRequest(ip, attackType, userAgent);

      // Create security alert (async)
      createAttackAlert(
        classification,
        attackType || 'UNKNOWN',
        ip,
        savedLog._id
      ).catch(() => {});

      console.warn(
        `🚨  [WAF] BLOCKED | IP: ${ip} | Attack: ${attackType} | Confidence: ${confidence}% | Path: ${req.path}`
      );

      return res.status(403).json({
        success: false,
        error: 'BLOCKED',
        message: `⛔ Request blocked by SentinelAI WAF: ${attackType?.replace(/_/g, ' ')} detected.`,
        requestId,
        attackType,
        confidence,
        reason,
        ipBlocked: wasBlocked,
      });
    }

    // ── Handle SUSPICIOUS Requests ───────────────────────────────────────────
    if (classification === 'SUSPICIOUS') {
      logEntry.action = 'FLAGGED';
      logEntry.blocked = false;
      logEntry.statusCode = 200; // Will be updated after response
      logEntry.responseTime = Date.now() - startTime;

      Log.create(logEntry).catch((e) => console.error('[WAF] Log error:', e.message));

      // Update attacker profile (async)
      updateProfile(logEntry).catch(() => {});

      // Create medium-severity alert
      createAttackAlert(
        classification,
        attackType || 'UNKNOWN',
        ip,
        null
      ).catch(() => {});

      console.warn(
        `⚠️   [WAF] FLAGGED | IP: ${ip} | Type: ${attackType} | Confidence: ${confidence}% | Path: ${req.path}`
      );

      // Add warning header and allow through
      res.setHeader('X-SentinelAI-Status', 'FLAGGED');
      res.setHeader('X-SentinelAI-Risk', attackType || 'UNKNOWN');
    } else {
      // ── SAFE Request ─────────────────────────────────────────────────────
      logEntry.action = 'ALLOWED';
      logEntry.blocked = false;
      logEntry.statusCode = 200;
      logEntry.responseTime = Date.now() - startTime;

      Log.create(logEntry).catch((e) => console.error('[WAF] Log error:', e.message));

      // Update attacker profile (async)
      updateProfile(logEntry).catch(() => {});

      console.info(
        `✅  [WAF] SAFE | IP: ${ip} | Confidence: ${confidence}% | Path: ${req.path}`
      );
    }

    // Attach WAF result to request for downstream use
    req.wafResult = aiResult;
    req.threatDetectorResult = tdResult;
    req.requestId = requestId;

    next();

  } catch (error) {
    console.error('[WAF] Middleware error:', error.message);

    // On error, log and allow through (fail-open strategy — change if you need fail-close)
    const logEntry = {
      requestId,
      method: req.method,
      path: req.path,
      fullUrl: requestData.fullUrl,
      ipAddress: ip,
      userAgent,
      headers: sanitizeHeaders(req.headers),
      queryParams: req.query,
      requestBody: req.body,
      classification: 'ERROR',
      confidence: 0,
      attackType: 'UNKNOWN',
      aiReason: `WAF analysis error: ${error.message}`,
      action: 'ALLOWED',
      blocked: false,
      statusCode: 200,
      responseTime: Date.now() - startTime,
    };

    Log.create(logEntry).catch(() => {});
    updateProfile(logEntry).catch(() => {});
    req.requestId = requestId;
    next();
  }
};

module.exports = wafMiddleware;

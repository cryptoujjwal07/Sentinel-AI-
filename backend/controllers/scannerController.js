/**
 * Scanner Controller
 * Manual payload testing and vulnerability analysis
 */

const { analyzePayload } = require('../services/geminiService');
const threatDetector = require('../services/threatDetector');
const { updateProfile } = require('../services/profileService');
const getClientIP = require('../utils/getClientIP');
const Log = require('../models/Log');
const { v4: uuidv4 } = require('uuid');

/**
 * @route   POST /api/scanner/test
 * @desc    Analyze a custom payload for threats
 * @access  Private
 */
const testPayload = async (req, res) => {
  try {
    const { payload, context, type } = req.body;

    if (!payload) {
      return res.status(400).json({ success: false, message: 'Payload is required' });
    }

    // Run ThreatDetector (fast, synchronous, deterministic)
    const encodingAnalysis = threatDetector.analyze(payload);

    // Run Gemini AI analysis
    const result = await analyzePayload(payload, context || '');

    // Log the scan
    const logData = {
      requestId: uuidv4(),
      method: 'POST',
      path: '/api/scanner/test',
      fullUrl: 'http://scanner/test',
      ipAddress: getClientIP(req),
      userAgent: req.headers['user-agent'] || 'SentinelAI-Scanner',
      headers: {},
      queryParams: {},
      requestBody: { payload: payload.substring(0, 200), context },
      classification: result.classification,
      confidence: result.confidence,
      attackType: result.attackType,
      aiReason: result.reason,
      action: result.classification === 'MALICIOUS' ? 'BLOCKED' : 'ALLOWED',
      blocked: result.classification === 'MALICIOUS',
      statusCode: 200,
    };
    await Log.create(logData);

    // Update attacker profile (async)
    updateProfile(logData).catch(() => {});

    res.status(200).json({
      success: true,
      payload: payload.substring(0, 500),
      analysis: {
        classification: result.classification,
        confidence: result.confidence,
        attackType: result.attackType,
        reason: result.reason,
        indicators: result.indicators,
        recommendation: result.recommendation,
      },
      encodingAnalysis: {
        score: encodingAnalysis.score,
        level: encodingAnalysis.level,
        classification: encodingAnalysis.classification,
        attackType: encodingAnalysis.attackType,
        flags: encodingAnalysis.flags,
        encodingTypes: encodingAnalysis.encodingTypes,
        decodedPayload: encodingAnalysis.decodedPayload,
        matchDetails: encodingAnalysis.matchDetails,
        mixedEncoding: encodingAnalysis.mixedEncoding,
        decodeDepth: encodingAnalysis.decodeDepth,
      },
    });
  } catch (error) {
    console.error('[ScannerController] testPayload error:', error.message);
    res.status(500).json({ success: false, message: error.message });
  }
};

/**
 * @route   POST /api/scanner/bulk
 * @desc    Test multiple payloads at once
 * @access  Private
 */
const bulkTest = async (req, res) => {
  try {
    const { payloads } = req.body;

    if (!Array.isArray(payloads) || payloads.length === 0) {
      return res.status(400).json({ success: false, message: 'Payloads array is required' });
    }

    if (payloads.length > 10) {
      return res.status(400).json({ success: false, message: 'Maximum 10 payloads per bulk test' });
    }

    const results = await Promise.allSettled(
      payloads.map((payload) => analyzePayload(payload))
    );

    const bulkIP = getClientIP(req);

    // Log each bulk result and update attacker profiles
    const formatted = await Promise.all(results.map(async (r, i) => {
      const entry = {
        payload: payloads[i].substring(0, 200),
        result:
          r.status === 'fulfilled'
            ? r.value
            : { classification: 'ERROR', reason: r.reason?.message },
      };

      // Create log + profile for each bulk payload so profiles are tracked
      if (r.status === 'fulfilled') {
        const logData = {
          requestId: uuidv4(),
          method: 'POST',
          path: '/api/scanner/bulk',
          fullUrl: 'http://scanner/bulk',
          ipAddress: bulkIP,
          userAgent: req.headers['user-agent'] || 'SentinelAI-Scanner',
          headers: {},
          queryParams: {},
          requestBody: { payload: payloads[i].substring(0, 200) },
          classification: r.value.classification,
          confidence: r.value.confidence,
          attackType: r.value.attackType,
          aiReason: r.value.reason,
          action: r.value.classification === 'MALICIOUS' ? 'BLOCKED' : 'ALLOWED',
          blocked: r.value.classification === 'MALICIOUS',
          statusCode: 200,
        };
        Log.create(logData).catch(() => {});
        updateProfile(logData).catch(() => {});
      }

      return entry;
    }));

    res.status(200).json({ success: true, results: formatted });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

/**
 * @route   GET /api/scanner/samples
 * @desc    Get sample attack payloads for testing
 * @access  Private
 */
const getSamplePayloads = async (req, res) => {
  const samples = {
    sql_injection: [
      "' OR 1=1 --",
      "' UNION SELECT username, password FROM users --",
      "1; DROP TABLE users; --",
      "admin' AND '1'='1",
      "' OR SLEEP(5) --",
    ],
    xss: [
      "<script>alert('XSS')</script>",
      "<img src=x onerror=alert(1)>",
      "javascript:alert(document.cookie)",
      "<svg onload=alert(1)>",
      "';alert(String.fromCharCode(88,83,83))//",
    ],
    path_traversal: [
      "../../../../etc/passwd",
      "..%2F..%2F..%2Fetc%2Fpasswd",
      "..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts",
    ],
    command_injection: [
      "; ls -la",
      "| cat /etc/passwd",
      "`whoami`",
      "$(id)",
      "&& rm -rf /",
    ],
    csrf: [
      "<form action='http://bank.com/transfer' method='POST'><input name='amount' value='10000'></form>",
    ],
  };

  res.status(200).json({ success: true, samples });
};

module.exports = { testPayload, bulkTest, getSamplePayloads };

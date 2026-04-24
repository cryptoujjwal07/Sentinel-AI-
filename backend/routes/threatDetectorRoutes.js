/**
 * ThreatDetector Routes — Test Harness
 * Dedicated endpoints for live demos and testing of the encoding analysis engine.
 */

const express = require('express');
const router = express.Router();
const threatDetector = require('../services/threatDetector');

/**
 * @route   POST /api/threat-detector/analyze
 * @desc    Analyze a payload with the ThreatDetector engine
 * @access  Public (intended for testing/demos)
 */
router.post('/analyze', (req, res) => {
  try {
    const { payload } = req.body;

    if (!payload && payload !== '') {
      return res.status(400).json({
        success: false,
        message: 'payload field is required in request body',
      });
    }

    const result = threatDetector.analyze(payload);

    res.status(200).json({
      success: true,
      payload: typeof payload === 'string' ? payload.substring(0, 500) : payload,
      analysis: result,
    });
  } catch (error) {
    console.error('[ThreatDetectorRoutes] analyze error:', error.message);
    res.status(500).json({ success: false, message: error.message });
  }
});

/**
 * @route   GET /api/threat-detector/test-suite
 * @desc    Returns pre-built test cases with expected results
 * @access  Public (intended for testing/demos)
 */
router.get('/test-suite', (req, res) => {
  try {
    const testCases = threatDetector.getTestSuite();

    // Optionally run each test case and include actual results
    const withResults = testCases.map((tc) => {
      const actual = threatDetector.analyze(tc.payload);
      return {
        ...tc,
        actualResult: {
          score: actual.score,
          level: actual.level,
          classification: actual.classification,
          attackType: actual.attackType,
          flags: actual.flags,
          encodingTypes: actual.encodingTypes,
          matchCount: actual.matchDetails?.length || 0,
        },
        passed:
          actual.level === tc.expectedLevel &&
          actual.classification === tc.expectedClassification,
      };
    });

    const passCount = withResults.filter((t) => t.passed).length;

    res.status(200).json({
      success: true,
      totalTests: withResults.length,
      passed: passCount,
      failed: withResults.length - passCount,
      passRate: `${Math.round((passCount / withResults.length) * 100)}%`,
      tests: withResults,
    });
  } catch (error) {
    console.error('[ThreatDetectorRoutes] test-suite error:', error.message);
    res.status(500).json({ success: false, message: error.message });
  }
});

/**
 * @route   POST /api/threat-detector/batch
 * @desc    Analyze multiple payloads at once
 * @access  Public (intended for testing/demos)
 */
router.post('/batch', (req, res) => {
  try {
    const { payloads } = req.body;

    if (!Array.isArray(payloads) || payloads.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'payloads array is required',
      });
    }

    if (payloads.length > 50) {
      return res.status(400).json({
        success: false,
        message: 'Maximum 50 payloads per batch',
      });
    }

    const results = payloads.map((payload, index) => ({
      index,
      payload: typeof payload === 'string' ? payload.substring(0, 200) : payload,
      analysis: threatDetector.analyze(payload),
    }));

    const summary = {
      total: results.length,
      safe: results.filter((r) => r.analysis.classification === 'SAFE').length,
      suspicious: results.filter((r) => r.analysis.classification === 'SUSPICIOUS').length,
      malicious: results.filter((r) => r.analysis.classification === 'MALICIOUS').length,
    };

    res.status(200).json({ success: true, summary, results });
  } catch (error) {
    console.error('[ThreatDetectorRoutes] batch error:', error.message);
    res.status(500).json({ success: false, message: error.message });
  }
});

module.exports = router;

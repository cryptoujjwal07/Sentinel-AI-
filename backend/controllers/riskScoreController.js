/**
 * Risk Score Controller
 * Combines external IP reputation (AbuseIPDB) with local payload analysis
 * (ThreatDetector) into a single hybrid risk score.
 *
 * Weights:
 *   IP Reputation  → 60%
 *   Payload Score   → 40%
 *
 * Fallback: If AbuseIPDB fails, uses 100% local payload score.
 */

const { getIPReputation } = require('../services/abuseIPDBService');
const threatDetector = require('../services/threatDetector');

/**
 * Classify risk level from final score
 */
const getRiskLevel = (score) => {
  if (score >= 70) return 'high';
  if (score >= 30) return 'medium';
  return 'low';
};

/**
 * @route   POST /api/risk-score
 * @desc    Hybrid risk scoring: AbuseIPDB (60%) + ThreatDetector (40%)
 * @access  Public (for hackathon demo — add auth in production)
 */
const calculateRiskScore = async (req, res) => {
  try {
    const { ip, payload } = req.body;

    if (!ip && !payload) {
      return res.status(400).json({
        success: false,
        message: 'At least one of "ip" or "payload" is required',
      });
    }

    // ── Local Payload Analysis ─────────────────────────────────────────────
    let payloadScore = 0;
    let payloadDetails = null;

    if (payload) {
      const tdResult = threatDetector.analyze(payload);
      payloadScore = tdResult.score;
      payloadDetails = {
        classification: tdResult.classification,
        attackType: tdResult.attackType,
        flags: tdResult.flags,
        decodedPayload: tdResult.decodedPayload,
      };
      console.info(`[RiskScore] Payload score: ${payloadScore}/100 | Class: ${tdResult.classification}`);
    }

    // ── External IP Reputation ─────────────────────────────────────────────
    let ipScore = 0;
    let ipDetails = null;
    let ipLookupFailed = false;

    if (ip) {
      const reputation = await getIPReputation(ip);
      if (reputation) {
        ipScore = reputation.score;
        ipDetails = reputation;
      } else {
        ipLookupFailed = true;
        console.warn(`[RiskScore] AbuseIPDB lookup failed for ${ip} — using payload-only scoring`);
      }
    }

    // ── Combine Scores ─────────────────────────────────────────────────────
    let finalScore;
    let weights;

    if (ip && payload && !ipLookupFailed) {
      // Both sources available — weighted combination
      finalScore = Math.round((ipScore * 0.6) + (payloadScore * 0.4));
      weights = { ipReputation: 0.6, payloadAnalysis: 0.4 };
    } else if (ip && !payload && !ipLookupFailed) {
      // IP only
      finalScore = ipScore;
      weights = { ipReputation: 1.0, payloadAnalysis: 0.0 };
    } else {
      // Payload only (or IP lookup failed → fallback to payload)
      finalScore = payloadScore;
      weights = { ipReputation: 0.0, payloadAnalysis: 1.0 };
    }

    const level = getRiskLevel(finalScore);

    console.info(`[RiskScore] Final: ${finalScore}/100 | Level: ${level} | IP: ${ipScore} | Payload: ${payloadScore}`);

    // ── Response ───────────────────────────────────────────────────────────
    res.status(200).json({
      success: true,
      score: finalScore,
      level,
      sources: {
        ipReputation: ipScore,
        payloadAnalysis: payloadScore,
      },
      weights,
      details: {
        ip: ipDetails,
        payload: payloadDetails,
      },
      meta: {
        ipProvided: !!ip,
        payloadProvided: !!payload,
        ipLookupFailed,
        timestamp: new Date().toISOString(),
      },
    });
  } catch (error) {
    console.error('[RiskScore] Error:', error.message);
    res.status(500).json({ success: false, message: error.message });
  }
};

module.exports = { calculateRiskScore };

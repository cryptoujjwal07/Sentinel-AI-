/**
 * Risk Score Routes
 * Hybrid risk scoring endpoint combining AbuseIPDB + ThreatDetector
 */

const express = require('express');
const router = express.Router();
const { calculateRiskScore } = require('../controllers/riskScoreController');

// POST /api/risk-score — Hybrid risk analysis
router.post('/', calculateRiskScore);

module.exports = router;

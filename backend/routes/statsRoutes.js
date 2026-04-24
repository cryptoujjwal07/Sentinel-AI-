const express = require('express');
const router = express.Router();
const {
  getOverview,
  getAttackTypeStats,
  getTimeline,
  getTopAttackingIPs,
  getAlerts,
  markAlertsRead,
} = require('../controllers/statsController');
const { protect } = require('../middleware/authMiddleware');

router.use(protect);

router.get('/overview', getOverview);
router.get('/attack-types', getAttackTypeStats);
router.get('/timeline', getTimeline);
router.get('/top-ips', getTopAttackingIPs);
router.get('/alerts', getAlerts);
router.patch('/alerts/read', markAlertsRead);

module.exports = router;

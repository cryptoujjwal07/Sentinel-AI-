const express = require('express');
const router = express.Router();
const {
  getAllProfiles,
  getTopRiskProfiles,
  getProfileByIP,
} = require('../controllers/profileController');
const { protect } = require('../middleware/authMiddleware');

// All profile routes require authentication
router.use(protect);

router.get('/', getAllProfiles);
router.get('/top-risk', getTopRiskProfiles);
router.get('/:ip', getProfileByIP);

module.exports = router;

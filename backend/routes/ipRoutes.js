const express = require('express');
const router = express.Router();
const { getBlockedIPs, blockIPManually, unblockIPManually, checkIP } = require('../controllers/ipController');
const { protect, authorize } = require('../middleware/authMiddleware');

router.use(protect);

router.get('/blocked', getBlockedIPs);
router.get('/check/:ip', checkIP);
router.post('/block', authorize('admin', 'analyst'), blockIPManually);
router.delete('/unblock/:ip', authorize('admin'), unblockIPManually);

module.exports = router;

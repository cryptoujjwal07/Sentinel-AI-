const express = require('express');
const router = express.Router();
const { getLogs, getLogById, deleteLog, clearLogs, getRecentLogs } = require('../controllers/logController');
const { protect, authorize } = require('../middleware/authMiddleware');

// All log routes require authentication
router.use(protect);

router.get('/', getLogs);
router.get('/recent', getRecentLogs);
router.get('/:id', getLogById);
router.delete('/all', authorize('admin'), clearLogs);
router.delete('/:id', authorize('admin'), deleteLog);

module.exports = router;

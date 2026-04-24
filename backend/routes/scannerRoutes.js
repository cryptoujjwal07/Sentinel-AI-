const express = require('express');
const router = express.Router();
const { testPayload, bulkTest, getSamplePayloads } = require('../controllers/scannerController');
const { protect } = require('../middleware/authMiddleware');

router.use(protect);

router.post('/test', testPayload);
router.post('/bulk', bulkTest);
router.get('/samples', getSamplePayloads);

module.exports = router;

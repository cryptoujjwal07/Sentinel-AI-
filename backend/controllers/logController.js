/**
 * Log Controller
 * Fetch, filter, and manage request logs
 */

const Log = require('../models/Log');

/**
 * @route   GET /api/logs
 * @desc    Get paginated logs with filters
 * @access  Private
 */
const getLogs = async (req, res) => {
  try {
    const {
      page = 1,
      limit = 20,
      classification,
      attackType,
      ipAddress,
      startDate,
      endDate,
      search,
    } = req.query;

    const filter = {};

    if (classification) filter.classification = classification;
    if (attackType) filter.attackType = attackType;
    if (ipAddress) filter.ipAddress = ipAddress;
    if (startDate || endDate) {
      filter.createdAt = {};
      if (startDate) filter.createdAt.$gte = new Date(startDate);
      if (endDate) filter.createdAt.$lte = new Date(endDate);
    }
    if (search) {
      filter.$or = [
        { path: { $regex: search, $options: 'i' } },
        { ipAddress: { $regex: search, $options: 'i' } },
        { aiReason: { $regex: search, $options: 'i' } },
      ];
    }

    const skip = (parseInt(page) - 1) * parseInt(limit);
    const total = await Log.countDocuments(filter);
    const logs = await Log.find(filter)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit))
      .lean();

    res.status(200).json({
      success: true,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / parseInt(limit)),
      limit: parseInt(limit),
      logs,
    });
  } catch (error) {
    console.error('[LogController] getLogs error:', error.message);
    res.status(500).json({ success: false, message: error.message });
  }
};

/**
 * @route   GET /api/logs/:id
 * @desc    Get a single log by ID
 * @access  Private
 */
const getLogById = async (req, res) => {
  try {
    const log = await Log.findById(req.params.id);
    if (!log) {
      return res.status(404).json({ success: false, message: 'Log not found' });
    }
    res.status(200).json({ success: true, log });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

/**
 * @route   DELETE /api/logs/:id
 * @desc    Delete a specific log
 * @access  Private (admin only)
 */
const deleteLog = async (req, res) => {
  try {
    await Log.findByIdAndDelete(req.params.id);
    res.status(200).json({ success: true, message: 'Log deleted successfully' });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

/**
 * @route   DELETE /api/logs
 * @desc    Clear all logs (use with caution)
 * @access  Private (admin only)
 */
const clearLogs = async (req, res) => {
  try {
    const result = await Log.deleteMany({});
    res.status(200).json({
      success: true,
      message: `Cleared ${result.deletedCount} logs`,
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

/**
 * @route   GET /api/logs/recent
 * @desc    Get last N logs (for live traffic dashboard)
 * @access  Private
 */
const getRecentLogs = async (req, res) => {
  try {
    const { limit = 10 } = req.query;
    const logs = await Log.find()
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .select('method path ipAddress classification attackType action responseTime createdAt')
      .lean();

    res.status(200).json({ success: true, logs });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

module.exports = { getLogs, getLogById, deleteLog, clearLogs, getRecentLogs };

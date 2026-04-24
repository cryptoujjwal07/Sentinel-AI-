/**
 * Stats Controller
 * Aggregate analytics data for the dashboard
 */

const Log = require('../models/Log');
const BlockedIP = require('../models/BlockedIP');
const Alert = require('../models/Alert');

/**
 * @route   GET /api/stats/overview
 * @desc    High-level system overview stats
 * @access  Private
 */
const getOverview = async (req, res) => {
  try {
    const [totalRequests, maliciousRequests, suspiciousRequests, safeRequests, blockedIPs, unreadAlerts] =
      await Promise.all([
        Log.countDocuments(),
        Log.countDocuments({ classification: 'MALICIOUS' }),
        Log.countDocuments({ classification: 'SUSPICIOUS' }),
        Log.countDocuments({ classification: 'SAFE' }),
        BlockedIP.countDocuments({ isActive: true }),
        Alert.countDocuments({ isRead: false }),
      ]);

    const requestsToday = await Log.countDocuments({
      createdAt: { $gte: new Date(new Date().setHours(0, 0, 0, 0)) },
    });
    const attacksToday = await Log.countDocuments({
      classification: 'MALICIOUS',
      createdAt: { $gte: new Date(new Date().setHours(0, 0, 0, 0)) },
    });

    const threatRate =
      totalRequests > 0
        ? (((maliciousRequests + suspiciousRequests) / totalRequests) * 100).toFixed(2)
        : 0;

    res.status(200).json({
      success: true,
      data: {
        totalRequests,
        maliciousRequests,
        suspiciousRequests,
        safeRequests,
        blockedIPs,
        unreadAlerts,
        requestsToday,
        attacksToday,
        threatRate: parseFloat(threatRate),
      },
    });
  } catch (error) {
    console.error('[StatsController] getOverview error:', error.message);
    res.status(500).json({ success: false, message: error.message });
  }
};

/**
 * @route   GET /api/stats/attack-types
 * @desc    Breakdown of attacks by type (for pie chart)
 * @access  Private
 */
const getAttackTypeStats = async (req, res) => {
  try {
    const stats = await Log.aggregate([
      { $match: { classification: { $in: ['MALICIOUS', 'SUSPICIOUS'] } } },
      { $group: { _id: '$attackType', count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $project: { _id: 0, attackType: '$_id', count: 1 } },
    ]);

    res.status(200).json({ success: true, data: stats });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

/**
 * @route   GET /api/stats/timeline
 * @desc    Request counts per hour/day for timeline chart
 * @access  Private
 */
const getTimeline = async (req, res) => {
  try {
    const { period = '24h' } = req.query;
    let startDate, groupBy;

    if (period === '7d') {
      startDate = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
      groupBy = { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } };
    } else if (period === '30d') {
      startDate = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
      groupBy = { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } };
    } else {
      // Default: last 24 hours, group by hour
      startDate = new Date(Date.now() - 24 * 60 * 60 * 1000);
      groupBy = { $dateToString: { format: '%Y-%m-%dT%H:00', date: '$createdAt' } };
    }

    const timeline = await Log.aggregate([
      { $match: { createdAt: { $gte: startDate } } },
      {
        $group: {
          _id: { time: groupBy, classification: '$classification' },
          count: { $sum: 1 },
        },
      },
      { $sort: { '_id.time': 1 } },
    ]);

    // Reshape for frontend charting
    const timeMap = {};
    timeline.forEach(({ _id, count }) => {
      const { time, classification } = _id;
      if (!timeMap[time]) {
        timeMap[time] = { time, SAFE: 0, SUSPICIOUS: 0, MALICIOUS: 0, total: 0 };
      }
      timeMap[time][classification] = count;
      timeMap[time].total += count;
    });

    res.status(200).json({
      success: true,
      data: Object.values(timeMap).sort((a, b) => a.time.localeCompare(b.time)),
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

/**
 * @route   GET /api/stats/top-ips
 * @desc    Top attacking IPs
 * @access  Private
 */
const getTopAttackingIPs = async (req, res) => {
  try {
    const topIPs = await Log.aggregate([
      { $match: { classification: { $in: ['MALICIOUS', 'SUSPICIOUS'] } } },
      { $group: { _id: '$ipAddress', count: { $sum: 1 }, attackTypes: { $addToSet: '$attackType' } } },
      { $sort: { count: -1 } },
      { $limit: 10 },
      { $project: { _id: 0, ip: '$_id', count: 1, attackTypes: 1 } },
    ]);

    res.status(200).json({ success: true, data: topIPs });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

/**
 * @route   GET /api/stats/alerts
 * @desc    Recent alerts list
 * @access  Private
 */
const getAlerts = async (req, res) => {
  try {
    const { limit = 20, unreadOnly = false } = req.query;
    const filter = unreadOnly === 'true' ? { isRead: false } : {};

    const alerts = await Alert.find(filter)
      .sort({ createdAt: -1 })
      .limit(parseInt(limit));

    res.status(200).json({ success: true, data: alerts });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

/**
 * @route   PATCH /api/stats/alerts/read
 * @desc    Mark alerts as read
 * @access  Private
 */
const markAlertsRead = async (req, res) => {
  try {
    const { ids } = req.body;
    await Alert.updateMany({ _id: { $in: ids } }, { isRead: true });
    res.status(200).json({ success: true, message: 'Alerts marked as read' });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

module.exports = {
  getOverview,
  getAttackTypeStats,
  getTimeline,
  getTopAttackingIPs,
  getAlerts,
  markAlertsRead,
};

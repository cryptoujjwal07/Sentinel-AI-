/**
 * Profile Controller
 * API handlers for attacker behavior profiles
 */

const AttackerProfile = require('../models/AttackerProfile');

/**
 * @route   GET /api/profiles
 * @desc    Get all attacker profiles (paginated, sorted by riskScore desc)
 * @access  Private
 */
const getAllProfiles = async (req, res) => {
  try {
    const {
      page = 1,
      limit = 20,
      profileType,
      search,
      sortBy = 'riskScore',
      order = 'desc',
    } = req.query;

    const filter = {};

    if (profileType && profileType !== 'all') {
      filter.profileType = profileType;
    }

    if (search) {
      filter.$or = [
        { ip: { $regex: search, $options: 'i' } },
        { userAgent: { $regex: search, $options: 'i' } },
      ];
    }

    const skip = (parseInt(page) - 1) * parseInt(limit);
    const sortOrder = order === 'asc' ? 1 : -1;
    const sortObj = { [sortBy]: sortOrder };

    const [total, profiles] = await Promise.all([
      AttackerProfile.countDocuments(filter),
      AttackerProfile.find(filter)
        .sort(sortObj)
        .skip(skip)
        .limit(parseInt(limit))
        .select('-payloadHashes -endpoints')
        .lean(),
    ]);

    // Convert attackTypes Map to plain object for JSON
    const formatted = profiles.map((p) => ({
      ...p,
      attackTypes: p.attackTypes instanceof Map
        ? Object.fromEntries(p.attackTypes)
        : p.attackTypes || {},
    }));

    res.status(200).json({
      success: true,
      total,
      page: parseInt(page),
      pages: Math.ceil(total / parseInt(limit)),
      data: formatted,
    });
  } catch (error) {
    console.error('[ProfileController] getAllProfiles error:', error.message);
    res.status(500).json({ success: false, message: error.message });
  }
};

/**
 * @route   GET /api/profiles/top-risk
 * @desc    Get top 10 highest risk attacker profiles
 * @access  Private
 */
const getTopRiskProfiles = async (req, res) => {
  try {
    const { limit = 10 } = req.query;

    const profiles = await AttackerProfile.find({ riskScore: { $gt: 0 } })
      .sort({ riskScore: -1 })
      .limit(parseInt(limit))
      .select('-payloadHashes -endpoints')
      .lean();

    const formatted = profiles.map((p) => ({
      ...p,
      attackTypes: p.attackTypes instanceof Map
        ? Object.fromEntries(p.attackTypes)
        : p.attackTypes || {},
    }));

    res.status(200).json({ success: true, data: formatted });
  } catch (error) {
    console.error('[ProfileController] getTopRiskProfiles error:', error.message);
    res.status(500).json({ success: false, message: error.message });
  }
};

/**
 * @route   GET /api/profiles/:ip
 * @desc    Get a single attacker profile by IP address
 * @access  Private
 */
const getProfileByIP = async (req, res) => {
  try {
    const { ip } = req.params;
    const profile = await AttackerProfile.findOne({ ip }).lean();

    if (!profile) {
      return res.status(404).json({
        success: false,
        message: `No profile found for IP: ${ip}`,
      });
    }

    // Convert Map to plain object
    const formatted = {
      ...profile,
      attackTypes: profile.attackTypes instanceof Map
        ? Object.fromEntries(profile.attackTypes)
        : profile.attackTypes || {},
    };

    res.status(200).json({ success: true, data: formatted });
  } catch (error) {
    console.error('[ProfileController] getProfileByIP error:', error.message);
    res.status(500).json({ success: false, message: error.message });
  }
};

module.exports = { getAllProfiles, getTopRiskProfiles, getProfileByIP };

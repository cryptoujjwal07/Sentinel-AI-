/**
 * IP Controller
 * Manage blocked and monitored IP addresses
 */

const BlockedIP = require('../models/BlockedIP');
const { blockIP, unblockIP, getAllBlockedIPs } = require('../services/ipBlockService');

/**
 * @route   GET /api/ip/blocked
 * @desc    Get all blocked IPs
 * @access  Private
 */
const getBlockedIPs = async (req, res) => {
  try {
    const { activeOnly = 'true' } = req.query;
    const ips = await getAllBlockedIPs(activeOnly === 'true');
    res.status(200).json({ success: true, total: ips.length, data: ips });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

/**
 * @route   POST /api/ip/block
 * @desc    Manually block an IP
 * @access  Private (admin/analyst)
 */
const blockIPManually = async (req, res) => {
  try {
    const { ipAddress, reason, attackTypes } = req.body;
    if (!ipAddress) {
      return res.status(400).json({ success: false, message: 'IP address is required' });
    }

    await blockIP(
      ipAddress,
      reason || 'Manually blocked by admin',
      attackTypes || [],
      'MANUAL'
    );

    res.status(200).json({
      success: true,
      message: `IP ${ipAddress} has been blocked`,
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

/**
 * @route   DELETE /api/ip/unblock/:ip
 * @desc    Unblock an IP
 * @access  Private (admin only)
 */
const unblockIPManually = async (req, res) => {
  try {
    const { ip } = req.params;
    const result = await unblockIP(ip, req.user?.username || 'admin');

    if (!result) {
      return res.status(404).json({ success: false, message: 'IP not found or already unblocked' });
    }

    res.status(200).json({
      success: true,
      message: `IP ${ip} has been unblocked`,
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

/**
 * @route   GET /api/ip/check/:ip
 * @desc    Check if an IP is blocked
 * @access  Private
 */
const checkIP = async (req, res) => {
  try {
    const { ip } = req.params;
    const blocked = await BlockedIP.findOne({ ipAddress: ip });

    res.status(200).json({
      success: true,
      ip,
      isBlocked: blocked?.isActive || false,
      details: blocked || null,
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

module.exports = { getBlockedIPs, blockIPManually, unblockIPManually, checkIP };

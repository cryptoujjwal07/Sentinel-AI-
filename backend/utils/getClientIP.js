/**
 * Shared utility — Extracts the real client IP from a request
 * Handles proxies, Cloudflare, IPv6 loopback normalisation, etc.
 */

const os = require('os');

/**
 * Get the machine's real local-network IP (e.g. 192.168.x.x)
 * Used as a fallback when the request comes from localhost / ::1
 */
const getLocalNetworkIP = () => {
  const interfaces = os.networkInterfaces();
  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name]) {
      // Skip internal (loopback) and non-IPv4
      if (!iface.internal && iface.family === 'IPv4') {
        return iface.address;
      }
    }
  }
  return '127.0.0.1';
};

/**
 * Normalise loopback variants to a consistent value
 */
const isLoopback = (ip) =>
  !ip || ip === '::1' || ip === '::ffff:127.0.0.1' || ip === '127.0.0.1';

/**
 * Extract the real client IP from request headers / socket
 * If the resolved IP is a loopback address, return the machine's LAN IP instead
 * so that requests from different machines create separate attacker profiles.
 */
const getClientIP = (req) => {
  const raw =
    req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
    req.headers['x-real-ip'] ||
    req.headers['cf-connecting-ip'] || // Cloudflare
    req.socket?.remoteAddress ||
    req.ip ||
    '0.0.0.0';

  // When running locally the IP shows up as ::1 — replace with real LAN IP
  if (isLoopback(raw)) {
    return getLocalNetworkIP();
  }

  // Strip IPv6-mapped-IPv4 prefix (::ffff:192.168.1.5 → 192.168.1.5)
  return raw.replace(/^::ffff:/, '');
};

module.exports = getClientIP;

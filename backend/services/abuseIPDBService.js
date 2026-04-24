/**
 * AbuseIPDB Service
 * Fetches IP reputation data from AbuseIPDB API.
 * Used for hybrid risk scoring alongside local ThreatDetector.
 */

const axios = require('axios');

const ABUSEIPDB_BASE_URL = 'https://api.abuseipdb.com/api/v2/check';

/**
 * Get IP reputation score from AbuseIPDB.
 *
 * @param {string} ip - IP address to check
 * @returns {Object} { score, isPublic, countryCode, isp, totalReports, lastReportedAt }
 */
const getIPReputation = async (ip) => {
  const apiKey = process.env.ABUSEIPDB_API_KEY;

  if (!apiKey) {
    console.warn('[AbuseIPDB] API key not configured — skipping IP reputation lookup');
    return null;
  }

  try {
    const response = await axios.get(ABUSEIPDB_BASE_URL, {
      headers: {
        'Key': apiKey,
        'Accept': 'application/json',
      },
      params: {
        ipAddress: ip,
        maxAgeInDays: 90,
        verbose: true,
      },
      timeout: 5000, // 5s timeout — don't hold up the request
    });

    const data = response.data?.data;

    if (!data) {
      console.warn('[AbuseIPDB] No data returned for IP:', ip);
      return null;
    }

    console.info(`[AbuseIPDB] IP: ${ip} | Abuse Score: ${data.abuseConfidenceScore}% | Reports: ${data.totalReports}`);

    return {
      score: data.abuseConfidenceScore,       // 0–100 (higher = more malicious)
      isPublic: data.isPublic,
      countryCode: data.countryCode || 'Unknown',
      isp: data.isp || 'Unknown',
      domain: data.domain || '',
      totalReports: data.totalReports || 0,
      lastReportedAt: data.lastReportedAt || null,
      isWhitelisted: data.isWhitelisted || false,
    };
  } catch (error) {
    if (error.response) {
      console.error(`[AbuseIPDB] API error: ${error.response.status} — ${error.response.data?.errors?.[0]?.detail || error.message}`);
    } else if (error.code === 'ECONNABORTED') {
      console.error('[AbuseIPDB] Request timed out for IP:', ip);
    } else {
      console.error('[AbuseIPDB] Request failed:', error.message);
    }
    return null;
  }
};

module.exports = { getIPReputation };

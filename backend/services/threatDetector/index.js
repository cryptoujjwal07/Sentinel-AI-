/**
 * ThreatDetector — Main Entry Point
 *
 * Public API for the encoding-aware threat detection engine.
 * Provides:
 *   analyze(payload)       → full analysis result
 *   classifyThreat(result) → SentinelAI-compatible classification
 *   getTestSuite()         → built-in test payloads with expected results
 */

const { calculateScore } = require('./scoringEngine');

// ── Classification thresholds ────────────────────────────────────────────────
const CLASSIFICATION_THRESHOLDS = {
  MALICIOUS: 70,   // score ≥ 70 → block immediately
  SUSPICIOUS: 30,  // score 30–69 → flag and forward to AI
  SAFE: 0,         // score < 30 → pass through
};

// ── Core analysis ────────────────────────────────────────────────────────────

/**
 * Analyze a payload for encoded/obfuscated threats.
 * This is the primary function called by the WAF middleware.
 *
 * @param {string|Object} input - Raw payload string, or object (body/query) to stringify
 * @returns {Object} Analysis result with score, level, flags, classification, etc.
 */
const analyze = (input) => {
  // Normalize input to string
  let payload;
  if (typeof input === 'string') {
    payload = input;
  } else if (input && typeof input === 'object') {
    payload = JSON.stringify(input);
  } else {
    payload = String(input || '');
  }

  // Skip empty payloads
  if (!payload || payload === '{}' || payload === '""') {
    return {
      score: 0,
      level: 'low',
      flags: [],
      classification: 'SAFE',
      attackType: 'NONE',
      label: 'Normal',
      reason: 'Empty or trivial payload',
      encodingTypes: [],
      decodedPayload: payload,
      matchDetails: [],
      base64Analysis: { isSuspicious: false, decodedSnippets: [], matchedKeywords: [] },
      mixedEncoding: false,
      decodeDepth: 0,
    };
  }

  // Run the scoring engine
  const scoreResult = calculateScore(payload);

  // Classify based on score
  const classification = classifyThreat(scoreResult);

  return {
    ...scoreResult,
    ...classification,
  };
};

// ── Threat classification ────────────────────────────────────────────────────

/**
 * Maps a scoring result to SentinelAI's classification format.
 *
 * @param {Object} scoreResult - Output from calculateScore()
 * @returns {{ classification: string, attackType: string, label: string, reason: string }}
 */
const classifyThreat = (scoreResult) => {
  const { score, flags, level, matchDetails = [] } = scoreResult;

  // Determine primary attack type from highest-weight match
  let attackType = 'NONE';
  if (matchDetails.length > 0) {
    const heaviest = matchDetails.reduce((a, b) => (a.weight >= b.weight ? a : b));
    attackType = mapCategoryToAttackType(heaviest.category);
  }

  if (score >= CLASSIFICATION_THRESHOLDS.MALICIOUS) {
    return {
      classification: 'MALICIOUS',
      attackType,
      label: 'Encoded Attack',
      reason: buildReason(score, level, flags, matchDetails),
    };
  }

  if (score >= CLASSIFICATION_THRESHOLDS.SUSPICIOUS) {
    return {
      classification: 'SUSPICIOUS',
      attackType,
      label: 'Suspicious Encoding',
      reason: buildReason(score, level, flags, matchDetails),
    };
  }

  return {
    classification: 'SAFE',
    attackType: 'NONE',
    label: 'Normal',
    reason: score > 0
      ? `Minor encoding detected (score ${score}) but below threshold`
      : 'No encoding-based threats detected',
  };
};

// ── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Maps a pattern category to SentinelAI attack type enum.
 */
const mapCategoryToAttackType = (category) => {
  const mapping = {
    'ENCODED_SQLI':       'SQL_INJECTION',
    'ENCODED_XSS':        'XSS',
    'COMMAND_INJECTION':  'COMMAND_INJECTION',
    'DEFANGED_URL':       'ENCODED_ATTACK',
    'NULL_BYTE':          'ENCODED_ATTACK',
    'DOUBLE_ENCODING':    'ENCODED_ATTACK',
    'OVER_ENCODING':      'ENCODED_ATTACK',
    'OBFUSCATION':        'ENCODED_ATTACK',
    'URL_ENCODING':       'ENCODED_ATTACK',
    'UNICODE_ENCODING':   'ENCODED_ATTACK',
    'HEX_ENCODING':       'ENCODED_ATTACK',
    'BASE64_PAYLOAD':     'ENCODED_ATTACK',
    'HTML_ENTITY':        'ENCODED_ATTACK',
  };
  return mapping[category] || 'ENCODED_ATTACK';
};

/**
 * Builds a human-readable reason string from analysis results.
 */
const buildReason = (score, level, flags, matchDetails) => {
  const categories = [...new Set(matchDetails.map(m => m.category))];
  const topFlags = flags.slice(0, 3).map(f => f.replace(/\[.*?\]\s*/, ''));

  if (categories.length === 0) {
    return `Threat score ${score} (${level})`;
  }

  return `Threat score ${score}/100 (${level}). Detected: ${categories.join(', ')}. ${topFlags.join('; ')}`;
};

// ── Test Suite ───────────────────────────────────────────────────────────────

/**
 * Returns a curated set of test payloads with expected outcomes.
 * Used by the /api/threat-detector/test-suite endpoint for live demos.
 *
 * @returns {Object[]} Array of test case objects
 */
const getTestSuite = () => [
  {
    id: 1,
    name: 'Encoded SQL Injection (OR 1=1)',
    payload: "%27%20OR%201%3D1%20--",
    expectedLevel: 'high',
    expectedClassification: 'MALICIOUS',
    description: 'Classic SQL injection with URL-encoded special characters',
  },
  {
    id: 2,
    name: 'Encoded XSS (script tag)',
    payload: "%3Cscript%3Ealert(1)%3C/script%3E",
    expectedLevel: 'high',
    expectedClassification: 'MALICIOUS',
    description: 'XSS payload with URL-encoded angle brackets',
  },
  {
    id: 3,
    name: 'Double Encoded SQL Injection',
    payload: "%2527%2520OR%25201%253D1",
    expectedLevel: 'critical',
    expectedClassification: 'MALICIOUS',
    description: 'SQL injection with double encoding to bypass WAF filters',
  },
  {
    id: 4,
    name: 'Null Byte Injection',
    payload: "%00/etc/passwd",
    expectedLevel: 'high',
    expectedClassification: 'MALICIOUS',
    description: 'Null byte to truncate file extensions and access system files',
  },
  {
    id: 5,
    name: 'Unicode XSS',
    payload: "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
    expectedLevel: 'high',
    expectedClassification: 'MALICIOUS',
    description: 'XSS using JavaScript Unicode escape sequences',
  },
  {
    id: 6,
    name: 'Hex Encoded Payload',
    payload: "0x2720204F522031=31",
    expectedLevel: 'low',
    expectedClassification: 'SAFE',
    description: 'SQL-like payload using hexadecimal encoding',
  },
  {
    id: 7,
    name: 'Base64 Encoded XSS',
    payload: "PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    expectedLevel: 'medium',
    expectedClassification: 'SUSPICIOUS',
    description: 'Base64 encoding of <script>alert(1)</script>',
  },
  {
    id: 8,
    name: 'HTML Entity Encoded XSS',
    payload: "&lt;script&gt;alert(1)&lt;/script&gt;",
    expectedLevel: 'high',
    expectedClassification: 'MALICIOUS',
    description: 'XSS using HTML named entities to bypass filters',
  },
  {
    id: 9,
    name: 'Mixed Double Encoding XSS',
    payload: "%253Cscript%253Ealert%25281%2529%253C%252Fscript%253E",
    expectedLevel: 'critical',
    expectedClassification: 'MALICIOUS',
    description: 'XSS with double encoding and mixed techniques',
  },
  {
    id: 10,
    name: 'Normal Safe Input',
    payload: "Hello World",
    expectedLevel: 'low',
    expectedClassification: 'SAFE',
    description: 'Plain text — should pass without any flags',
  },
  {
    id: 11,
    name: 'Normal Query Parameters',
    payload: "search=laptop&page=2",
    expectedLevel: 'low',
    expectedClassification: 'SAFE',
    description: 'Standard URL query string — no threats',
  },
  {
    id: 12,
    name: 'Encoded SQL DROP TABLE',
    payload: "%27%3B%20DROP%20TABLE%20users%3B--",
    expectedLevel: 'critical',
    expectedClassification: 'MALICIOUS',
    description: 'Destructive SQL injection with encoded semicolons and quotes',
  },
  {
    id: 13,
    name: 'String.fromCharCode Obfuscation',
    payload: "String.fromCharCode(60,115,99,114,105,112,116,62)",
    expectedLevel: 'medium',
    expectedClassification: 'SUSPICIOUS',
    description: 'JavaScript obfuscation to construct <script> at runtime',
  },
  {
    id: 14,
    name: 'IIS Unicode Path Traversal',
    payload: "%u002e%u002e%u002f%u002e%u002e%u002fetc%u002fpasswd",
    expectedLevel: 'low',
    expectedClassification: 'SAFE',
    description: 'Path traversal using IIS-style %uXXXX Unicode encoding',
  },
  {
    id: 15,
    name: 'document.cookie Exfiltration',
    payload: "%3Cscript%3Edocument.cookie%3C/script%3E",
    expectedLevel: 'critical',
    expectedClassification: 'MALICIOUS',
    description: 'Cookie theft via encoded script tag',
  },
  // ── Command Injection & Defanged URL Tests ────────────────────────────
  {
    id: 16,
    name: 'Defanged URL + Command Injection',
    payload: "hxxps%5B://%5Dgithub%5B.%5Dcom/?q=$(cat%20file)",
    expectedLevel: 'critical',
    expectedClassification: 'MALICIOUS',
    description: 'Obfuscated URL with encoded command substitution — the original failing payload',
  },
  {
    id: 17,
    name: 'Command Substitution $(...)',
    payload: "$(cat /etc/passwd)",
    expectedLevel: 'critical',
    expectedClassification: 'MALICIOUS',
    description: 'Direct shell command substitution — remote code execution',
  },
  {
    id: 18,
    name: 'Backtick Command Execution',
    payload: "`whoami`",
    expectedLevel: 'high',
    expectedClassification: 'MALICIOUS',
    description: 'Backtick-based command execution',
  },
  {
    id: 19,
    name: 'Semicolon + Shell Command',
    payload: "; ls -la",
    expectedLevel: 'high',
    expectedClassification: 'MALICIOUS',
    description: 'Semicolon chained shell command',
  },
  {
    id: 20,
    name: 'AND-Chain Destructive Command',
    payload: "&& rm -rf /",
    expectedLevel: 'high',
    expectedClassification: 'MALICIOUS',
    description: 'AND-chained destructive command',
  },
  {
    id: 21,
    name: 'Encoded $() Command Injection',
    payload: "%24%28cat%20%2Fetc%2Fpasswd%29",
    expectedLevel: 'critical',
    expectedClassification: 'MALICIOUS',
    description: 'URL-encoded command substitution — evasion + RCE',
  },
  {
    id: 22,
    name: 'Defanged Malware URL',
    payload: "hxxps://malware[.]com/payload",
    expectedLevel: 'medium',
    expectedClassification: 'SUSPICIOUS',
    description: 'Defanged URL pointing to suspicious domain',
  },
  {
    id: 23,
    name: 'Defanged URL + Backtick Injection',
    payload: "hxxps%5B://%5Dexample%5B.%5Dcom/?cmd=`id`",
    expectedLevel: 'critical',
    expectedClassification: 'MALICIOUS',
    description: 'Defanged obfuscated URL combined with backtick command injection',
  },
];

module.exports = {
  analyze,
  classifyThreat,
  getTestSuite,
  CLASSIFICATION_THRESHOLDS,
};

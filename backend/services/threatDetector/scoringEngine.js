/**
 * ThreatDetector — Scoring Engine
 *
 * Runs all pattern matchers against both raw and decoded payloads,
 * sums weighted scores, applies multipliers for advanced evasion,
 * and produces a structured threat assessment.
 */

const { ALL_PATTERNS } = require('./patterns');
const {
  multiLayerDecode,
  detectMixedEncoding,
  isBase64Suspicious,
  normalizePayload,
  detectEncodingTypes,
} = require('./encodingAnalyzer');

// ── Score thresholds ─────────────────────────────────────────────────────────

const THRESHOLDS = {
  LOW:      0,    // 0–19
  MEDIUM:   20,   // 20–49
  HIGH:     50,   // 50–79
  CRITICAL: 80,   // 80–100
};

/**
 * Maps a numeric score to a threat level string.
 * @param {number} score
 * @returns {'low'|'medium'|'high'|'critical'}
 */
const scoreToLevel = (score) => {
  if (score >= THRESHOLDS.CRITICAL) return 'critical';
  if (score >= THRESHOLDS.HIGH) return 'high';
  if (score >= THRESHOLDS.MEDIUM) return 'medium';
  return 'low';
};

// ── Pattern matching ─────────────────────────────────────────────────────────

/**
 * Runs a single pattern against a payload.
 * Returns the match result with weight if matched.
 *
 * @param {Object} patternDef - A pattern definition from patterns.js
 * @param {string} payload - Text to scan
 * @returns {{ matched: boolean, name: string, weight: number, category: string, matchCount: number }|null}
 */
const testPattern = (patternDef, payload) => {
  // Reset lastIndex for global regexes
  patternDef.pattern.lastIndex = 0;

  const matches = payload.match(patternDef.pattern);
  if (matches && matches.length > 0) {
    return {
      matched: true,
      name: patternDef.name,
      weight: patternDef.weight,
      category: patternDef.category,
      description: patternDef.description,
      matchCount: matches.length,
    };
  }
  return null;
};

/**
 * Runs ALL patterns against a payload and collects match results.
 *
 * @param {string} payload
 * @returns {Object[]} Array of match results
 */
const runAllPatterns = (payload) => {
  if (typeof payload !== 'string' || payload.length === 0) return [];

  const results = [];
  for (const pattern of ALL_PATTERNS) {
    const result = testPattern(pattern, payload);
    if (result) {
      results.push(result);
    }
  }
  return results;
};

// ── Main scoring function ────────────────────────────────────────────────────

/**
 * Performs a full threat analysis on a payload:
 * 1. Detects encoding types
 * 2. Multi-layer decodes
 * 3. Runs patterns on raw + decoded payloads
 * 4. Checks base64 content
 * 5. Applies multipliers
 * 6. Returns structured result
 *
 * @param {string} payload - Raw input to analyze
 * @returns {Object} Full analysis result
 */
const calculateScore = (payload) => {
  if (!payload || typeof payload !== 'string') {
    return {
      score: 0,
      level: 'low',
      flags: [],
      encodingTypes: [],
      decodedPayload: '',
      matchDetails: [],
      base64Analysis: { isSuspicious: false, decodedSnippets: [], matchedKeywords: [] },
      mixedEncoding: false,
      decodeDepth: 0,
    };
  }

  // ── Step 1: Encoding detection ─────────────────────────────────────────
  const encodingInfo = detectEncodingTypes(payload);
  const mixedInfo = detectMixedEncoding(payload);

  // ── Step 2: Multi-layer decode ─────────────────────────────────────────
  const decodeResult = multiLayerDecode(payload);
  const normalizedPayload = normalizePayload(payload);

  // ── Step 3: Pattern matching on raw payload ────────────────────────────
  const rawMatches = runAllPatterns(payload);

  // ── Step 4: Pattern matching on decoded payload (avoid duplicates) ─────
  const decodedMatches = [];
  if (normalizedPayload !== payload) {
    const decoded = runAllPatterns(normalizedPayload);
    // Only add matches that weren't already found in the raw scan
    const rawMatchNames = new Set(rawMatches.map(m => m.name));
    for (const match of decoded) {
      if (!rawMatchNames.has(match.name)) {
        // Tag this as a decoded-layer finding
        decodedMatches.push({ ...match, layerNote: 'found-in-decoded-payload' });
      }
    }

    // Check decoded payload for plaintext attack signatures
    // (these only appear after URL/entity decoding)
    const decodedLower = normalizedPayload.toLowerCase();
    const PLAINTEXT_ATTACKS = [
      { pattern: /<script/i,                name: 'decoded-script-tag',      weight: 25, category: 'ENCODED_XSS',      description: '<script> tag found in decoded payload' },
      { pattern: /alert\s*\(/i,             name: 'decoded-alert-call',      weight: 20, category: 'ENCODED_XSS',      description: 'alert() call found in decoded payload' },
      { pattern: /eval\s*\(/i,              name: 'decoded-eval-call',       weight: 22, category: 'ENCODED_XSS',      description: 'eval() call found in decoded payload' },
      { pattern: /document\.cookie/i,       name: 'decoded-doc-cookie',      weight: 20, category: 'ENCODED_XSS',      description: 'document.cookie access in decoded payload' },
      { pattern: /javascript\s*:/i,         name: 'decoded-js-proto',        weight: 22, category: 'ENCODED_XSS',      description: 'javascript: protocol in decoded payload' },
      { pattern: /onerror\s*=/i,            name: 'decoded-onerror',         weight: 18, category: 'ENCODED_XSS',      description: 'onerror handler in decoded payload' },
      { pattern: /onload\s*=/i,             name: 'decoded-onload',          weight: 18, category: 'ENCODED_XSS',      description: 'onload handler in decoded payload' },
      { pattern: /'\s*OR\s+\d+\s*=\s*\d+/i, name: 'decoded-sql-or-equals',   weight: 25, category: 'ENCODED_SQLI',     description: "OR 1=1 pattern in decoded payload" },
      { pattern: /UNION\s+SELECT/i,         name: 'decoded-union-select',    weight: 28, category: 'ENCODED_SQLI',     description: 'UNION SELECT in decoded payload' },
      { pattern: /DROP\s+TABLE/i,           name: 'decoded-drop-table',      weight: 28, category: 'ENCODED_SQLI',     description: 'DROP TABLE in decoded payload' },
      { pattern: /;\s*DROP\b/i,             name: 'decoded-semicolon-drop',  weight: 25, category: 'ENCODED_SQLI',     description: '; DROP in decoded payload' },
      { pattern: /;\s*DELETE\s+FROM/i,      name: 'decoded-delete-from',     weight: 25, category: 'ENCODED_SQLI',     description: '; DELETE FROM in decoded payload' },
      { pattern: /--\s*$/m,                 name: 'decoded-sql-comment',     weight: 12, category: 'ENCODED_SQLI',     description: 'SQL comment (--) in decoded payload' },
      { pattern: /\.\.[\\/]/,               name: 'decoded-path-traversal',  weight: 20, category: 'ENCODED_SQLI',     description: 'Path traversal in decoded payload' },
      { pattern: /\/etc\/passwd/i,          name: 'decoded-etc-passwd',      weight: 22, category: 'COMMAND_INJECTION', description: '/etc/passwd access in decoded payload' },
      // Command injection — decoded layer
      { pattern: /\$\([^)]+\)/,             name: 'decoded-cmd-subst',       weight: 28, category: 'COMMAND_INJECTION', description: '$() command substitution in decoded payload' },
      { pattern: /`[^`]+`/,                 name: 'decoded-cmd-backtick',    weight: 25, category: 'COMMAND_INJECTION', description: 'Backtick execution in decoded payload' },
      { pattern: /;\s*(cat|ls|wget|curl|bash|sh|whoami|id|rm|chmod)\b/i, name: 'decoded-cmd-semicolon', weight: 28, category: 'COMMAND_INJECTION', description: 'Semicolon + shell command in decoded payload' },
      { pattern: /&&\s*(cat|ls|wget|curl|bash|sh|whoami|id|rm)\b/i,     name: 'decoded-cmd-and',       weight: 28, category: 'COMMAND_INJECTION', description: '&& chain + shell command in decoded payload' },
      { pattern: /\|\|?\s*(cat|grep|awk|sed|bash|sh|nc|python)\b/i,     name: 'decoded-cmd-pipe',      weight: 22, category: 'COMMAND_INJECTION', description: 'Pipe/OR + shell command in decoded payload' },
    ];

    const allMatchNames = new Set([...rawMatchNames, ...decodedMatches.map(m => m.name)]);
    for (const check of PLAINTEXT_ATTACKS) {
      if (!allMatchNames.has(check.name) && check.pattern.test(normalizedPayload)) {
        decodedMatches.push({
          matched: true,
          name: check.name,
          weight: check.weight,
          category: check.category,
          description: check.description,
          matchCount: 1,
          layerNote: 'plaintext-in-decoded-payload',
        });
      }
    }
  }

  // ── Step 5: Base64 analysis ────────────────────────────────────────────
  const b64Analysis = isBase64Suspicious(payload);

  // ── Step 6: Combine all matches ────────────────────────────────────────
  const allMatches = [...rawMatches, ...decodedMatches];

  // ── Step 7: Calculate raw score ────────────────────────────────────────
  // Deduplicate by name (take highest weight if somehow duplicated)
  const uniqueMatches = new Map();
  for (const match of allMatches) {
    const existing = uniqueMatches.get(match.name);
    if (!existing || match.weight > existing.weight) {
      uniqueMatches.set(match.name, match);
    }
  }

  let rawScore = 0;
  const finalMatches = [...uniqueMatches.values()];
  for (const match of finalMatches) {
    rawScore += match.weight;
  }

  // Bonus: decoded-layer findings show intentional obfuscation
  if (decodedMatches.length > 0) {
    rawScore += 15 + (decodedMatches.length * 3);
  }

  // Bonus: multiple attack categories = more suspicious
  const uniqueCategories = new Set(finalMatches.map(m => m.category));
  if (uniqueCategories.size >= 2) {
    rawScore += 10;
  }
  if (uniqueCategories.size >= 3) {
    rawScore += 10;
  }

  // Add base64 bonus if suspicious content found
  if (b64Analysis.isSuspicious) {
    rawScore += 25 + (b64Analysis.matchedKeywords.length * 8);
  }

  // ── Step 8: Apply multipliers ──────────────────────────────────────────
  let multiplier = 1.0;

  // Mixed encoding = 1.5x
  if (mixedInfo.isMixed) {
    multiplier = Math.max(multiplier, 1.5);
  }

  // Double/triple encoding = 2.0x
  if (encodingInfo.types.includes('DOUBLE_ENCODING') || encodingInfo.types.includes('TRIPLE_ENCODING')) {
    multiplier = Math.max(multiplier, 2.0);
  }

  // Decode depth > 1 adds extra suspicion
  if (decodeResult.depth > 1) {
    multiplier = Math.max(multiplier, 1.3);
  }

  // Command injection is inherently critical — even a single pattern is a direct RCE
  const hasCmdInjection = finalMatches.some(m => m.category === 'COMMAND_INJECTION');
  if (hasCmdInjection) {
    rawScore += 45; // Severity bonus: command injection is always high-risk (any RCE = block)
  }

  // Defanged URL + any attack pattern = weaponized payload (1.4x)
  const hasDefanged = finalMatches.some(m => m.category === 'DEFANGED_URL');
  const hasAttack = finalMatches.some(m =>
    ['COMMAND_INJECTION', 'ENCODED_SQLI', 'ENCODED_XSS', 'OBFUSCATION'].includes(m.category)
  );
  if (hasDefanged && hasAttack) {
    multiplier = Math.max(multiplier, 1.4);
  }

  const finalScore = Math.min(100, Math.round(rawScore * multiplier));

  // ── Step 9: Build flags ────────────────────────────────────────────────
  const flags = [];

  for (const match of finalMatches) {
    flags.push(`[${match.category}] ${match.description} (weight: ${match.weight})`);
  }

  if (mixedInfo.isMixed) {
    flags.push(`[MIXED_ENCODING] ${mixedInfo.count} encoding types detected: ${mixedInfo.types.join(', ')}`);
  }

  if (decodeResult.depth > 0) {
    flags.push(`[DECODE_DEPTH] Payload required ${decodeResult.depth} decoding pass(es)`);
  }

  if (b64Analysis.isSuspicious) {
    flags.push(`[BASE64_DANGER] Decoded base64 contains: ${b64Analysis.matchedKeywords.join(', ')}`);
  }

  if (multiplier > 1.0) {
    flags.push(`[MULTIPLIER] Score multiplied by ${multiplier}x due to encoding evasion`);
  }

  // ── Return structured result ───────────────────────────────────────────
  return {
    score: finalScore,
    level: scoreToLevel(finalScore),
    flags,
    encodingTypes: encodingInfo.types,
    decodedPayload: normalizedPayload,
    matchDetails: finalMatches.map(m => ({
      name: m.name,
      category: m.category,
      weight: m.weight,
      description: m.description,
      matchCount: m.matchCount,
      layer: m.layerNote || 'raw-payload',
    })),
    base64Analysis: b64Analysis,
    mixedEncoding: mixedInfo.isMixed,
    decodeDepth: decodeResult.depth,
    rawScore,
    multiplier,
  };
};

module.exports = {
  calculateScore,
  scoreToLevel,
  runAllPatterns,
  testPattern,
  THRESHOLDS,
};

/**
 * ThreatDetector — Encoding Analyzer
 *
 * Core analysis layer that detects, decodes, and inspects encoded payloads.
 * Designed to be crash-safe: malformed encoding never throws.
 */

// ── Keywords that are suspicious when found inside decoded/base64 content ─────
const DANGEROUS_KEYWORDS = [
  'select', 'union', 'drop', 'insert', 'delete', 'update', 'alter', 'exec',
  'script', 'alert', 'eval', 'onerror', 'onload', 'onclick', 'javascript',
  'document', 'cookie', 'passwd', 'shadow', 'etc/', 'cmd', 'bash', 'powershell',
  'wget', 'curl', 'chmod', 'whoami', 'cat ', 'rm ', 'shutdown',
];

// ── Safe decodeURIComponent wrapper ──────────────────────────────────────────

/**
 * Wraps decodeURIComponent to prevent crashes on malformed input.
 * Returns the original string if decoding fails.
 * @param {string} str - Input string
 * @returns {string} Decoded string or original
 */
const safeDecodeURI = (str) => {
  if (typeof str !== 'string') return String(str || '');
  try {
    return decodeURIComponent(str);
  } catch {
    // Malformed encoding — return original
    return str;
  }
};

// ── Multi-layer decode ───────────────────────────────────────────────────────

/**
 * Iteratively decodes a payload up to `maxDepth` levels.
 * Stops early if a round produces no change (fully decoded).
 *
 * @param {string} payload - The raw input
 * @param {number} maxDepth - Maximum decode iterations (default 3)
 * @returns {{ layers: string[], depth: number }} All decoded versions + depth reached
 */
const multiLayerDecode = (payload, maxDepth = 3) => {
  const layers = [payload];
  let current = payload;

  for (let i = 0; i < maxDepth; i++) {
    const decoded = safeDecodeURI(current);
    if (decoded === current) break; // No further decoding possible
    layers.push(decoded);
    current = decoded;
  }

  return {
    layers,
    depth: layers.length - 1, // 0 = no decoding happened
    fullyDecoded: current,
  };
};

// ── Encoding type detection ──────────────────────────────────────────────────

/**
 * Detects which encoding schemes are present in a payload.
 * Returns an array of encoding type labels and a count.
 *
 * @param {string} payload
 * @returns {{ types: string[], count: number }}
 */
const detectEncodingTypes = (payload) => {
  if (typeof payload !== 'string') return { types: [], count: 0 };

  const types = [];

  // URL encoding: %XX
  if (/%[0-9A-Fa-f]{2}/.test(payload)) {
    types.push('URL_ENCODING');
  }

  // Double encoding: %25XX
  if (/%25[0-9A-Fa-f]{2}/.test(payload)) {
    types.push('DOUBLE_ENCODING');
  }

  // Triple encoding: %2525XX
  if (/%2525[0-9A-Fa-f]{2}/.test(payload)) {
    types.push('TRIPLE_ENCODING');
  }

  // Unicode: \uXXXX or %uXXXX
  if (/\\u[0-9A-Fa-f]{4}/i.test(payload) || /%u[0-9A-Fa-f]{4}/i.test(payload)) {
    types.push('UNICODE_ENCODING');
  }

  // Hex: 0xNN or \xNN
  if (/0x[0-9A-Fa-f]{2,}/i.test(payload) || /\\x[0-9A-Fa-f]{2}/i.test(payload)) {
    types.push('HEX_ENCODING');
  }

  // Base64: long A-Za-z0-9+/ blocks with optional padding
  if (/(?:[A-Za-z0-9+/]{4}){5,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?/.test(payload)) {
    types.push('BASE64');
  }

  // HTML entities: &lt; &#60; &#x3C;
  if (/&[a-zA-Z]+;/.test(payload) || /&#x?[0-9A-Fa-f]+;?/.test(payload)) {
    types.push('HTML_ENTITY');
  }

  // Null byte
  if (/%00/.test(payload) || /\x00/.test(payload) || /\\u0000/i.test(payload)) {
    types.push('NULL_BYTE');
  }

  return {
    types,
    count: types.length,
  };
};

// ── Mixed encoding detection ─────────────────────────────────────────────────

/**
 * Checks whether a payload uses 2+ different encoding schemes simultaneously.
 * Mixed encoding is a strong signal of intentional obfuscation.
 *
 * @param {string} payload
 * @returns {{ isMixed: boolean, types: string[], count: number }}
 */
const detectMixedEncoding = (payload) => {
  const { types, count } = detectEncodingTypes(payload);
  return {
    isMixed: count >= 2,
    types,
    count,
  };
};

// ── Base64 inspection ────────────────────────────────────────────────────────

/**
 * Extracts base64 candidates from a payload, decodes them, and checks
 * whether the decoded content contains dangerous keywords.
 *
 * @param {string} payload
 * @returns {{ isSuspicious: boolean, decodedSnippets: string[], matchedKeywords: string[] }}
 */
const isBase64Suspicious = (payload) => {
  if (typeof payload !== 'string') {
    return { isSuspicious: false, decodedSnippets: [], matchedKeywords: [] };
  }

  // Extract base64-looking strings (at least 20 chars)
  const b64Regex = /(?:[A-Za-z0-9+/]{4}){5,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?/g;
  const candidates = payload.match(b64Regex) || [];

  const decodedSnippets = [];
  const matchedKeywords = [];

  for (const candidate of candidates) {
    try {
      const decoded = Buffer.from(candidate, 'base64').toString('utf-8');

      // Check if decoded string looks like readable text (at least 50% printable ASCII)
      const printableRatio = (decoded.match(/[\x20-\x7E]/g) || []).length / decoded.length;
      if (printableRatio < 0.5) continue;

      decodedSnippets.push(decoded.substring(0, 200));

      // Check for dangerous content in decoded string
      const lower = decoded.toLowerCase();
      for (const kw of DANGEROUS_KEYWORDS) {
        if (lower.includes(kw)) {
          matchedKeywords.push(kw);
        }
      }
    } catch {
      // Invalid base64 — skip
    }
  }

  return {
    isSuspicious: matchedKeywords.length > 0,
    decodedSnippets,
    matchedKeywords: [...new Set(matchedKeywords)],
  };
};

// ── HTML entity decoder ──────────────────────────────────────────────────────

/**
 * Decodes common HTML entities to their character equivalents.
 * @param {string} str
 * @returns {string}
 */
const decodeHTMLEntities = (str) => {
  if (typeof str !== 'string') return String(str || '');

  const entityMap = {
    '&lt;': '<', '&gt;': '>', '&amp;': '&', '&quot;': '"',
    '&apos;': "'", '&nbsp;': ' ', '&tab;': '\t',
  };

  // Named entities
  let result = str.replace(/&[a-zA-Z]+;/g, (match) => entityMap[match.toLowerCase()] || match);

  // Decimal entities: &#60;
  result = result.replace(/&#(\d{1,5});?/g, (_, code) => {
    const num = parseInt(code, 10);
    return num < 0x10FFFF ? String.fromCodePoint(num) : _;
  });

  // Hex entities: &#x3C;
  result = result.replace(/&#x([0-9A-Fa-f]{1,4});?/gi, (_, hex) => {
    const num = parseInt(hex, 16);
    return num < 0x10FFFF ? String.fromCodePoint(num) : _;
  });

  return result;
};

// ── Defanged URL normalization ───────────────────────────────────────────────

/**
 * Normalizes defanged/obfuscated URLs and payloads.
 * Threat actors use these patterns to bypass WAFs:
 *   hxxp  → http      (protocol obfuscation)
 *   [.]   → .         (domain obfuscation)
 *   [://] → ://       (protocol separator obfuscation)
 *   [:]   → :         (port obfuscation)
 *   {.}   → .         (alternate domain obfuscation)
 *   (.)   → .         (alternate domain obfuscation)
 *
 * @param {string} str
 * @returns {string}
 */
const normalizeDefanged = (str) => {
  if (typeof str !== 'string') return String(str || '');

  let result = str;

  // Protocol obfuscation: hxxp(s) → http(s)
  result = result.replace(/hxxps?/gi, (m) => m.toLowerCase().replace('xx', 'tt'));

  // Bracket-based obfuscation for dots, colons, slashes
  result = result.replace(/\[\.]|\{\.\}|\(\.\.?\)/g, '.');       // [.], {.}, (.) → .
  result = result.replace(/\[:\/\/\]/g, '://');                   // [://] → ://
  result = result.replace(/\[:\]/g, ':');                          // [:] → :
  result = result.replace(/\[\/\]/g, '/');                        // [/] → /
  result = result.replace(/\[at\]/gi, '@');                       // [at] → @
  result = result.replace(/\[dot\]/gi, '.');                      // [dot] → .

  return result;
};

// ── Full payload normalization ───────────────────────────────────────────────

/**
 * Normalizes a payload by applying all known decodings.
 * Returns the maximally-decoded version for pattern matching.
 *
 * Order: URL decode → Defang normalize → HTML entity decode → Hex → Unicode
 *
 * @param {string} payload
 * @returns {string} Normalized payload
 */
const normalizePayload = (payload) => {
  if (typeof payload !== 'string') return String(payload || '');

  // Step 1: Multi-layer URL decode
  const { fullyDecoded } = multiLayerDecode(payload);

  // Step 2: Defanged URL normalization (hxxp, [.], [://], etc.)
  const defangedNormalized = normalizeDefanged(fullyDecoded);

  // Step 3: HTML entity decode
  const htmlDecoded = decodeHTMLEntities(defangedNormalized);

  // Step 4: Hex escape decode (\x41 → A)
  const hexDecoded = htmlDecoded.replace(/\\x([0-9A-Fa-f]{2})/gi, (_, hex) =>
    String.fromCharCode(parseInt(hex, 16))
  );

  // Step 5: Unicode escape decode (\u0041 → A)
  const unicodeDecoded = hexDecoded.replace(/\\u([0-9A-Fa-f]{4})/gi, (_, code) =>
    String.fromCharCode(parseInt(code, 16))
  );

  return unicodeDecoded;
};

module.exports = {
  safeDecodeURI,
  multiLayerDecode,
  detectEncodingTypes,
  detectMixedEncoding,
  isBase64Suspicious,
  decodeHTMLEntities,
  normalizeDefanged,
  normalizePayload,
  DANGEROUS_KEYWORDS,
};

/**
 * ThreatDetector — Pattern Definitions
 * 
 * Organized regex patterns grouped by attack category.
 * Each entry:
 *   name    — human-readable identifier (used in flags)
 *   pattern — compiled RegExp (case-insensitive where appropriate)
 *   weight  — score contribution (1–30)
 *   category — attack family for grouping
 *
 * Weight guide:
 *   1-5   = informational / low confidence
 *   6-15  = moderate signal
 *   16-25 = strong signal
 *   26-30 = critical / near-certain malicious
 */

// ── URL Encoding Patterns ────────────────────────────────────────────────────

const URL_ENCODING_PATTERNS = [
  {
    name: 'url-encoded-single-quote',
    pattern: /%27/gi,
    weight: 10,
    category: 'URL_ENCODING',
    description: 'URL-encoded single quote (\')',
  },
  {
    name: 'url-encoded-double-quote',
    pattern: /%22/gi,
    weight: 8,
    category: 'URL_ENCODING',
    description: 'URL-encoded double quote (")',
  },
  {
    name: 'url-encoded-lt',
    pattern: /%3C/gi,
    weight: 12,
    category: 'URL_ENCODING',
    description: 'URL-encoded less-than (<)',
  },
  {
    name: 'url-encoded-gt',
    pattern: /%3E/gi,
    weight: 10,
    category: 'URL_ENCODING',
    description: 'URL-encoded greater-than (>)',
  },
  {
    name: 'url-encoded-open-paren',
    pattern: /%28/gi,
    weight: 6,
    category: 'URL_ENCODING',
    description: 'URL-encoded open parenthesis',
  },
  {
    name: 'url-encoded-close-paren',
    pattern: /%29/gi,
    weight: 6,
    category: 'URL_ENCODING',
    description: 'URL-encoded close parenthesis',
  },
  {
    name: 'url-encoded-semicolon',
    pattern: /%3B/gi,
    weight: 8,
    category: 'URL_ENCODING',
    description: 'URL-encoded semicolon (;)',
  },
  {
    name: 'url-encoded-pipe',
    pattern: /%7C/gi,
    weight: 7,
    category: 'URL_ENCODING',
    description: 'URL-encoded pipe (|)',
  },
  {
    name: 'url-encoded-backtick',
    pattern: /%60/gi,
    weight: 10,
    category: 'URL_ENCODING',
    description: 'URL-encoded backtick (`)',
  },
  {
    name: 'general-url-encoding',
    pattern: /(%[0-9A-Fa-f]{2}){3,}/g,
    weight: 5,
    category: 'URL_ENCODING',
    description: 'Multiple consecutive URL-encoded characters',
  },
];

// ── Double Encoding Patterns (High Severity) ────────────────────────────────

const DOUBLE_ENCODING_PATTERNS = [
  {
    name: 'double-encoded-single-quote',
    pattern: /%2527/gi,
    weight: 25,
    category: 'DOUBLE_ENCODING',
    description: 'Double-encoded single quote — strong evasion signal',
  },
  {
    name: 'double-encoded-lt',
    pattern: /%253[Cc]/gi,
    weight: 25,
    category: 'DOUBLE_ENCODING',
    description: 'Double-encoded less-than — XSS evasion',
  },
  {
    name: 'double-encoded-gt',
    pattern: /%253[Ee]/gi,
    weight: 22,
    category: 'DOUBLE_ENCODING',
    description: 'Double-encoded greater-than',
  },
  {
    name: 'double-encoded-space',
    pattern: /%2520/gi,
    weight: 15,
    category: 'DOUBLE_ENCODING',
    description: 'Double-encoded space',
  },
  {
    name: 'double-encoded-slash',
    pattern: /%252[Ff]/gi,
    weight: 18,
    category: 'DOUBLE_ENCODING',
    description: 'Double-encoded forward slash — path traversal evasion',
  },
  {
    name: 'double-encoded-percent',
    pattern: /%25[0-9A-Fa-f]{2}/g,
    weight: 20,
    category: 'DOUBLE_ENCODING',
    description: 'Generic double-encoding pattern (%25xx)',
  },
];

// ── Unicode Encoding Patterns ────────────────────────────────────────────────

const UNICODE_ENCODING_PATTERNS = [
  {
    name: 'unicode-escape-sequence',
    pattern: /\\u[0-9A-Fa-f]{4}/gi,
    weight: 12,
    category: 'UNICODE_ENCODING',
    description: 'JavaScript Unicode escape (\\uXXXX)',
  },
  {
    name: 'iis-unicode-encoding',
    pattern: /%u[0-9A-Fa-f]{4}/gi,
    weight: 18,
    category: 'UNICODE_ENCODING',
    description: 'IIS-style Unicode encoding (%uXXXX) — often used in WAF evasion',
  },
  {
    name: 'unicode-fullwidth-chars',
    pattern: /[\uFF01-\uFF5E]/g,
    weight: 14,
    category: 'UNICODE_ENCODING',
    description: 'Full-width Unicode characters — obfuscation technique',
  },
];

// ── Hex Encoding Patterns ────────────────────────────────────────────────────

const HEX_ENCODING_PATTERNS = [
  {
    name: 'hex-literal',
    pattern: /0x[0-9A-Fa-f]{2,}/gi,
    weight: 10,
    category: 'HEX_ENCODING',
    description: 'Hex literal (0xNN...) — common in SQL injection',
  },
  {
    name: 'hex-escape-sequence',
    pattern: /\\x[0-9A-Fa-f]{2}/gi,
    weight: 12,
    category: 'HEX_ENCODING',
    description: 'Hex escape sequence (\\xNN)',
  },
  {
    name: 'css-hex-escape',
    pattern: /\\[0-9A-Fa-f]{1,6}\s?/g,
    weight: 8,
    category: 'HEX_ENCODING',
    description: 'CSS-style hex escape',
  },
];

// ── Base64 Patterns ──────────────────────────────────────────────────────────

const BASE64_PATTERNS = [
  {
    name: 'base64-long-string',
    pattern: /(?:[A-Za-z0-9+/]{4}){5,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?/g,
    weight: 8,
    category: 'BASE64_PAYLOAD',
    description: 'Potential base64-encoded payload (≥20 chars)',
  },
  {
    name: 'base64-atob-usage',
    pattern: /atob\s*\(/gi,
    weight: 15,
    category: 'BASE64_PAYLOAD',
    description: 'JavaScript atob() call — runtime base64 decoding',
  },
  {
    name: 'base64-btoa-usage',
    pattern: /btoa\s*\(/gi,
    weight: 10,
    category: 'BASE64_PAYLOAD',
    description: 'JavaScript btoa() call — base64 encoding',
  },
];

// ── HTML Entity Encoding ─────────────────────────────────────────────────────

const HTML_ENTITY_PATTERNS = [
  {
    name: 'html-entity-named',
    pattern: /&(lt|gt|amp|quot|apos|nbsp);/gi,
    weight: 6,
    category: 'HTML_ENTITY',
    description: 'Named HTML entity',
  },
  {
    name: 'html-entity-decimal',
    pattern: /&#\d{1,5};/g,
    weight: 10,
    category: 'HTML_ENTITY',
    description: 'Decimal HTML entity (&#NNN;)',
  },
  {
    name: 'html-entity-hex',
    pattern: /&#x[0-9A-Fa-f]{1,4};/gi,
    weight: 18,
    category: 'HTML_ENTITY',
    description: 'Hexadecimal HTML entity (&#xNN;)',
  },
  {
    name: 'html-entity-without-semicolon',
    pattern: /&#\d{2,5}(?!;)/g,
    weight: 20,
    category: 'HTML_ENTITY',
    description: 'HTML entity without trailing semicolon — evasion technique',
  },
];

// ── Null Byte Injection (Critical) ──────────────────────────────────────────

const NULL_BYTE_PATTERNS = [
  {
    name: 'null-byte-url-encoded',
    pattern: /%00/g,
    weight: 28,
    category: 'NULL_BYTE',
    description: 'URL-encoded null byte — can truncate strings and bypass filters',
  },
  {
    name: 'null-byte-literal',
    pattern: /\x00/g,
    weight: 30,
    category: 'NULL_BYTE',
    description: 'Literal null byte in payload',
  },
  {
    name: 'null-byte-unicode',
    pattern: /\\u0000/gi,
    weight: 28,
    category: 'NULL_BYTE',
    description: 'Unicode null byte',
  },
  {
    name: 'null-byte-hex',
    pattern: /\\x00/gi,
    weight: 28,
    category: 'NULL_BYTE',
    description: 'Hex-escaped null byte',
  },
];

// ── Encoded SQL Injection ───────────────────────────────────────────────────

const ENCODED_SQLI_PATTERNS = [
  {
    name: 'encoded-sql-or-1=1',
    pattern: /(%27|')\s*(%4F%52|OR)\s*\d+\s*(%3D|=)\s*\d+/gi,
    weight: 30,
    category: 'ENCODED_SQLI',
    description: 'Encoded OR 1=1 pattern',
  },
  {
    name: 'encoded-sql-union-select',
    pattern: /(%55%4E%49%4F%4E|UNION)\s+(%53%45%4C%45%43%54|SELECT)/gi,
    weight: 28,
    category: 'ENCODED_SQLI',
    description: 'Encoded UNION SELECT',
  },
  {
    name: 'encoded-sql-drop',
    pattern: /(%44%52%4F%50|DROP)\s+(%54%41%42%4C%45|TABLE)/gi,
    weight: 28,
    category: 'ENCODED_SQLI',
    description: 'Encoded DROP TABLE',
  },
  {
    name: 'encoded-sql-comment-dash',
    pattern: /%2D%2D/gi,
    weight: 12,
    category: 'ENCODED_SQLI',
    description: 'Encoded SQL comment (--)',
  },
  {
    name: 'encoded-sql-comment-hash',
    pattern: /%23/gi,
    weight: 8,
    category: 'ENCODED_SQLI',
    description: 'Encoded hash (#) — MySQL comment',
  },
  {
    name: 'encoded-sql-semicolon-keyword',
    pattern: /%3B\s*(DROP|DELETE|INSERT|UPDATE|ALTER|EXEC)/gi,
    weight: 28,
    category: 'ENCODED_SQLI',
    description: 'Encoded semicolon followed by SQL keyword',
  },
];

// ── Encoded XSS Patterns ───────────────────────────────────────────────────

const ENCODED_XSS_PATTERNS = [
  {
    name: 'encoded-script-tag',
    pattern: /%3[Cc]script%3[Ee]/gi,
    weight: 30,
    category: 'ENCODED_XSS',
    description: 'URL-encoded <script> tag',
  },
  {
    name: 'encoded-img-onerror',
    pattern: /%3[Cc]img[^>]*on\w+\s*%3[Dd]/gi,
    weight: 22,
    category: 'ENCODED_XSS',
    description: 'Encoded <img> with event handler',
  },
  {
    name: 'encoded-event-handler',
    pattern: /on(error|load|click|mouseover|focus|blur)\s*(%3[Dd]|=)/gi,
    weight: 18,
    category: 'ENCODED_XSS',
    description: 'Event handler attribute with encoded equals',
  },
  {
    name: 'encoded-javascript-proto',
    pattern: /(%6A%61%76%61%73%63%72%69%70%74|javascript)\s*(%3[Aa]|:)/gi,
    weight: 25,
    category: 'ENCODED_XSS',
    description: 'Encoded javascript: protocol',
  },
  {
    name: 'encoded-alert-call',
    pattern: /alert\s*(%28|%2528|\()/gi,
    weight: 25,
    category: 'ENCODED_XSS',
    description: 'alert() with encoded parenthesis',
  },
  {
    name: 'encoded-eval-call',
    pattern: /eval\s*(%28|%2528|\()/gi,
    weight: 22,
    category: 'ENCODED_XSS',
    description: 'eval() with encoded parenthesis — code execution',
  },
  {
    name: 'encoded-svg-onload',
    pattern: /%3[Cc]svg[^>]*onload/gi,
    weight: 22,
    category: 'ENCODED_XSS',
    description: 'Encoded <svg> with onload handler',
  },
  {
    name: 'encoded-iframe',
    pattern: /%3[Cc]iframe/gi,
    weight: 20,
    category: 'ENCODED_XSS',
    description: 'Encoded <iframe> tag',
  },
];

// ── Over-Encoded / Obfuscation Patterns ─────────────────────────────────────

const OBFUSCATION_PATTERNS = [
  {
    name: 'triple-encoding',
    pattern: /%25252[0-9A-Fa-f]/gi,
    weight: 30,
    category: 'OVER_ENCODING',
    description: 'Triple encoding detected — extreme evasion attempt',
  },
  {
    name: 'string-fromcharcode',
    pattern: /String\.fromCharCode/gi,
    weight: 20,
    category: 'OBFUSCATION',
    description: 'String.fromCharCode() — runtime character construction',
  },
  {
    name: 'char-code-sequence',
    pattern: /fromCharCode\s*\(\s*\d+(\s*,\s*\d+){2,}/gi,
    weight: 22,
    category: 'OBFUSCATION',
    description: 'fromCharCode with multiple numeric arguments',
  },
  {
    name: 'concat-obfuscation',
    pattern: /['"][^'"]{0,3}['"]\s*\+\s*['"][^'"]{0,3}['"]/g,
    weight: 8,
    category: 'OBFUSCATION',
    description: 'String concatenation obfuscation (splitting keywords)',
  },
  {
    name: 'document-cookie-access',
    pattern: /document\s*(\.|%2[Ee])\s*cookie/gi,
    weight: 18,
    category: 'OBFUSCATION',
    description: 'document.cookie access — potential data exfiltration',
  },
  {
    name: 'document-write',
    pattern: /document\s*(\.|%2[Ee])\s*write/gi,
    weight: 16,
    category: 'OBFUSCATION',
    description: 'document.write — DOM manipulation',
  },
];

// ── Command Injection Patterns ──────────────────────────────────────────────

const COMMAND_INJECTION_PATTERNS = [
  {
    name: 'cmd-dollar-paren',
    pattern: /\$\([^)]+\)/g,
    weight: 28,
    category: 'COMMAND_INJECTION',
    description: 'Shell command substitution $(...) — executes embedded command',
  },
  {
    name: 'cmd-backtick-exec',
    pattern: /`[^`]+`/g,
    weight: 25,
    category: 'COMMAND_INJECTION',
    description: 'Backtick command execution `...`',
  },
  {
    name: 'cmd-semicolon-command',
    pattern: /;\s*(ls|cat|pwd|wget|curl|bash|sh|cmd|whoami|id|uname|rm|chmod|chown|nc|ncat|python|perl|ruby|php|node)\b/gi,
    weight: 28,
    category: 'COMMAND_INJECTION',
    description: 'Semicolon followed by shell command',
  },
  {
    name: 'cmd-and-chain',
    pattern: /&&\s*(ls|cat|pwd|wget|curl|bash|sh|cmd|whoami|id|uname|rm|chmod|chown|nc|python|perl|ruby|php|node)\b/gi,
    weight: 28,
    category: 'COMMAND_INJECTION',
    description: 'AND-chained shell command (&&)',
  },
  {
    name: 'cmd-or-chain',
    pattern: /\|\|\s*(ls|cat|pwd|wget|curl|bash|sh|cmd|whoami|id|uname|rm|chmod|chown|nc|python|perl|ruby|php|node)\b/gi,
    weight: 25,
    category: 'COMMAND_INJECTION',
    description: 'OR-chained shell command (||)',
  },
  {
    name: 'cmd-pipe',
    pattern: /\|\s*(cat|grep|awk|sed|head|tail|sort|uniq|wc|tee|xargs|base64|nc)\b/gi,
    weight: 22,
    category: 'COMMAND_INJECTION',
    description: 'Pipe to data-exfiltration command',
  },
  {
    name: 'cmd-encoded-dollar-paren',
    pattern: /%24%28[^)]*%29/gi,
    weight: 30,
    category: 'COMMAND_INJECTION',
    description: 'URL-encoded $() command substitution — strong evasion signal',
  },
  {
    name: 'cmd-encoded-backtick',
    pattern: /%60[^%]*%60/gi,
    weight: 28,
    category: 'COMMAND_INJECTION',
    description: 'URL-encoded backtick execution',
  },
  {
    name: 'cmd-encoded-semicolon-cmd',
    pattern: /%3[Bb]\s*(ls|cat|pwd|wget|curl|bash|sh|cmd|whoami|rm)\b/gi,
    weight: 25,
    category: 'COMMAND_INJECTION',
    description: 'URL-encoded semicolon + shell command',
  },
  {
    name: 'cmd-encoded-pipe',
    pattern: /%7[Cc]\s*(cat|grep|bash|sh|python|perl|nc)\b/gi,
    weight: 22,
    category: 'COMMAND_INJECTION',
    description: 'URL-encoded pipe + shell command',
  },
  {
    name: 'cmd-etc-passwd',
    pattern: /\/etc\/passwd|\/etc\/shadow/gi,
    weight: 25,
    category: 'COMMAND_INJECTION',
    description: 'Direct reference to sensitive system files',
  },
  {
    name: 'cmd-reverse-shell',
    pattern: /\b(nc|ncat|netcat)\s+(-e|-c|--exec)/gi,
    weight: 30,
    category: 'COMMAND_INJECTION',
    description: 'Reverse shell attempt via netcat',
  },
  {
    name: 'cmd-curl-wget-download',
    pattern: /(curl|wget)\s+[^\s]*\s*\|/gi,
    weight: 25,
    category: 'COMMAND_INJECTION',
    description: 'Download-and-pipe pattern (remote code execution)',
  },
];

// ── Defanged URL / Obfuscated URL Patterns ──────────────────────────────────

const DEFANGED_URL_PATTERNS = [
  {
    name: 'defanged-hxxp-protocol',
    pattern: /hxxps?/gi,
    weight: 18,
    category: 'DEFANGED_URL',
    description: 'Defanged protocol (hxxp/hxxps) — intentional URL obfuscation',
  },
  {
    name: 'defanged-bracket-dot',
    pattern: /\[\.\]/g,
    weight: 15,
    category: 'DEFANGED_URL',
    description: 'Defanged dot [.] — domain obfuscation',
  },
  {
    name: 'defanged-bracket-protocol',
    pattern: /\[:\/\/\]/g,
    weight: 18,
    category: 'DEFANGED_URL',
    description: 'Defanged protocol separator [://]',
  },
  {
    name: 'defanged-bracket-colon',
    pattern: /\[:\]/g,
    weight: 12,
    category: 'DEFANGED_URL',
    description: 'Defanged colon [:] — port/protocol obfuscation',
  },
  {
    name: 'defanged-bracket-at',
    pattern: /\[at\]/gi,
    weight: 10,
    category: 'DEFANGED_URL',
    description: 'Defanged at-sign [at] — email/URL obfuscation',
  },
  {
    name: 'defanged-bracket-dot-word',
    pattern: /\[dot\]/gi,
    weight: 15,
    category: 'DEFANGED_URL',
    description: 'Defanged dot [dot] — domain obfuscation',
  },
  {
    name: 'defanged-curly-dot',
    pattern: /\{\.\}/g,
    weight: 15,
    category: 'DEFANGED_URL',
    description: 'Curly-bracket dot {.} — alternate domain obfuscation',
  },
];

// ── Export all patterns grouped ──────────────────────────────────────────────

const ALL_PATTERNS = [
  ...URL_ENCODING_PATTERNS,
  ...DOUBLE_ENCODING_PATTERNS,
  ...UNICODE_ENCODING_PATTERNS,
  ...HEX_ENCODING_PATTERNS,
  ...BASE64_PATTERNS,
  ...HTML_ENTITY_PATTERNS,
  ...NULL_BYTE_PATTERNS,
  ...ENCODED_SQLI_PATTERNS,
  ...ENCODED_XSS_PATTERNS,
  ...OBFUSCATION_PATTERNS,
  ...COMMAND_INJECTION_PATTERNS,
  ...DEFANGED_URL_PATTERNS,
];

module.exports = {
  ALL_PATTERNS,
  URL_ENCODING_PATTERNS,
  DOUBLE_ENCODING_PATTERNS,
  UNICODE_ENCODING_PATTERNS,
  HEX_ENCODING_PATTERNS,
  BASE64_PATTERNS,
  HTML_ENTITY_PATTERNS,
  NULL_BYTE_PATTERNS,
  ENCODED_SQLI_PATTERNS,
  ENCODED_XSS_PATTERNS,
  OBFUSCATION_PATTERNS,
  COMMAND_INJECTION_PATTERNS,
  DEFANGED_URL_PATTERNS,
};

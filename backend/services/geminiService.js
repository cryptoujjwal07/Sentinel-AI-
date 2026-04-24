/**
 * Gemini AI Service
 * Core intelligence layer — analyzes HTTP requests for threats using Google Gemini
 */

const { GoogleGenerativeAI } = require('@google/generative-ai');

// Initialize Gemini client
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

/**
 * Builds the highly-optimized WAF analysis prompt
 * Engineered for speed, accuracy, and structured JSON output
 */
const buildWAFPrompt = (requestData) => {
  return `You are SentinelAI, an expert cybersecurity AI and Web Application Firewall (WAF) engine.
Analyze the following HTTP request for security threats.

## REQUEST DATA:
${JSON.stringify(requestData, null, 2)}

## YOUR TASK:
Perform a comprehensive security analysis. Detect ALL of the following:
- SQL Injection (SQLi): UNION, SELECT, DROP, INSERT, OR 1=1, --, ;, etc.
- Cross-Site Scripting (XSS): <script>, onerror, alert(), eval(), javascript:, etc.
- Cross-Site Request Forgery (CSRF): Missing/mismatched tokens, suspicious origins
- Path Traversal: ../../../, %2e%2e%2f, etc.
- Command Injection: ;, &&, ||, backticks, system commands like ls, cat, wget, curl
- Header Injection: CRLF injection, Host header attacks
- Suspicious Bots: Automated scanner signatures in User-Agent
- Brute Force patterns: Repeated auth attempts

## ANALYSIS RULES:
1. Check ALL fields: URL path, query params, body, and headers
2. URL-decode and base64-decode values before checking
3. Be sensitive to obfuscation (hex encoding, case variation, comments)
4. Consider the combination of signals, not just individual fields
5. A SUSPICIOUS rating means unusual but not definitively malicious
6. A MALICIOUS rating means clear attack indicators are present

## OUTPUT FORMAT (respond with VALID JSON ONLY, no markdown):
{
  "classification": "SAFE" | "SUSPICIOUS" | "MALICIOUS",
  "confidence": <integer 0-100>,
  "attack_type": "SQL_INJECTION" | "XSS" | "CSRF" | "PATH_TRAVERSAL" | "COMMAND_INJECTION" | "SUSPICIOUS_HEADERS" | "BRUTE_FORCE" | "NONE" | "UNKNOWN",
  "reason": "<concise single sentence explanation>",
  "indicators": ["<indicator1>", "<indicator2>"],
  "recommendation": "BLOCK" | "MONITOR" | "ALLOW"
}`;
};

/**
 * Analyzes a request using Gemini AI
 * @param {Object} requestData - Extracted request information
 * @returns {Object} AI analysis result
 */
const analyzeRequest = async (requestData) => {
  try {
    const model = genAI.getGenerativeModel({
      model: process.env.GEMINI_MODEL || 'gemini-1.5-flash',
      generationConfig: {
        temperature: 0.1,       // Low temperature for consistent, deterministic responses
        topK: 1,
        topP: 0.95,
        maxOutputTokens: 512,   // Keep responses concise and fast
      },
    });

    const prompt = buildWAFPrompt(requestData);
    const result = await model.generateContent(prompt);
    const responseText = result.response.text().trim();

    // Strip markdown code blocks if Gemini wraps the JSON
    const cleanedText = responseText
      .replace(/^```json\s*/i, '')
      .replace(/^```\s*/i, '')
      .replace(/\s*```$/i, '')
      .trim();

    const parsed = JSON.parse(cleanedText);

    // Validate required fields
    const validClassifications = ['SAFE', 'SUSPICIOUS', 'MALICIOUS'];
    if (!validClassifications.includes(parsed.classification)) {
      parsed.classification = 'SUSPICIOUS';
    }

    return {
      success: true,
      classification: parsed.classification || 'SUSPICIOUS',
      confidence: Math.min(100, Math.max(0, parseInt(parsed.confidence) || 50)),
      attackType: parsed.attack_type || 'UNKNOWN',
      reason: parsed.reason || 'AI analysis completed',
      indicators: Array.isArray(parsed.indicators) ? parsed.indicators : [],
      recommendation: parsed.recommendation || 'MONITOR',
    };

  } catch (error) {
    console.error('[GeminiService] Analysis failed:', error.message);

    // Fallback: pattern-based detection when AI is unavailable
    return fallbackPatternDetection(requestData);
  }
};

/**
 * Rule-based fallback when Gemini API is unavailable.
 * Uses the ThreatDetector engine for encoding-aware analysis first,
 * then falls back to basic regex patterns.
 */
const fallbackPatternDetection = (requestData) => {
  // ── Try ThreatDetector first (encoding-aware, much more powerful) ──────
  try {
    const threatDetector = require('./threatDetector');
    const payloadStr = JSON.stringify(requestData);
    const tdResult = threatDetector.analyze(payloadStr);

    if (tdResult.classification !== 'SAFE') {
      return {
        success: true,
        classification: tdResult.classification,
        confidence: Math.min(95, tdResult.score),
        attackType: tdResult.attackType || 'ENCODED_ATTACK',
        reason: `[ThreatDetector Fallback] ${tdResult.reason}`,
        indicators: tdResult.flags.slice(0, 5),
        recommendation: tdResult.classification === 'MALICIOUS' ? 'BLOCK' : 'MONITOR',
      };
    }
  } catch (e) {
    // ThreatDetector not available — continue with basic patterns
    console.warn('[GeminiService] ThreatDetector fallback unavailable:', e.message);
  }

  // ── Basic regex fallback (original patterns) ──────────────────────────────
  const payload = JSON.stringify(requestData).toLowerCase();

  // SQL Injection patterns
  const sqlPatterns = [
    /(\bselect\b|\bunion\b|\bdrop\b|\binsert\b|\bdelete\b|\bupdate\b)/i,
    /(--|;|\/\*|\*\/)/,
    /(\bor\b|\band\b)\s+[\d'"]+=[\d'"]+/i,
    /'\s*(or|and)\s+'?\d/i,
  ];

  // XSS patterns
  const xssPatterns = [
    /<script[\s>]/i,
    /javascript:/i,
    /on\w+\s*=/i,
    /eval\s*\(/i,
    /alert\s*\(/i,
    /<iframe/i,
  ];

  // Path traversal patterns
  const pathPatterns = [/\.\.[\/\\]/, /%2e%2e/i, /%252e/i];

  // Command injection patterns
  const cmdPatterns = [/;\s*(ls|cat|pwd|wget|curl|bash|sh|cmd)\b/i, /`[^`]+`/, /\|\|?\s*\w/];

  for (const pattern of sqlPatterns) {
    if (pattern.test(payload)) {
      return {
        success: true,
        classification: 'MALICIOUS',
        confidence: 85,
        attackType: 'SQL_INJECTION',
        reason: 'SQL injection pattern detected in fallback analysis',
        indicators: ['SQL keyword detected'],
        recommendation: 'BLOCK',
      };
    }
  }

  for (const pattern of xssPatterns) {
    if (pattern.test(payload)) {
      return {
        success: true,
        classification: 'MALICIOUS',
        confidence: 85,
        attackType: 'XSS',
        reason: 'XSS pattern detected in fallback analysis',
        indicators: ['Script injection pattern detected'],
        recommendation: 'BLOCK',
      };
    }
  }

  for (const pattern of pathPatterns) {
    if (pattern.test(payload)) {
      return {
        success: true,
        classification: 'SUSPICIOUS',
        confidence: 75,
        attackType: 'PATH_TRAVERSAL',
        reason: 'Path traversal pattern detected in fallback analysis',
        indicators: ['Directory traversal sequence detected'],
        recommendation: 'MONITOR',
      };
    }
  }

  for (const pattern of cmdPatterns) {
    if (pattern.test(payload)) {
      return {
        success: true,
        classification: 'MALICIOUS',
        confidence: 80,
        attackType: 'COMMAND_INJECTION',
        reason: 'Command injection pattern detected in fallback analysis',
        indicators: ['Shell command pattern detected'],
        recommendation: 'BLOCK',
      };
    }
  }

  return {
    success: false, // Indicates AI was unavailable
    classification: 'SAFE',
    confidence: 50,
    attackType: 'NONE',
    reason: 'Fallback analysis: no obvious threats detected',
    indicators: [],
    recommendation: 'ALLOW',
  };
};

/**
 * Analyzes a raw payload string (for the scanner endpoint)
 */
const analyzePayload = async (payload, context = '') => {
  const requestData = {
    method: 'SCAN',
    path: '/scanner/test',
    queryParams: { payload },
    requestBody: { payload, context },
    headers: { 'user-agent': 'SentinelAI-Scanner' },
    ipAddress: '127.0.0.1',
  };
  return analyzeRequest(requestData);
};

module.exports = { analyzeRequest, analyzePayload, fallbackPatternDetection };

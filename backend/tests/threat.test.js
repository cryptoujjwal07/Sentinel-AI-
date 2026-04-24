/**
 * ThreatDetector Unit Tests
 * Tests the core detection logic — no database or API needed
 */

const threatDetector = require('../services/threatDetector');

describe('ThreatDetector Service', () => {

  // ── Safe Payloads (should NOT be flagged) ──────────────────────────────

  describe('Safe Payloads', () => {
    test('normal text should be SAFE', () => {
      const result = threatDetector.analyze('Hello World');
      expect(result.classification).toBe('SAFE');
      expect(result.score).toBe(0);
    });

    test('normal query params should be SAFE', () => {
      const result = threatDetector.analyze('search=laptop&page=2');
      expect(result.classification).toBe('SAFE');
      expect(result.score).toBeLessThan(30);
    });

    test('normal URL should be SAFE', () => {
      const result = threatDetector.analyze('https://github.com/user/repo');
      expect(result.classification).toBe('SAFE');
    });

    test('empty string should be SAFE', () => {
      const result = threatDetector.analyze('');
      expect(result.classification).toBe('SAFE');
    });
  });

  // ── Command Injection ──────────────────────────────────────────────────

  describe('Command Injection Detection', () => {
    test('should detect $() command substitution', () => {
      const result = threatDetector.analyze('$(cat /etc/passwd)');
      expect(result.classification).toBe('MALICIOUS');
      expect(result.attackType).toBe('COMMAND_INJECTION');
    });

    test('should detect backtick execution', () => {
      const result = threatDetector.analyze('`whoami`');
      expect(result.classification).toBe('MALICIOUS');
    });

    test('should detect semicolon + shell command', () => {
      const result = threatDetector.analyze('; ls -la');
      expect(result.classification).toBe('MALICIOUS');
    });

    test('should detect && chain', () => {
      const result = threatDetector.analyze('&& rm -rf /');
      expect(result.classification).toBe('MALICIOUS');
    });

    test('should detect encoded $() injection', () => {
      const result = threatDetector.analyze('%24%28cat%20%2Fetc%2Fpasswd%29');
      expect(result.classification).toBe('MALICIOUS');
      expect(result.score).toBeGreaterThanOrEqual(70);
    });
  });

  // ── Defanged URL + Obfuscation ─────────────────────────────────────────

  describe('Defanged URL & Obfuscation Detection', () => {
    test('should detect the exact payload from the bug report', () => {
      const result = threatDetector.analyze(
        'hxxps%5B://%5Dgithub%5B.%5Dcom/?q=$(cat%20file)'
      );
      expect(result.classification).toBe('MALICIOUS');
      expect(result.score).toBeGreaterThanOrEqual(70);
      expect(result.decodedPayload).toContain('https://github.com');
    });

    test('should flag defanged malware URL as SUSPICIOUS', () => {
      const result = threatDetector.analyze('hxxps://malware[.]com/payload');
      expect(result.classification).toBe('SUSPICIOUS');
    });
  });

  // ── SQL Injection (Encoded) ────────────────────────────────────────────

  describe('SQL Injection Detection', () => {
    test('should detect encoded OR 1=1', () => {
      const result = threatDetector.analyze("%27%20OR%201%3D1%20--");
      expect(result.classification).toBe('MALICIOUS');
      expect(result.attackType).toBe('SQL_INJECTION');
    });

    test('should detect encoded DROP TABLE', () => {
      const result = threatDetector.analyze("%27%3B%20DROP%20TABLE%20users%3B--");
      expect(result.classification).toBe('MALICIOUS');
    });
  });

  // ── XSS (Encoded) ─────────────────────────────────────────────────────

  describe('XSS Detection', () => {
    test('should detect encoded <script> tag', () => {
      const result = threatDetector.analyze("%3Cscript%3Ealert(1)%3C/script%3E");
      expect(result.classification).toBe('MALICIOUS');
      expect(result.attackType).toBe('XSS');
    });

    test('should detect HTML entity encoded XSS', () => {
      const result = threatDetector.analyze("&lt;script&gt;alert(1)&lt;/script&gt;");
      expect(result.classification).toBe('MALICIOUS');
    });

    test('should detect document.cookie exfiltration', () => {
      const result = threatDetector.analyze("%3Cscript%3Edocument.cookie%3C/script%3E");
      expect(result.classification).toBe('MALICIOUS');
    });
  });

  // ── Built-in Test Suite ────────────────────────────────────────────────

  describe('Built-in Test Suite', () => {
    const testCases = threatDetector.getTestSuite();

    test('should have at least 20 test cases', () => {
      expect(testCases.length).toBeGreaterThanOrEqual(20);
    });

    test.each(testCases)(
      '#$id $name → $expectedClassification',
      (tc) => {
        const result = threatDetector.analyze(tc.payload);
        expect(result.classification).toBe(tc.expectedClassification);
      }
    );
  });
});

/**
 * API Endpoint Tests
 * Uses Supertest to test Express routes without starting the server.
 * 
 * NOTE: Protected routes require JWT auth.
 * These tests verify that:
 *   1. Unprotected routes (health, threat-detector) work correctly
 *   2. Protected routes reject requests without auth tokens
 */

const request = require('supertest');
const app = require('../server');

describe('API Endpoints', () => {

  // ── Health Check (no auth required) ────────────────────────────────────

  describe('GET /health', () => {
    test('should return 200 with OK status', async () => {
      const res = await request(app).get('/health');

      expect(res.status).toBe(200);
      expect(res.body.status).toBe('OK');
      expect(res.body.message).toContain('SentinelAI');
      expect(res.body).toHaveProperty('timestamp');
      expect(res.body).toHaveProperty('uptime');
    });
  });

  // ── Threat Detector API (public test harness) ──────────────────────────

  describe('POST /api/threat-detector/analyze', () => {
    test('should detect malicious payload $(cat file)', async () => {
      const res = await request(app)
        .post('/api/threat-detector/analyze')
        .send({ payload: '$(cat /etc/passwd)' });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.analysis.classification).toBe('MALICIOUS');
      expect(res.body.analysis.attackType).toBe('COMMAND_INJECTION');
      expect(res.body.analysis.score).toBeGreaterThanOrEqual(70);
    });

    test('should mark normal text as SAFE', async () => {
      const res = await request(app)
        .post('/api/threat-detector/analyze')
        .send({ payload: 'Hello World' });

      expect(res.status).toBe(200);
      expect(res.body.analysis.classification).toBe('SAFE');
      expect(res.body.analysis.score).toBe(0);
    });

    test('should detect encoded XSS', async () => {
      const res = await request(app)
        .post('/api/threat-detector/analyze')
        .send({ payload: '%3Cscript%3Ealert(1)%3C/script%3E' });

      expect(res.status).toBe(200);
      expect(res.body.analysis.classification).toBe('MALICIOUS');
    });

    test('should require payload field', async () => {
      const res = await request(app)
        .post('/api/threat-detector/analyze')
        .send({});

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });
  });

  describe('GET /api/threat-detector/test-suite', () => {
    test('should return all test cases with results', async () => {
      const res = await request(app).get('/api/threat-detector/test-suite');

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.totalTests).toBeGreaterThanOrEqual(20);
      expect(res.body.passed).toBeGreaterThanOrEqual(15);
      expect(res.body).toHaveProperty('passRate');
      expect(res.body.tests).toBeInstanceOf(Array);
    });
  });

  describe('POST /api/threat-detector/batch', () => {
    test('should analyze multiple payloads', async () => {
      const res = await request(app)
        .post('/api/threat-detector/batch')
        .send({
          payloads: [
            'Hello World',
            '$(cat /etc/passwd)',
            "%3Cscript%3Ealert(1)%3C/script%3E",
          ],
        });

      expect(res.status).toBe(200);
      expect(res.body.summary.total).toBe(3);
      expect(res.body.summary.safe).toBe(1);
      expect(res.body.summary.malicious).toBe(2);
    });

    test('should reject empty payloads array', async () => {
      const res = await request(app)
        .post('/api/threat-detector/batch')
        .send({ payloads: [] });

      expect(res.status).toBe(400);
    });
  });

  // ── Protected Routes (should reject without auth) ──────────────────────

  describe('Protected API Routes (auth required)', () => {
    test('GET /api/logs should return 401 without token', async () => {
      const res = await request(app).get('/api/logs');
      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
    });

    test('GET /api/stats/alerts should return 401 without token', async () => {
      const res = await request(app).get('/api/stats/alerts');
      expect(res.status).toBe(401);
    });

    test('POST /api/ip/block should return 401 without token', async () => {
      const res = await request(app)
        .post('/api/ip/block')
        .send({ ipAddress: '192.168.1.100', reason: 'test' });
      expect(res.status).toBe(401);
    });

    test('GET /api/ip/blocked should return 401 without token', async () => {
      const res = await request(app).get('/api/ip/blocked');
      expect(res.status).toBe(401);
    });
  });

  // ── 404 Handler ────────────────────────────────────────────────────────

  describe('404 Handler', () => {
    test('should return 404 for unknown routes', async () => {
      const res = await request(app).get('/api/nonexistent');
      expect(res.status).toBe(404);
      expect(res.body.success).toBe(false);
    });
  });
});

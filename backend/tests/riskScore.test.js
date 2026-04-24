/**
 * Risk Score API Tests
 * Tests the hybrid scoring endpoint: AbuseIPDB (60%) + ThreatDetector (40%)
 */

const request = require('supertest');
const app = require('../server');

describe('Risk Score API — POST /api/risk-score', () => {

  // ── Input Validation ───────────────────────────────────────────────────

  test('should reject empty body', async () => {
    const res = await request(app)
      .post('/api/risk-score')
      .send({});

    expect(res.status).toBe(400);
    expect(res.body.success).toBe(false);
  });

  // ── Payload-Only Scoring (no IP → fallback to 100% local) ──────────────

  test('should score malicious payload as high risk', async () => {
    const res = await request(app)
      .post('/api/risk-score')
      .send({ payload: '$(cat /etc/passwd)' });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.score).toBeGreaterThanOrEqual(70);
    expect(res.body.level).toBe('high');
    expect(res.body.sources.payloadAnalysis).toBeGreaterThanOrEqual(70);
    expect(res.body.weights.payloadAnalysis).toBe(1.0);
    expect(res.body.details.payload.classification).toBe('MALICIOUS');
  });

  test('should score safe payload as low risk', async () => {
    const res = await request(app)
      .post('/api/risk-score')
      .send({ payload: 'Hello World' });

    expect(res.status).toBe(200);
    expect(res.body.score).toBe(0);
    expect(res.body.level).toBe('low');
    expect(res.body.details.payload.classification).toBe('SAFE');
  });

  test('should score encoded XSS as high risk', async () => {
    const res = await request(app)
      .post('/api/risk-score')
      .send({ payload: '%3Cscript%3Ealert(1)%3C/script%3E' });

    expect(res.status).toBe(200);
    expect(res.body.score).toBeGreaterThanOrEqual(70);
    expect(res.body.level).toBe('high');
  });

  test('should score defanged URL + command injection as high', async () => {
    const res = await request(app)
      .post('/api/risk-score')
      .send({ payload: 'hxxps%5B://%5Dgithub%5B.%5Dcom/?q=$(cat%20file)' });

    expect(res.status).toBe(200);
    expect(res.body.score).toBeGreaterThanOrEqual(70);
    expect(res.body.level).toBe('high');
  });

  // ── IP-Only Scoring (AbuseIPDB fallback — graceful when no key) ────────

  test('should handle IP-only request gracefully', async () => {
    const res = await request(app)
      .post('/api/risk-score')
      .send({ ip: '8.8.8.8' });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body).toHaveProperty('score');
    expect(res.body).toHaveProperty('level');
    expect(res.body.meta.ipProvided).toBe(true);
  });

  // ── Combined IP + Payload ──────────────────────────────────────────────

  test('should handle combined IP + payload request', async () => {
    const res = await request(app)
      .post('/api/risk-score')
      .send({ ip: '1.2.3.4', payload: '$(whoami)' });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.sources).toHaveProperty('ipReputation');
    expect(res.body.sources).toHaveProperty('payloadAnalysis');
    expect(res.body.sources.payloadAnalysis).toBeGreaterThanOrEqual(70);
    expect(res.body.meta.ipProvided).toBe(true);
    expect(res.body.meta.payloadProvided).toBe(true);
  });

  // ── Response Shape ─────────────────────────────────────────────────────

  test('should return correct response structure', async () => {
    const res = await request(app)
      .post('/api/risk-score')
      .send({ payload: 'test' });

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('score');
    expect(res.body).toHaveProperty('level');
    expect(res.body).toHaveProperty('sources');
    expect(res.body).toHaveProperty('weights');
    expect(res.body).toHaveProperty('details');
    expect(res.body).toHaveProperty('meta');
    expect(res.body.meta).toHaveProperty('timestamp');
  });
});

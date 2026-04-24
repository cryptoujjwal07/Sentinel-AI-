import axios from 'axios';

// Base API instance with auth token injection
const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || 'http://localhost:5000/api',
  timeout: 30000,
  headers: { 'Content-Type': 'application/json' },
});

// Request interceptor — inject JWT token
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('sentinel_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor — handle token expiry
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('sentinel_token');
      localStorage.removeItem('sentinel_user');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

// ── Auth APIs ─────────────────────────────────────────────────────────────────
export const authAPI = {
  login: (data) => api.post('/auth/login', data),
  register: (data) => api.post('/auth/register', data),
  googleLogin: (idToken) => api.post('/auth/google', { idToken }),
  getMe: () => api.get('/auth/me'),
};

// ── Stats APIs ────────────────────────────────────────────────────────────────
export const statsAPI = {
  getOverview: () => api.get('/stats/overview'),
  getAttackTypes: () => api.get('/stats/attack-types'),
  getTimeline: (period = '24h') => api.get(`/stats/timeline?period=${period}`),
  getTopIPs: () => api.get('/stats/top-ips'),
  getAlerts: (limit = 20) => api.get(`/stats/alerts?limit=${limit}`),
  markAlertsRead: (ids) => api.patch('/stats/alerts/read', { ids }),
};

// ── Logs APIs ─────────────────────────────────────────────────────────────────
export const logsAPI = {
  getLogs: (params) => api.get('/logs', { params }),
  getRecentLogs: (limit = 10) => api.get(`/logs/recent?limit=${limit}`),
  getLogById: (id) => api.get(`/logs/${id}`),
  deleteLog: (id) => api.delete(`/logs/${id}`),
  clearLogs: () => api.delete('/logs/all'),
};

// ── IP APIs ───────────────────────────────────────────────────────────────────
export const ipAPI = {
  getBlockedIPs: () => api.get('/ip/blocked'),
  blockIP: (data) => api.post('/ip/block', data),
  unblockIP: (ip) => api.delete(`/ip/unblock/${ip}`),
  checkIP: (ip) => api.get(`/ip/check/${ip}`),
};

// ── Scanner APIs ──────────────────────────────────────────────────────────────
export const scannerAPI = {
  testPayload: (data) => api.post('/scanner/test', data),
  bulkTest: (payloads) => api.post('/scanner/bulk', { payloads }),
  getSamples: () => api.get('/scanner/samples'),
};

// ── Profiles APIs ─────────────────────────────────────────────────────────────
export const profilesAPI = {
  getAll: (params) => api.get('/profiles', { params }),
  getByIP: (ip) => api.get(`/profiles/${ip}`),
  getTopRisk: (limit = 10) => api.get(`/profiles/top-risk?limit=${limit}`),
};

export default api;

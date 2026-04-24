import { useState, useEffect, useCallback } from 'react';
import { statsAPI, logsAPI } from '../services/api';
import StatCard from '../components/StatCard';
import { Shield, ShieldAlert, ShieldCheck, Activity, Ban, Bell, Zap, TrendingUp, X } from 'lucide-react';

const ClassBadge = ({ cls }) => {
  const map = {
    SAFE: 'badge badge-safe',
    SUSPICIOUS: 'badge badge-suspicious',
    MALICIOUS: 'badge badge-malicious',
    BLOCKED: 'badge badge-blocked',
    ERROR: 'badge badge-error',
  };
  return <span className={map[cls] || 'badge badge-error'}>{cls}</span>;
};

export default function Dashboard() {
  const [stats, setStats] = useState(null);
  const [recentLogs, setRecentLogs] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedCard, setSelectedCard] = useState(null);

  const fetchData = useCallback(async () => {
    try {
      const [statsRes, logsRes, alertsRes] = await Promise.all([
        statsAPI.getOverview(),
        logsAPI.getRecentLogs(15),
        statsAPI.getAlerts(8),
      ]);
      setStats(statsRes.data.data);
      setRecentLogs(logsRes.data.logs || []);
      setAlerts(alertsRes.data.data || []);
    } catch (err) {
      console.error('Dashboard fetch error:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    // Poll every 5 seconds for live updates
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, [fetchData]);

  const methodColor = {
    GET: 'var(--accent-emerald)', POST: 'var(--accent-indigo)',
    PUT: 'var(--accent-amber)', DELETE: 'var(--accent-rose)',
    PATCH: 'var(--accent-cyan)',
  };

  const severityMap = {
    CRITICAL: '#f43f5e', HIGH: '#f59e0b', MEDIUM: '#6366f1', LOW: '#10b981',
  };

  // Build detailed info for each card type
  const getCardDetails = (label) => {
    switch (label) {
      case 'Total Requests':
        return {
          icon: <Activity size={24} color="var(--accent-indigo)" />,
          description: 'Total number of HTTP requests processed by the WAF since deployment.',
          metrics: [
            { label: 'Today', value: stats?.requestsToday ?? 0 },
            { label: 'Safe', value: stats?.safeRequests ?? 0 },
            { label: 'Suspicious', value: stats?.suspiciousRequests ?? 0 },
            { label: 'Malicious', value: stats?.maliciousRequests ?? 0 },
          ],
          accent: 'var(--accent-indigo)',
        };
      case 'Malicious Blocked':
        return {
          icon: <ShieldAlert size={24} color="var(--malicious)" />,
          description: 'Requests classified as malicious and automatically blocked by SentinelAI.',
          metrics: [
            { label: 'Blocked', value: stats?.maliciousRequests ?? 0 },
            { label: 'IPs Blocked', value: stats?.blockedIPs ?? 0 },
            { label: 'Threat Rate', value: `${stats?.threatRate ?? 0}%` },
            { label: 'Alerts', value: stats?.unreadAlerts ?? 0 },
          ],
          accent: 'var(--malicious)',
        };
      case 'Suspicious Flagged':
        return {
          icon: <Zap size={24} color="var(--suspicious)" />,
          description: 'Requests flagged as suspicious — forwarded to AI for deeper analysis.',
          metrics: [
            { label: 'Flagged', value: stats?.suspiciousRequests ?? 0 },
            { label: 'Total Scanned', value: stats?.totalRequests ?? 0 },
            { label: 'Flag Rate', value: stats?.totalRequests ? `${((stats.suspiciousRequests / stats.totalRequests) * 100).toFixed(1)}%` : '0%' },
          ],
          accent: 'var(--suspicious)',
        };
      case 'Safe Requests':
        return {
          icon: <ShieldCheck size={24} color="var(--safe)" />,
          description: 'Requests that passed all security checks and were classified as safe.',
          metrics: [
            { label: 'Safe', value: stats?.safeRequests ?? 0 },
            { label: 'Total', value: stats?.totalRequests ?? 0 },
            { label: 'Safe Rate', value: stats?.totalRequests ? `${((stats.safeRequests / stats.totalRequests) * 100).toFixed(1)}%` : '0%' },
          ],
          accent: 'var(--safe)',
        };
      case 'IPs Blocked':
        return {
          icon: <Ban size={24} color="var(--accent-rose)" />,
          description: 'Unique IP addresses currently blocked from accessing the application.',
          metrics: [
            { label: 'Blocked IPs', value: stats?.blockedIPs ?? 0 },
            { label: 'Malicious Hits', value: stats?.maliciousRequests ?? 0 },
          ],
          accent: 'var(--accent-rose)',
        };
      case 'Unread Alerts':
        return {
          icon: <Bell size={24} color="var(--accent-amber)" />,
          description: 'Security alerts that haven\'t been reviewed yet.',
          metrics: [
            { label: 'Unread', value: stats?.unreadAlerts ?? 0 },
            { label: 'Critical', value: alerts.filter(a => a.severity === 'CRITICAL').length },
            { label: 'High', value: alerts.filter(a => a.severity === 'HIGH').length },
          ],
          accent: 'var(--accent-amber)',
        };
      case 'Requests Today':
        return {
          icon: <TrendingUp size={24} color="var(--accent-cyan)" />,
          description: 'Number of requests received in the last 24 hours.',
          metrics: [
            { label: 'Today', value: stats?.requestsToday ?? 0 },
            { label: 'All Time', value: stats?.totalRequests ?? 0 },
          ],
          accent: 'var(--accent-cyan)',
        };
      case 'Threat Rate':
        return {
          icon: <Shield size={24} color="var(--accent-purple)" />,
          description: 'Percentage of total traffic identified as malicious or suspicious.',
          metrics: [
            { label: 'Threat Rate', value: `${stats?.threatRate ?? 0}%` },
            { label: 'Malicious', value: stats?.maliciousRequests ?? 0 },
            { label: 'Suspicious', value: stats?.suspiciousRequests ?? 0 },
            { label: 'Total', value: stats?.totalRequests ?? 0 },
          ],
          accent: 'var(--accent-purple)',
        };
      default:
        return null;
    }
  };

  const handleCardClick = (card) => {
    console.log(`[Dashboard] Card clicked: ${card.label}`, card);
    const details = getCardDetails(card.label);
    if (details) {
      setSelectedCard({ ...card, ...details });
    }
  };

  const closeModal = () => {
    console.log('[Dashboard] Closing card detail modal');
    setSelectedCard(null);
  };

  return (
    <div>
      {/* Header */}
      <div className="page-header">
        <div>
          <h1 className="page-title">Security Dashboard</h1>
          <p className="page-subtitle">Real-time threat monitoring & WAF analytics</p>
        </div>
        <div className="live-indicator">
          <div className="live-dot" />
          Auto-refreshing every 5s
        </div>
      </div>

      {/* Stat Cards */}
      <div className="stat-cards-grid">
        <StatCard
          icon={<Activity size={22} color="var(--accent-indigo)" />}
          label="Total Requests"
          value={stats?.totalRequests ?? '—'}
          accent="var(--accent-indigo)"
          loading={loading}
          onClick={handleCardClick}
        />
        <StatCard
          icon={<ShieldAlert size={22} color="var(--malicious)" />}
          label="Malicious Blocked"
          value={stats?.maliciousRequests ?? '—'}
          accent="var(--malicious)"
          loading={loading}
          onClick={handleCardClick}
        />
        <StatCard
          icon={<Zap size={22} color="var(--suspicious)" />}
          label="Suspicious Flagged"
          value={stats?.suspiciousRequests ?? '—'}
          accent="var(--suspicious)"
          loading={loading}
          onClick={handleCardClick}
        />
        <StatCard
          icon={<ShieldCheck size={22} color="var(--safe)" />}
          label="Safe Requests"
          value={stats?.safeRequests ?? '—'}
          accent="var(--safe)"
          loading={loading}
          onClick={handleCardClick}
        />
        <StatCard
          icon={<Ban size={22} color="var(--accent-rose)" />}
          label="IPs Blocked"
          value={stats?.blockedIPs ?? '—'}
          accent="var(--accent-rose)"
          loading={loading}
          onClick={handleCardClick}
        />
        <StatCard
          icon={<Bell size={22} color="var(--accent-amber)" />}
          label="Unread Alerts"
          value={stats?.unreadAlerts ?? '—'}
          accent="var(--accent-amber)"
          loading={loading}
          onClick={handleCardClick}
        />
        <StatCard
          icon={<TrendingUp size={22} color="var(--accent-cyan)" />}
          label="Requests Today"
          value={stats?.requestsToday ?? '—'}
          accent="var(--accent-cyan)"
          loading={loading}
          onClick={handleCardClick}
        />
        <StatCard
          icon={<Shield size={22} color="var(--accent-purple)" />}
          label="Threat Rate"
          value={stats ? `${stats.threatRate}%` : '—'}
          accent="var(--accent-purple)"
          loading={loading}
          onClick={handleCardClick}
        />
      </div>

      {/* Card Detail Modal */}
      {selectedCard && (
        <div className="card-modal-overlay" onClick={closeModal}>
          <div className="card-modal" onClick={(e) => e.stopPropagation()}>
            <div className="card-modal-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                <div className="stat-icon" style={{ '--icon-bg': `${selectedCard.accent}18`, width: 44, height: 44 }}>
                  {selectedCard.icon}
                </div>
                <div>
                  <h3 style={{ fontSize: 17, fontWeight: 600, color: 'var(--text-primary)' }}>
                    {selectedCard.label}
                  </h3>
                  <div style={{ fontSize: 28, fontWeight: 700, color: selectedCard.accent, lineHeight: 1, marginTop: 4 }}>
                    {typeof selectedCard.value === 'number' ? selectedCard.value.toLocaleString() : selectedCard.value}
                  </div>
                </div>
              </div>
              <button
                onClick={closeModal}
                style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', padding: 4 }}
                title="Close"
              >
                <X size={18} />
              </button>
            </div>

            <div className="card-modal-body">
              <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 20, lineHeight: 1.6 }}>
                {selectedCard.description}
              </p>

              {/* Metric Breakdown */}
              <div className="card-modal-metrics">
                {selectedCard.metrics?.map((m, i) => (
                  <div key={i} className="card-modal-metric-item">
                    <div className="card-modal-metric-value" style={{ color: selectedCard.accent }}>
                      {typeof m.value === 'number' ? m.value.toLocaleString() : m.value}
                    </div>
                    <div className="card-modal-metric-label">{m.label}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Two-column layout */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 380px', gap: 20 }}>
        {/* Live Traffic Feed */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">⚡ Live Traffic</span>
            <div className="live-indicator"><div className="live-dot" />Live</div>
          </div>
          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>Method</th>
                  <th>Path</th>
                  <th>IP Address</th>
                  <th>Classification</th>
                  <th>Attack Type</th>
                  <th>Time</th>
                </tr>
              </thead>
              <tbody>
                {recentLogs.length === 0 && (
                  <tr><td colSpan={6} style={{ textAlign: 'center', padding: '32px', color: 'var(--text-muted)' }}>
                    No traffic recorded yet
                  </td></tr>
                )}
                {recentLogs.map((log, i) => (
                  <tr key={log._id || i}>
                    <td>
                      <span className="mono" style={{ color: methodColor[log.method] || 'white', fontWeight: 600 }}>
                        {log.method}
                      </span>
                    </td>
                    <td>
                      <span className="mono" style={{ color: 'var(--text-primary)', maxWidth: 220, display: 'block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {log.path}
                      </span>
                    </td>
                    <td><span className="mono">{log.ipAddress}</span></td>
                    <td><ClassBadge cls={log.classification} /></td>
                    <td>
                      <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                        {log.attackType !== 'NONE' ? log.attackType?.replace(/_/g, ' ') : '—'}
                      </span>
                    </td>
                    <td style={{ color: 'var(--text-muted)', fontSize: 12 }}>
                      {new Date(log.createdAt).toLocaleTimeString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Alerts Panel */}
        <div className="card" style={{ overflow: 'hidden' }}>
          <div className="card-header">
            <span className="card-title">🔔 Recent Alerts</span>
            <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
              {alerts.filter(a => !a.isRead).length} unread
            </span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, maxHeight: 480, overflowY: 'auto' }}>
            {alerts.length === 0 && (
              <div style={{ textAlign: 'center', padding: '40px 0', color: 'var(--text-muted)' }}>
                ✅ No alerts yet
              </div>
            )}
            {alerts.map((alert) => (
              <div key={alert._id} className={`alert-item${!alert.isRead ? ' unread' : ''}`}>
                <div
                  className="alert-severity"
                  style={{ background: severityMap[alert.severity] || '#6366f1' }}
                />
                <div style={{ minWidth: 0 }}>
                  <div style={{ fontSize: 13, fontWeight: 500, color: 'var(--text-primary)', marginBottom: 2 }}>
                    {alert.title}
                  </div>
                  <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                    {alert.ipAddress && <span className="mono">{alert.ipAddress} · </span>}
                    {new Date(alert.createdAt).toLocaleString()}
                  </div>
                </div>
                <span style={{
                  fontSize: 10, fontWeight: 700, padding: '2px 7px', borderRadius: 99,
                  background: `${severityMap[alert.severity]}20`,
                  color: severityMap[alert.severity],
                  border: `1px solid ${severityMap[alert.severity]}40`,
                  flexShrink: 0,
                }}>
                  {alert.severity}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

import { useState, useEffect, useCallback } from 'react';
import { profilesAPI } from '../services/api';
import {
  UserRoundSearch, ShieldAlert, Gauge, Clock, Radio, Search,
  ChevronLeft, ChevronRight, Eye, X, Fingerprint
} from 'lucide-react';

// ── Profile Type Badge ────────────────────────────────────────────────────────
const ProfileBadge = ({ type }) => {
  const map = {
    'normal':              'profile-badge profile-badge-normal',
    'scanner':             'profile-badge profile-badge-scanner',
    'repetitive attacker': 'profile-badge profile-badge-repetitive',
    'aggressive attacker': 'profile-badge profile-badge-aggressive',
    'suspicious bot':      'profile-badge profile-badge-bot',
  };
  return (
    <span className={map[type] || 'profile-badge profile-badge-normal'}>
      {type?.toUpperCase()}
    </span>
  );
};

// ── Risk Score Bar ────────────────────────────────────────────────────────────
const RiskBar = ({ score }) => {
  const color =
    score >= 70 ? 'var(--malicious)' :
    score >= 40 ? 'var(--suspicious)' :
    score >= 10 ? 'var(--accent-indigo)' :
    'var(--safe)';

  return (
    <div className="risk-bar-container">
      <div className="risk-bar-track">
        <div
          className="risk-bar-fill"
          style={{ width: `${score}%`, background: color }}
        />
      </div>
      <span className="risk-bar-label" style={{ color }}>{score}</span>
    </div>
  );
};

// ── Detail Modal ──────────────────────────────────────────────────────────────
const ProfileModal = ({ profile, onClose }) => {
  if (!profile) return null;

  const attackEntries = Object.entries(profile.attackTypes || {});

  return (
    <div className="profile-modal-overlay" onClick={onClose}>
      <div className="profile-modal" onClick={(e) => e.stopPropagation()}>
        <div className="profile-modal-header">
          <h3>
            <Fingerprint size={18} style={{ marginRight: 8, verticalAlign: 'middle' }} />
            Attacker Profile
          </h3>
          <button className="btn btn-ghost btn-sm" onClick={onClose}>
            <X size={16} />
          </button>
        </div>

        <div className="profile-modal-body">
          {/* IP & Type */}
          <div className="profile-detail-row">
            <span className="profile-detail-label">IP Address</span>
            <span className="mono" style={{ fontSize: 16, fontWeight: 600 }}>{profile.ip}</span>
          </div>
          <div className="profile-detail-row">
            <span className="profile-detail-label">Profile Type</span>
            <ProfileBadge type={profile.profileType} />
          </div>
          <div className="profile-detail-row">
            <span className="profile-detail-label">Risk Score</span>
            <RiskBar score={profile.riskScore} />
          </div>

          <hr className="profile-divider" />

          {/* Stats Grid */}
          <div className="profile-stats-grid">
            <div className="profile-stat-item">
              <div className="profile-stat-value">{profile.totalRequests?.toLocaleString()}</div>
              <div className="profile-stat-label">Total Requests</div>
            </div>
            <div className="profile-stat-item">
              <div className="profile-stat-value" style={{ color: 'var(--suspicious)' }}>
                {profile.suspiciousRequests?.toLocaleString()}
              </div>
              <div className="profile-stat-label">Suspicious</div>
            </div>
            <div className="profile-stat-item">
              <div className="profile-stat-value" style={{ color: 'var(--malicious)' }}>
                {profile.maliciousRequests?.toLocaleString()}
              </div>
              <div className="profile-stat-label">Malicious</div>
            </div>
            <div className="profile-stat-item">
              <div className="profile-stat-value" style={{ color: 'var(--safe)' }}>
                {profile.safeRequests?.toLocaleString()}
              </div>
              <div className="profile-stat-label">Safe</div>
            </div>
          </div>

          <hr className="profile-divider" />

          {/* Attack Types */}
          <div className="profile-detail-row">
            <span className="profile-detail-label">Attack Types</span>
          </div>
          {attackEntries.length === 0 ? (
            <div style={{ color: 'var(--text-muted)', fontSize: 13, padding: '4px 0' }}>
              No attacks detected
            </div>
          ) : (
            <div className="profile-attack-types">
              {attackEntries.map(([type, count]) => (
                <div key={type} className="profile-attack-chip">
                  <span>{type.replace(/_/g, ' ')}</span>
                  <span className="profile-attack-count">{count}</span>
                </div>
              ))}
            </div>
          )}

          <hr className="profile-divider" />

          {/* Additional Info */}
          <div className="profile-detail-row">
            <span className="profile-detail-label">Request Frequency</span>
            <span className="mono">{profile.requestFrequency?.toFixed(1)} req/min</span>
          </div>
          <div className="profile-detail-row">
            <span className="profile-detail-label">Repeated Payloads</span>
            <span className="mono">{profile.repeatedPayloadCount}</span>
          </div>
          <div className="profile-detail-row">
            <span className="profile-detail-label">User Agent</span>
            <span style={{ fontSize: 12, color: 'var(--text-muted)', wordBreak: 'break-all' }}>
              {profile.userAgent}
            </span>
          </div>
          <div className="profile-detail-row">
            <span className="profile-detail-label">First Seen</span>
            <span className="mono">{new Date(profile.firstSeen).toLocaleString()}</span>
          </div>
          <div className="profile-detail-row">
            <span className="profile-detail-label">Last Seen</span>
            <span className="mono">{new Date(profile.lastSeen).toLocaleString()}</span>
          </div>
          <div className="profile-detail-row">
            <span className="profile-detail-label">Blocked</span>
            <span style={{ color: profile.isBlocked ? 'var(--malicious)' : 'var(--safe)' }}>
              {profile.isBlocked ? '⛔ Yes' : '✅ No'}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};

// ── Main Profiles Page ────────────────────────────────────────────────────────
export default function Profiles() {
  const [profiles, setProfiles] = useState([]);
  const [topRisk, setTopRisk] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [filterType, setFilterType] = useState('all');
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [total, setTotal] = useState(0);
  const [selectedProfile, setSelectedProfile] = useState(null);

  const fetchProfiles = useCallback(async () => {
    try {
      const params = { page, limit: 15, sortBy: 'riskScore', order: 'desc' };
      if (search) params.search = search;
      if (filterType !== 'all') params.profileType = filterType;

      const [profilesRes, topRes] = await Promise.all([
        profilesAPI.getAll(params),
        page === 1 ? profilesAPI.getTopRisk(5) : Promise.resolve(null),
      ]);

      setProfiles(profilesRes.data.data || []);
      setTotalPages(profilesRes.data.pages || 1);
      setTotal(profilesRes.data.total || 0);
      if (topRes) setTopRisk(topRes.data.data || []);
    } catch (err) {
      console.error('Profiles fetch error:', err);
    } finally {
      setLoading(false);
    }
  }, [page, search, filterType]);

  useEffect(() => {
    setLoading(true);
    fetchProfiles();
  }, [fetchProfiles]);

  // Auto-refresh every 10 seconds
  useEffect(() => {
    const interval = setInterval(fetchProfiles, 10000);
    return () => clearInterval(interval);
  }, [fetchProfiles]);

  const handleSearch = (e) => {
    setSearch(e.target.value);
    setPage(1);
  };

  const handleViewProfile = async (ip) => {
    try {
      const res = await profilesAPI.getByIP(ip);
      setSelectedProfile(res.data.data);
    } catch (err) {
      console.error('Error fetching profile:', err);
    }
  };

  const profileTypeOptions = [
    'all', 'normal', 'scanner', 'repetitive attacker', 'aggressive attacker', 'suspicious bot',
  ];

  return (
    <div>
      {/* Header */}
      <div className="page-header">
        <div>
          <h1 className="page-title">Attacker Profiles</h1>
          <p className="page-subtitle">
            Rule-based behavior profiling &amp; risk scoring — {total} profiles tracked
          </p>
        </div>
        <div className="live-indicator">
          <div className="live-dot" />
          Auto-refreshing every 10s
        </div>
      </div>

      {/* Top Risk Cards (shown only on page 1) */}
      {topRisk.length > 0 && page === 1 && (
        <div className="profile-top-risk-grid">
          {topRisk.map((p) => (
            <div
              key={p.ip || p._id}
              className="profile-top-card"
              onClick={() => handleViewProfile(p.ip)}
            >
              <div className="profile-top-header">
                <ShieldAlert size={16} color="var(--malicious)" />
                <span className="profile-top-label">HIGH RISK</span>
              </div>
              <div className="mono" style={{ fontSize: 14, fontWeight: 600, marginBottom: 6 }}>
                {p.ip}
              </div>
              <RiskBar score={p.riskScore} />
              <div style={{ marginTop: 8 }}>
                <ProfileBadge type={p.profileType} />
              </div>
              <div className="profile-top-stats">
                <span>{p.maliciousRequests} malicious</span>
                <span>{p.suspiciousRequests} suspicious</span>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Filters */}
      <div className="card" style={{ marginBottom: 20, padding: '16px 20px' }}>
        <div className="profile-filters">
          <div className="profile-search-wrap">
            <Search size={16} className="profile-search-icon" />
            <input
              type="text"
              className="form-input profile-search-input"
              placeholder="Search by IP address..."
              value={search}
              onChange={handleSearch}
            />
          </div>
          <select
            className="form-select"
            style={{ maxWidth: 220 }}
            value={filterType}
            onChange={(e) => { setFilterType(e.target.value); setPage(1); }}
          >
            {profileTypeOptions.map((opt) => (
              <option key={opt} value={opt}>
                {opt === 'all' ? 'All Profile Types' : opt.charAt(0).toUpperCase() + opt.slice(1)}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Profiles Table */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">
            <UserRoundSearch size={16} style={{ marginRight: 8, verticalAlign: 'middle' }} />
            Attacker Profiles
          </span>
          <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
            Page {page} of {totalPages}
          </span>
        </div>

        <div className="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>IP Address</th>
                <th>Profile Type</th>
                <th>Risk Score</th>
                <th>Total</th>
                <th>Suspicious</th>
                <th>Malicious</th>
                <th>Attack Types</th>
                <th>Frequency</th>
                <th>Last Seen</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading && profiles.length === 0 && (
                <tr>
                  <td colSpan={10} style={{ textAlign: 'center', padding: '48px', color: 'var(--text-muted)' }}>
                    <div className="spinner" style={{ margin: '0 auto 12px', width: 28, height: 28 }} />
                    Loading profiles...
                  </td>
                </tr>
              )}
              {!loading && profiles.length === 0 && (
                <tr>
                  <td colSpan={10} style={{ textAlign: 'center', padding: '48px', color: 'var(--text-muted)' }}>
                    <UserRoundSearch size={28} style={{ marginBottom: 8, opacity: 0.4 }} />
                    <div>No attacker profiles found</div>
                    <div style={{ fontSize: 12, marginTop: 4 }}>
                      Profiles are created automatically when the WAF processes requests
                    </div>
                  </td>
                </tr>
              )}
              {profiles.map((p) => {
                const attackKeys = Object.keys(p.attackTypes || {});
                return (
                  <tr key={p.ip || p._id}>
                    <td>
                      <span className="mono" style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                        {p.ip}
                      </span>
                    </td>
                    <td><ProfileBadge type={p.profileType} /></td>
                    <td><RiskBar score={p.riskScore} /></td>
                    <td>{p.totalRequests?.toLocaleString()}</td>
                    <td>
                      <span style={{ color: p.suspiciousRequests > 0 ? 'var(--suspicious)' : 'var(--text-muted)' }}>
                        {p.suspiciousRequests}
                      </span>
                    </td>
                    <td>
                      <span style={{ color: p.maliciousRequests > 0 ? 'var(--malicious)' : 'var(--text-muted)' }}>
                        {p.maliciousRequests}
                      </span>
                    </td>
                    <td>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                        {attackKeys.length === 0 ? (
                          <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>—</span>
                        ) : (
                          attackKeys.slice(0, 3).map((t) => (
                            <span key={t} className="profile-attack-mini">
                              {t.replace(/_/g, ' ')}
                            </span>
                          ))
                        )}
                        {attackKeys.length > 3 && (
                          <span className="profile-attack-mini" style={{ opacity: 0.6 }}>
                            +{attackKeys.length - 3}
                          </span>
                        )}
                      </div>
                    </td>
                    <td>
                      <span className="mono" style={{ fontSize: 12 }}>
                        {p.requestFrequency?.toFixed(1)}/min
                      </span>
                    </td>
                    <td style={{ color: 'var(--text-muted)', fontSize: 12 }}>
                      {new Date(p.lastSeen).toLocaleString()}
                    </td>
                    <td>
                      <button
                        className="btn btn-ghost btn-sm"
                        onClick={() => handleViewProfile(p.ip)}
                        title="View full profile"
                      >
                        <Eye size={14} />
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="profile-pagination">
            <button
              className="btn btn-ghost btn-sm"
              disabled={page <= 1}
              onClick={() => setPage((p) => Math.max(1, p - 1))}
            >
              <ChevronLeft size={16} /> Previous
            </button>
            <div className="profile-page-numbers">
              {Array.from({ length: Math.min(totalPages, 5) }, (_, i) => {
                const pageNum = page <= 3 ? i + 1 : page - 2 + i;
                if (pageNum > totalPages) return null;
                return (
                  <button
                    key={pageNum}
                    className={`profile-page-btn ${pageNum === page ? 'active' : ''}`}
                    onClick={() => setPage(pageNum)}
                  >
                    {pageNum}
                  </button>
                );
              })}
            </div>
            <button
              className="btn btn-ghost btn-sm"
              disabled={page >= totalPages}
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
            >
              Next <ChevronRight size={16} />
            </button>
          </div>
        )}
      </div>

      {/* Detail Modal */}
      {selectedProfile && (
        <ProfileModal
          profile={selectedProfile}
          onClose={() => setSelectedProfile(null)}
        />
      )}
    </div>
  );
}

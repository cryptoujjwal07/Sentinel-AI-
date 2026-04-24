import { useState, useEffect, useCallback } from 'react';
import { logsAPI } from '../services/api';
import { Search, RefreshCw, Trash2, Eye, X } from 'lucide-react';
import toast from 'react-hot-toast';

const Badge = ({ cls }) => {
  const map = {
    SAFE: 'badge-safe', SUSPICIOUS: 'badge-suspicious',
    MALICIOUS: 'badge-malicious', ERROR: 'badge-error', BYPASSED: 'badge-error',
  };
  return <span className={`badge ${map[cls] || 'badge-error'}`}>{cls}</span>;
};

const ActionBadge = ({ action }) => {
  const map = { BLOCKED: 'badge-malicious', FLAGGED: 'badge-suspicious', ALLOWED: 'badge-safe', RATE_LIMITED: 'badge-suspicious' };
  return <span className={`badge ${map[action] || 'badge-error'}`}>{action}</span>;
};

const methodColors = {
  GET: '#10b981', POST: '#6366f1', PUT: '#f59e0b',
  DELETE: '#f43f5e', PATCH: '#06b6d4',
};

export default function Logs() {
  const [logs, setLogs] = useState([]);
  const [total, setTotal] = useState(0);
  const [pages, setPages] = useState(1);
  const [loading, setLoading] = useState(true);
  const [selectedLog, setSelectedLog] = useState(null);

  const [filters, setFilters] = useState({
    page: 1, limit: 20,
    classification: '', attackType: '',
    ipAddress: '', search: '',
  });

  const fetchLogs = useCallback(async () => {
    setLoading(true);
    try {
      // Strip empty strings from params
      const params = Object.fromEntries(
        Object.entries(filters).filter(([, v]) => v !== '')
      );
      const res = await logsAPI.getLogs(params);
      setLogs(res.data.logs || []);
      setTotal(res.data.total || 0);
      setPages(res.data.pages || 1);
    } catch (e) { console.error(e); }
    finally { setLoading(false); }
  }, [filters]);

  useEffect(() => { fetchLogs(); }, [fetchLogs]);

  const setFilter = (key, val) => setFilters(f => ({ ...f, [key]: val, page: 1 }));
  const setPage = (p) => setFilters(f => ({ ...f, page: p }));

  const handleDelete = async (id, e) => {
    e.stopPropagation();
    if (!confirm('Delete this log entry?')) return;
    try {
      await logsAPI.deleteLog(id);
      toast.success('Log deleted');
      fetchLogs();
    } catch { toast.error('Failed to delete log'); }
  };

  return (
    <div>
      {/* Header */}
      <div className="page-header">
        <div>
          <h1 className="page-title">Request Logs</h1>
          <p className="page-subtitle">{total.toLocaleString()} total records</p>
        </div>
        <button className="btn btn-ghost btn-sm" onClick={fetchLogs}>
          <RefreshCw size={14} className={loading ? 'spin' : ''} />
          Refresh
        </button>
      </div>

      {/* Filters */}
      <div className="card" style={{ marginBottom: 20, padding: '16px 20px' }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 12, alignItems: 'center' }}>
          {/* Search */}
          <div style={{ position: 'relative' }}>
            <Search size={14} style={{ position: 'absolute', left: 11, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)', pointerEvents: 'none' }} />
            <input
              type="text"
              className="form-input"
              placeholder="Search path / IP / reason…"
              value={filters.search}
              onChange={e => setFilter('search', e.target.value)}
              style={{ paddingLeft: 32 }}
            />
          </div>
          {/* Classification */}
          <select className="form-select" value={filters.classification} onChange={e => setFilter('classification', e.target.value)}>
            <option value="">All Classifications</option>
            <option value="SAFE">Safe</option>
            <option value="SUSPICIOUS">Suspicious</option>
            <option value="MALICIOUS">Malicious</option>
          </select>
          {/* Attack Type */}
          <select className="form-select" value={filters.attackType} onChange={e => setFilter('attackType', e.target.value)}>
            <option value="">All Attack Types</option>
            <option value="SQL_INJECTION">SQL Injection</option>
            <option value="XSS">XSS</option>
            <option value="CSRF">CSRF</option>
            <option value="PATH_TRAVERSAL">Path Traversal</option>
            <option value="COMMAND_INJECTION">Command Injection</option>
            <option value="NONE">None</option>
          </select>
          {/* IP Filter */}
          <input
            type="text"
            className="form-input"
            placeholder="Filter by IP…"
            value={filters.ipAddress}
            onChange={e => setFilter('ipAddress', e.target.value)}
          />
          {/* Clear */}
          <button
            className="btn btn-ghost btn-sm"
            onClick={() => setFilters({ page: 1, limit: 20, classification: '', attackType: '', ipAddress: '', search: '' })}
          >
            <X size={14} /> Clear
          </button>
        </div>
      </div>

      {/* Table */}
      <div className="card" style={{ padding: 0 }}>
        <div className="table-wrapper" style={{ border: 'none' }}>
          <table>
            <thead>
              <tr>
                <th>Method</th>
                <th>Path</th>
                <th>IP Address</th>
                <th>Classification</th>
                <th>Attack Type</th>
                <th>Action</th>
                <th>Confidence</th>
                <th>Time</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {loading && (
                <tr><td colSpan={9} style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)' }}>
                  <div className="spinner" style={{ margin: '0 auto', width: 32, height: 32 }} />
                </td></tr>
              )}
              {!loading && logs.length === 0 && (
                <tr><td colSpan={9} style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)' }}>
                  No logs found for selected filters
                </td></tr>
              )}
              {!loading && logs.map(log => (
                <tr
                  key={log._id}
                  style={{ cursor: 'pointer' }}
                  onClick={() => setSelectedLog(log)}
                >
                  <td>
                    <span className="mono" style={{ color: methodColors[log.method] || 'white', fontWeight: 600 }}>
                      {log.method}
                    </span>
                  </td>
                  <td>
                    <span className="mono" style={{ maxWidth: 200, display: 'block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: 'var(--text-primary)' }}>
                      {log.path}
                    </span>
                  </td>
                  <td><span className="mono">{log.ipAddress}</span></td>
                  <td><Badge cls={log.classification} /></td>
                  <td>
                    <span style={{ fontSize: 12, color: log.attackType !== 'NONE' ? 'var(--accent-rose)' : 'var(--text-muted)' }}>
                      {log.attackType?.replace(/_/g, ' ') || '—'}
                    </span>
                  </td>
                  <td><ActionBadge action={log.action} /></td>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <div style={{ flex: 1, height: 4, background: 'rgba(255,255,255,0.07)', borderRadius: 99, minWidth: 50 }}>
                        <div style={{
                          width: `${log.confidence}%`, height: '100%', borderRadius: 99,
                          background: log.classification === 'MALICIOUS' ? 'var(--malicious)'
                            : log.classification === 'SUSPICIOUS' ? 'var(--suspicious)' : 'var(--safe)',
                        }} />
                      </div>
                      <span style={{ fontSize: 11, color: 'var(--text-muted)', width: 30 }}>{log.confidence}%</span>
                    </div>
                  </td>
                  <td style={{ fontSize: 12, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                    {new Date(log.createdAt).toLocaleString()}
                  </td>
                  <td>
                    <div style={{ display: 'flex', gap: 4 }}>
                      <button className="btn btn-ghost btn-sm" onClick={e => { e.stopPropagation(); setSelectedLog(log); }}>
                        <Eye size={13} />
                      </button>
                      <button className="btn btn-danger btn-sm" onClick={e => handleDelete(log._id, e)}>
                        <Trash2 size={13} />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {pages > 1 && (
          <div style={{ display: 'flex', justifyContent: 'center', gap: 8, padding: 16, borderTop: '1px solid var(--border)' }}>
            <button className="btn btn-ghost btn-sm" onClick={() => setPage(filters.page - 1)} disabled={filters.page === 1}>← Prev</button>
            <span style={{ alignSelf: 'center', fontSize: 13, color: 'var(--text-muted)' }}>
              Page {filters.page} of {pages}
            </span>
            <button className="btn btn-ghost btn-sm" onClick={() => setPage(filters.page + 1)} disabled={filters.page === pages}>Next →</button>
          </div>
        )}
      </div>

      {/* Log Detail Modal */}
      {selectedLog && (
        <div
          onClick={() => setSelectedLog(null)}
          style={{
            position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.7)',
            backdropFilter: 'blur(4px)', zIndex: 999, display: 'flex',
            alignItems: 'center', justifyContent: 'center', padding: 24,
          }}
        >
          <div
            onClick={e => e.stopPropagation()}
            style={{
              background: 'var(--bg-card)', border: '1px solid var(--border-accent)',
              borderRadius: 'var(--radius-xl)', padding: 28, width: '100%',
              maxWidth: 640, maxHeight: '85vh', overflowY: 'auto',
              animation: 'slide-up 0.2s ease',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
              <h2 style={{ fontSize: 17, fontWeight: 700 }}>Request Detail</h2>
              <button className="btn btn-ghost btn-sm" onClick={() => setSelectedLog(null)}><X size={15} /></button>
            </div>

            {/* Detail rows */}
            {[
              ['Request ID', selectedLog.requestId],
              ['Method + Path', `${selectedLog.method} ${selectedLog.path}`],
              ['IP Address', selectedLog.ipAddress],
              ['User Agent', selectedLog.userAgent],
              ['Classification', selectedLog.classification],
              ['Attack Type', selectedLog.attackType],
              ['Confidence', `${selectedLog.confidence}%`],
              ['Action', selectedLog.action],
              ['AI Reason', selectedLog.aiReason],
              ['Time', new Date(selectedLog.createdAt).toLocaleString()],
            ].map(([label, val]) => (
              <div key={label} style={{ display: 'flex', gap: 12, marginBottom: 12, borderBottom: '1px solid var(--border)', paddingBottom: 10 }}>
                <span style={{ fontSize: 12, color: 'var(--text-muted)', width: 130, flexShrink: 0, textTransform: 'uppercase', letterSpacing: '0.4px' }}>{label}</span>
                <span style={{ fontSize: 13, color: 'var(--text-primary)', wordBreak: 'break-all' }}>{val || '—'}</span>
              </div>
            ))}

            {/* Body */}
            {Object.keys(selectedLog.requestBody || {}).length > 0 && (
              <div>
                <div style={{ fontSize: 12, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: 8 }}>Request Body</div>
                <pre style={{
                  background: 'rgba(0,0,0,0.3)', borderRadius: 8, padding: 12,
                  fontSize: 12, color: 'var(--accent-cyan)', overflow: 'auto',
                  fontFamily: 'JetBrains Mono, monospace', maxHeight: 200,
                }}>
                  {JSON.stringify(selectedLog.requestBody, null, 2)}
                </pre>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

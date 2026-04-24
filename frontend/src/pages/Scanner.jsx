import { useState, useEffect } from 'react';
import { scannerAPI } from '../services/api';
import toast from 'react-hot-toast';
import { Zap, ShieldAlert, ChevronDown, ChevronUp, Copy, RefreshCw } from 'lucide-react';

const classColor = { SAFE: 'safe', SUSPICIOUS: 'suspicious', MALICIOUS: 'malicious' };
const classIcon  = { SAFE: '✅', SUSPICIOUS: '⚠️', MALICIOUS: '🚨' };

const confBarColor = { SAFE: 'var(--safe)', SUSPICIOUS: 'var(--suspicious)', MALICIOUS: 'var(--malicious)' };

export default function Scanner() {
  const [payload, setPayload] = useState('');
  const [context, setContext] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [samples, setSamples] = useState(null);
  const [openCategory, setOpenCategory] = useState(null);

  // Bulk test
  const [bulkInput, setBulkInput] = useState('');
  const [bulkResults, setBulkResults] = useState([]);
  const [bulkLoading, setBulkLoading] = useState(false);

  useEffect(() => {
    scannerAPI.getSamples().then(r => setSamples(r.data.samples)).catch(() => {});
  }, []);

  const handleTest = async (e) => {
    e?.preventDefault();
    if (!payload.trim()) return toast.error('Enter a payload to test');
    setLoading(true);
    setResult(null);
    try {
      const res = await scannerAPI.testPayload({ payload: payload.trim(), context });
      setResult(res.data.analysis);
      if (res.data.analysis.classification === 'MALICIOUS') toast.error('🚨 Malicious payload detected!');
      else if (res.data.analysis.classification === 'SUSPICIOUS') toast('⚠️ Suspicious payload flagged', { icon: '⚠️' });
      else toast.success('✅ Payload is safe');
    } catch (err) {
      toast.error(err.response?.data?.message || 'Analysis failed');
    } finally { setLoading(false); }
  };

  const handleBulkTest = async () => {
    const lines = bulkInput.split('\n').map(l => l.trim()).filter(Boolean);
    if (!lines.length) return toast.error('Enter payloads (one per line)');
    if (lines.length > 10) return toast.error('Max 10 payloads for bulk test');
    setBulkLoading(true);
    setBulkResults([]);
    try {
      const res = await scannerAPI.bulkTest(lines);
      setBulkResults(res.data.results || []);
      toast.success(`Scanned ${lines.length} payloads`);
    } catch { toast.error('Bulk scan failed'); }
    finally { setBulkLoading(false); }
  };

  const useSample = (sample) => {
    setPayload(sample);
    setResult(null);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Vulnerability Scanner</h1>
          <p className="page-subtitle">Test payloads against SentinelAI's Gemini-powered detection engine</p>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 340px', gap: 20 }}>
        {/* Left Column */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>

          {/* Single Payload Tester */}
          <div className="card">
            <div className="card-header">
              <span className="card-title">⚡ Single Payload Analysis</span>
              <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>Powered by Gemini 1.5 Flash</span>
            </div>
            <form onSubmit={handleTest}>
              <div className="form-group">
                <label className="form-label">Payload to Analyze</label>
                <textarea
                  className="form-textarea"
                  value={payload}
                  onChange={e => setPayload(e.target.value)}
                  placeholder={"Enter any payload...\n\nExamples:\n' OR 1=1 --\n<script>alert(1)</script>\n../../../../etc/passwd"}
                  rows={5}
                />
              </div>
              <div className="form-group">
                <label className="form-label">Context (optional)</label>
                <input
                  className="form-input"
                  value={context}
                  onChange={e => setContext(e.target.value)}
                  placeholder="e.g. Login form, Search query, URL parameter…"
                />
              </div>
              <div style={{ display: 'flex', gap: 10 }}>
                <button type="submit" className="btn btn-primary" disabled={loading} style={{ flex: 1, justifyContent: 'center' }}>
                  {loading ? (
                    <><div className="spinner" style={{ width: 16, height: 16, borderWidth: 2 }} /> Analyzing with AI...</>
                  ) : <><Zap size={15} /> Analyze Payload</>}
                </button>
                <button type="button" className="btn btn-ghost" onClick={() => { setPayload(''); setResult(null); }}>
                  <RefreshCw size={14} /> Clear
                </button>
              </div>
            </form>

            {/* Result */}
            {result && (
              <div className={`scanner-result ${classColor[result.classification] || 'safe'}`} style={{ marginTop: 20 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
                  <span style={{ fontSize: 28 }}>{classIcon[result.classification]}</span>
                  <div>
                    <div style={{ fontSize: 18, fontWeight: 700 }}>{result.classification}</div>
                    <div style={{ fontSize: 13, color: 'var(--text-secondary)' }}>
                      Attack Type: <strong>{result.attackType?.replace(/_/g, ' ') || '—'}</strong>
                    </div>
                  </div>
                  <span style={{
                    marginLeft: 'auto', fontSize: 22, fontWeight: 800,
                    color: confBarColor[result.classification],
                  }}>
                    {result.confidence}%
                  </span>
                </div>

                {/* Confidence bar */}
                <div className="confidence-bar-wrap">
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, color: 'var(--text-muted)', marginBottom: 4 }}>
                    <span>Confidence</span><span>{result.confidence}%</span>
                  </div>
                  <div className="confidence-bar-track">
                    <div
                      className="confidence-bar-fill"
                      style={{ width: `${result.confidence}%`, background: confBarColor[result.classification] }}
                    />
                  </div>
                </div>

                <div style={{ margin: '12px 0', fontSize: 14, color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                  <strong>Reason: </strong>{result.reason}
                </div>

                {result.indicators?.length > 0 && (
                  <div>
                    <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                      Indicators Detected
                    </div>
                    {result.indicators.map((ind, i) => (
                      <div key={i} style={{
                        display: 'flex', alignItems: 'center', gap: 8, padding: '6px 10px',
                        background: 'rgba(0,0,0,0.2)', borderRadius: 6, marginBottom: 4,
                        fontSize: 13, color: 'var(--text-secondary)', fontFamily: 'JetBrains Mono, monospace',
                      }}>
                        <span style={{ color: 'var(--accent-rose)' }}>⚡</span> {ind}
                      </div>
                    ))}
                  </div>
                )}

                <div style={{ marginTop: 12 }}>
                  <span style={{
                    padding: '5px 14px', borderRadius: 99, fontSize: 12, fontWeight: 600,
                    background: result.recommendation === 'BLOCK' ? 'rgba(244,63,94,0.15)' : result.recommendation === 'MONITOR' ? 'rgba(245,158,11,0.15)' : 'rgba(16,185,129,0.15)',
                    color: result.recommendation === 'BLOCK' ? 'var(--malicious)' : result.recommendation === 'MONITOR' ? 'var(--suspicious)' : 'var(--safe)',
                  }}>
                    Recommended Action: {result.recommendation}
                  </span>
                </div>
              </div>
            )}
          </div>

          {/* Bulk Tester */}
          <div className="card">
            <div className="card-header">
              <span className="card-title">📦 Bulk Payload Test</span>
              <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>Up to 10 payloads</span>
            </div>
            <div className="form-group">
              <label className="form-label">Payloads (one per line)</label>
              <textarea
                className="form-textarea"
                value={bulkInput}
                onChange={e => setBulkInput(e.target.value)}
                placeholder={"' OR 1=1 --\n<script>alert(1)</script>\n../../../../etc/passwd"}
                rows={6}
              />
            </div>
            <button className="btn btn-primary" onClick={handleBulkTest} disabled={bulkLoading}>
              {bulkLoading
                ? <><div className="spinner" style={{ width: 16, height: 16, borderWidth: 2 }} /> Scanning...</>
                : <><ShieldAlert size={15} /> Run Bulk Scan</>}
            </button>

            {bulkResults.length > 0 && (
              <div style={{ marginTop: 16, display: 'flex', flexDirection: 'column', gap: 8 }}>
                {bulkResults.map((r, i) => (
                  <div key={i} style={{
                    display: 'flex', alignItems: 'center', gap: 12,
                    padding: '10px 14px', borderRadius: 10,
                    border: `1px solid ${r.result.classification === 'MALICIOUS' ? 'rgba(244,63,94,0.25)' : r.result.classification === 'SUSPICIOUS' ? 'rgba(245,158,11,0.25)' : 'rgba(16,185,129,0.2)'}`,
                    background: r.result.classification === 'MALICIOUS' ? 'rgba(244,63,94,0.05)' : r.result.classification === 'SUSPICIOUS' ? 'rgba(245,158,11,0.05)' : 'rgba(16,185,129,0.03)',
                  }}>
                    <span>{classIcon[r.result.classification] || '❓'}</span>
                    <span className="mono" style={{ flex: 1, fontSize: 12, color: 'var(--text-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {r.payload}
                    </span>
                    <span style={{ fontSize: 11, fontWeight: 700, color: confBarColor[r.result.classification] }}>
                      {r.result.classification}
                    </span>
                    <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{r.result.confidence}%</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Right Column — Sample Payloads */}
        <div className="card" style={{ alignSelf: 'start', position: 'sticky', top: 80 }}>
          <div className="card-header">
            <span className="card-title">🎯 Sample Payloads</span>
          </div>
          <p style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 14 }}>
            Click any payload to load it into the analyzer:
          </p>
          {!samples ? (
            <div className="spinner" style={{ margin: '20px auto', width: 24, height: 24 }} />
          ) : (
            Object.entries(samples).map(([category, payloads]) => (
              <div key={category} style={{ marginBottom: 10 }}>
                <button
                  style={{
                    width: '100%', display: 'flex', justifyContent: 'space-between',
                    alignItems: 'center', background: 'rgba(255,255,255,0.04)',
                    border: '1px solid var(--border)', borderRadius: 8,
                    padding: '8px 12px', color: 'var(--text-primary)',
                    fontSize: 13, fontWeight: 500, cursor: 'pointer',
                  }}
                  onClick={() => setOpenCategory(openCategory === category ? null : category)}
                >
                  <span>{category.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())}</span>
                  {openCategory === category ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                </button>
                {openCategory === category && (
                  <div style={{ marginTop: 6, display: 'flex', flexDirection: 'column', gap: 4 }}>
                    {payloads.map((p, i) => (
                      <button
                        key={i}
                        onClick={() => useSample(p)}
                        title="Click to use this payload"
                        style={{
                          textAlign: 'left', padding: '8px 12px',
                          background: 'rgba(0,0,0,0.3)', border: '1px solid var(--border)',
                          borderRadius: 7, color: 'var(--accent-cyan)', cursor: 'pointer',
                          fontFamily: 'JetBrains Mono, monospace', fontSize: 12,
                          transition: 'var(--transition)', wordBreak: 'break-all',
                        }}
                        onMouseEnter={e => e.currentTarget.style.borderColor = 'var(--border-accent)'}
                        onMouseLeave={e => e.currentTarget.style.borderColor = 'var(--border)'}
                      >
                        {p}
                      </button>
                    ))}
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}

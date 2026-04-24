import { useState, useEffect } from 'react';
import { statsAPI } from '../services/api';
import {
  ResponsiveContainer, AreaChart, Area, XAxis, YAxis, CartesianGrid,
  Tooltip, PieChart, Pie, Cell, Legend, BarChart, Bar
} from 'recharts';

const COLORS = {
  MALICIOUS: '#f43f5e',
  SUSPICIOUS: '#f59e0b',
  SAFE: '#10b981',
  SQL_INJECTION: '#f43f5e',
  XSS: '#8b5cf6',
  CSRF: '#f59e0b',
  PATH_TRAVERSAL: '#06b6d4',
  COMMAND_INJECTION: '#fb923c',
  UNKNOWN: '#64748b',
  NONE: '#334155',
};

const PIE_COLORS = ['#f43f5e','#8b5cf6','#f59e0b','#06b6d4','#fb923c','#6366f1','#10b981','#64748b'];

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div style={{
      background: 'rgba(13,17,23,0.95)', border: '1px solid rgba(99,102,241,0.3)',
      borderRadius: 10, padding: '12px 16px', fontSize: 13,
    }}>
      <p style={{ color: 'var(--text-muted)', marginBottom: 6 }}>{label}</p>
      {payload.map(p => (
        <div key={p.name} style={{ color: p.color, fontWeight: 500 }}>
          {p.name}: {p.value?.toLocaleString()}
        </div>
      ))}
    </div>
  );
};

export default function Analytics() {
  const [period, setPeriod] = useState('24h');
  const [timeline, setTimeline] = useState([]);
  const [attackTypes, setAttackTypes] = useState([]);
  const [topIPs, setTopIPs] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetch = async () => {
      setLoading(true);
      try {
        const [tlRes, atRes, ipRes] = await Promise.all([
          statsAPI.getTimeline(period),
          statsAPI.getAttackTypes(),
          statsAPI.getTopIPs(),
        ]);
        setTimeline(tlRes.data.data || []);
        setAttackTypes(atRes.data.data || []);
        setTopIPs(ipRes.data.data || []);
      } catch (e) { console.error(e); }
      finally { setLoading(false); }
    };
    fetch();
  }, [period]);

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Analytics</h1>
          <p className="page-subtitle">Deep-dive into attack patterns and traffic trends</p>
        </div>
        {/* Period Picker */}
        <div style={{ display: 'flex', gap: 8 }}>
          {['24h', '7d', '30d'].map(p => (
            <button
              key={p}
              onClick={() => setPeriod(p)}
              className={`btn btn-sm ${period === p ? 'btn-primary' : 'btn-ghost'}`}
            >
              {p}
            </button>
          ))}
        </div>
      </div>

      {/* Traffic Timeline */}
      <div className="card" style={{ marginBottom: 20 }}>
        <div className="card-header">
          <span className="card-title">📈 Traffic Timeline — {period}</span>
          <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
            {timeline.reduce((a, t) => a + (t.total || 0), 0).toLocaleString()} total requests
          </span>
        </div>
        {!loading && timeline.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '60px', color: 'var(--text-muted)' }}>
            No data available for this period
          </div>
        ) : (
          <ResponsiveContainer width="100%" height={280}>
            <AreaChart data={timeline} margin={{ top: 10, right: 20, bottom: 0, left: 0 }}>
              <defs>
                <linearGradient id="gradSafe" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#10b981" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#10b981" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="gradSusp" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#f59e0b" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#f59e0b" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="gradMal" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#f43f5e" stopOpacity={0.4} />
                  <stop offset="95%" stopColor="#f43f5e" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
              <XAxis
                dataKey="time"
                tick={{ fontSize: 11, fill: '#64748b' }}
                tickFormatter={v => v?.slice(-5)}
                axisLine={false} tickLine={false}
              />
              <YAxis tick={{ fontSize: 11, fill: '#64748b' }} axisLine={false} tickLine={false} />
              <Tooltip content={<CustomTooltip />} />
              <Legend wrapperStyle={{ fontSize: 13, paddingTop: 12 }} />
              <Area type="monotone" dataKey="SAFE" stroke="#10b981" fill="url(#gradSafe)" strokeWidth={2} dot={false} />
              <Area type="monotone" dataKey="SUSPICIOUS" stroke="#f59e0b" fill="url(#gradSusp)" strokeWidth={2} dot={false} />
              <Area type="monotone" dataKey="MALICIOUS" stroke="#f43f5e" fill="url(#gradMal)" strokeWidth={2} dot={false} />
            </AreaChart>
          </ResponsiveContainer>
        )}
      </div>

      <div className="chart-section">
        {/* Attack Type Pie */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">🎯 Attack Type Distribution</span>
          </div>
          {!loading && attackTypes.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '60px 0', color: 'var(--text-muted)' }}>
              ✅ No attacks detected
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={300}>
              <PieChart>
                <Pie
                  data={attackTypes}
                  dataKey="count"
                  nameKey="attackType"
                  cx="50%" cy="50%"
                  innerRadius={70} outerRadius={110}
                  paddingAngle={3}
                  label={({ attackType, percent }) =>
                    `${attackType?.replace(/_/g,' ')} (${(percent * 100).toFixed(0)}%)`
                  }
                  labelLine={false}
                >
                  {attackTypes.map((_, i) => (
                    <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip
                  formatter={(v, n) => [v, n?.replace(/_/g, ' ')]}
                  contentStyle={{ background: 'rgba(13,17,23,0.95)', border: '1px solid rgba(99,102,241,0.3)', borderRadius: 10 }}
                />
                <Legend
                  formatter={(v) => v?.replace(/_/g, ' ')}
                  wrapperStyle={{ fontSize: 12 }}
                />
              </PieChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* Top Attacking IPs */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">🌐 Top Attacking IPs</span>
          </div>
          {topIPs.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '60px 0', color: 'var(--text-muted)' }}>
              ✅ No attacking IPs
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={300}>
              <BarChart
                data={topIPs}
                layout="vertical"
                margin={{ top: 5, right: 20, left: 20, bottom: 5 }}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" horizontal={false} />
                <XAxis type="number" tick={{ fontSize: 11, fill: '#64748b' }} axisLine={false} tickLine={false} />
                <YAxis
                  dataKey="ip" type="category"
                  tick={{ fontSize: 11, fill: '#94a3b8', fontFamily: 'JetBrains Mono, monospace' }}
                  axisLine={false} tickLine={false} width={110}
                />
                <Tooltip content={<CustomTooltip />} />
                <Bar dataKey="count" name="Attacks" fill="url(#barGrad)" radius={[0, 4, 4, 0]}>
                  {topIPs.map((_, i) => (
                    <Cell key={i} fill={i === 0 ? '#f43f5e' : i < 3 ? '#f59e0b' : '#6366f1'} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>
    </div>
  );
}

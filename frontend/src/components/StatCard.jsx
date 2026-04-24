/**
 * StatCard — individual metric card for the dashboard overview strip
 * Props: icon, label, value, accent (CSS var color), change (optional), onClick (optional)
 */
export default function StatCard({ icon, label, value, accent = 'var(--accent-indigo)', change, loading, onClick }) {
  return (
    <div
      className={`stat-card${onClick ? ' stat-card-clickable' : ''}`}
      style={{ '--card-accent': accent, '--icon-bg': `${accent}18` }}
      onClick={() => {
        if (onClick) {
          console.log(`[StatCard] Clicked: ${label}`);
          onClick({ label, value });
        }
      }}
      role={onClick ? 'button' : undefined}
      tabIndex={onClick ? 0 : undefined}
      onKeyDown={onClick ? (e) => e.key === 'Enter' && onClick({ label, value }) : undefined}
    >
      <div className="stat-icon">{icon}</div>
      <div className="stat-info">
        {loading ? (
          <div style={{
            width: 60, height: 28, borderRadius: 6,
            background: 'rgba(255,255,255,0.07)',
            animation: 'pulse 1.5s ease-in-out infinite'
          }} />
        ) : (
          <div className="stat-value">{typeof value === 'number' ? value.toLocaleString() : value}</div>
        )}
        <div className="stat-label">{label}</div>
        {change !== undefined && (
          <div className={`stat-change ${change >= 0 ? 'up' : 'down'}`}>
            {change >= 0 ? '▲' : '▼'} {Math.abs(change)}% today
          </div>
        )}
      </div>
    </div>
  );
}

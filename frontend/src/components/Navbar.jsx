import { NavLink, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { useEffect, useState, useRef } from 'react';
import { statsAPI } from '../services/api';
import {
  LayoutDashboard, BarChart2, ScrollText,
  ShieldAlert, Bell, LogOut, Shield, UserRoundSearch, X, Check
} from 'lucide-react';

const navItems = [
  { to: '/',          label: 'Dashboard', icon: <LayoutDashboard size={16} /> },
  { to: '/analytics', label: 'Analytics',  icon: <BarChart2 size={16} /> },
  { to: '/logs',      label: 'Logs',       icon: <ScrollText size={16} /> },
  { to: '/scanner',   label: 'Scanner',    icon: <ShieldAlert size={16} /> },
  { to: '/profiles',  label: 'Profiles',   icon: <UserRoundSearch size={16} /> },
];

const severityColor = {
  CRITICAL: '#f43f5e', HIGH: '#f59e0b', MEDIUM: '#6366f1', LOW: '#10b981',
};

export default function Navbar() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [alertCount, setAlertCount] = useState(0);
  const [alerts, setAlerts] = useState([]);
  const [showNotifications, setShowNotifications] = useState(false);
  const panelRef = useRef(null);
  const bellRef = useRef(null);

  useEffect(() => {
    const fetchAlerts = async () => {
      try {
        const res = await statsAPI.getAlerts(50);
        const data = res.data.data || [];
        setAlerts(data);
        const unread = data.filter(a => !a.isRead).length;
        setAlertCount(unread);
      } catch {}
    };
    fetchAlerts();
    const interval = setInterval(fetchAlerts, 15000);
    return () => clearInterval(interval);
  }, []);

  // Close notification panel on outside click
  useEffect(() => {
    const handleClickOutside = (e) => {
      if (
        showNotifications &&
        panelRef.current && !panelRef.current.contains(e.target) &&
        bellRef.current && !bellRef.current.contains(e.target)
      ) {
        setShowNotifications(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [showNotifications]);

  const handleBellClick = () => {
    console.log('[Navbar] Bell clicked — toggling notifications panel');
    setShowNotifications(prev => !prev);
  };

  const handleMarkAllRead = async () => {
    try {
      const unreadIds = alerts.filter(a => !a.isRead).map(a => a._id);
      if (unreadIds.length > 0) {
        await statsAPI.markAlertsRead(unreadIds);
        setAlerts(prev => prev.map(a => ({ ...a, isRead: true })));
        setAlertCount(0);
        console.log('[Navbar] Marked all alerts as read');
      }
    } catch (err) {
      console.error('[Navbar] Failed to mark alerts read:', err);
    }
  };

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <nav className="navbar">
      {/* Brand */}
      <div className="navbar-brand">
        <div className="brand-icon">🛡️</div>
        <span>Sentinel<span style={{ color: 'var(--accent-indigo)' }}>AI</span></span>
      </div>

      {/* Nav Links */}
      <ul className="navbar-nav">
        {navItems.map(({ to, label, icon }) => (
          <li key={to}>
            <NavLink
              to={to}
              end={to === '/'}
              className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}
            >
              {icon}
              {label}
            </NavLink>
          </li>
        ))}
      </ul>

      {/* Right Side */}
      <div className="navbar-right">
        {/* Live Indicator */}
        <div className="live-indicator" style={{ marginRight: 8 }}>
          <div className="live-dot" />
          LIVE
        </div>

        {/* Alert Bell */}
        <div style={{ position: 'relative' }}>
          <div
            ref={bellRef}
            className="alert-badge"
            title="Unread Alerts"
            onClick={handleBellClick}
            role="button"
            tabIndex={0}
            onKeyDown={(e) => e.key === 'Enter' && handleBellClick()}
          >
            <Bell size={16} />
            {alertCount > 0 && (
              <span className="alert-count">{alertCount > 9 ? '9+' : alertCount}</span>
            )}
          </div>

          {/* Notification Dropdown Panel */}
          {showNotifications && (
            <div ref={panelRef} className="notification-panel">
              <div className="notification-panel-header">
                <span style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)' }}>
                  🔔 Notifications
                </span>
                <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                  {alertCount > 0 && (
                    <button
                      onClick={handleMarkAllRead}
                      className="btn btn-ghost btn-sm"
                      style={{ fontSize: 11, padding: '4px 8px', gap: 4 }}
                      title="Mark all read"
                    >
                      <Check size={12} />
                      Read all
                    </button>
                  )}
                  <button
                    onClick={() => setShowNotifications(false)}
                    style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', padding: 2 }}
                  >
                    <X size={14} />
                  </button>
                </div>
              </div>

              <div className="notification-panel-body">
                {alerts.length === 0 ? (
                  <div style={{ textAlign: 'center', padding: '32px 0', color: 'var(--text-muted)', fontSize: 13 }}>
                    ✅ No notifications
                  </div>
                ) : (
                  alerts.slice(0, 10).map((alert) => (
                    <div
                      key={alert._id}
                      className={`notification-item${!alert.isRead ? ' unread' : ''}`}
                    >
                      <div
                        className="notification-dot"
                        style={{ background: severityColor[alert.severity] || '#6366f1' }}
                      />
                      <div style={{ minWidth: 0, flex: 1 }}>
                        <div style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-primary)', marginBottom: 2 }}>
                          {alert.title}
                        </div>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                          {alert.ipAddress && <span className="mono">{alert.ipAddress} · </span>}
                          {new Date(alert.createdAt).toLocaleString()}
                        </div>
                      </div>
                      <span style={{
                        fontSize: 9, fontWeight: 700, padding: '2px 6px', borderRadius: 99,
                        background: `${severityColor[alert.severity] || '#6366f1'}20`,
                        color: severityColor[alert.severity] || '#6366f1',
                        border: `1px solid ${severityColor[alert.severity] || '#6366f1'}40`,
                        flexShrink: 0,
                        textTransform: 'uppercase',
                      }}>
                        {alert.severity}
                      </span>
                    </div>
                  ))
                )}
              </div>

              {alerts.length > 10 && (
                <div className="notification-panel-footer">
                  <button
                    onClick={() => { setShowNotifications(false); navigate('/'); }}
                    className="btn btn-ghost btn-sm"
                    style={{ width: '100%', justifyContent: 'center', fontSize: 12 }}
                  >
                    View all alerts on Dashboard
                  </button>
                </div>
              )}
            </div>
          )}
        </div>

        {/* User Avatar */}
        <div
          className="user-avatar"
          title={`${user?.username} (${user?.role})`}
        >
          {user?.username?.[0]?.toUpperCase() || 'U'}
        </div>

        {/* Logout */}
        <button
          onClick={handleLogout}
          className="btn btn-ghost btn-sm"
          title="Logout"
          style={{ gap: 6 }}
        >
          <LogOut size={15} />
          <span style={{ fontSize: 13 }}>Logout</span>
        </button>
      </div>
    </nav>
  );
}

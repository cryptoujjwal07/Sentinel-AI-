import { useState, useEffect, useRef } from 'react';
import { useAuth } from '../context/AuthContext';
import toast from 'react-hot-toast';

// Inline Google "G" logo SVG for the login button
const GoogleIcon = () => (
  <svg width="20" height="20" viewBox="0 0 48 48">
    <path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/>
    <path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/>
    <path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/>
    <path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/>
  </svg>
);

export default function Login() {
  const { login, register, loginWithGoogle } = useAuth();
  const [tab, setTab] = useState('login'); // 'login' | 'register'
  const [loading, setLoading] = useState(false);
  const [googleLoading, setGoogleLoading] = useState(false);
  const [form, setForm] = useState({ username: '', email: '', password: '' });
  const emailRef = useRef();

  useEffect(() => { emailRef.current?.focus(); }, [tab]);

  const handleChange = e => setForm(f => ({ ...f, [e.target.name]: e.target.value }));

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      if (tab === 'login') {
        await login(form.email, form.password);
        toast.success('Welcome back to SentinelAI!');
      } else {
        if (!form.username.trim()) return toast.error('Username is required');
        await register(form.username, form.email, form.password);
        toast.success('Account created! Welcome aboard.');
      }
    } catch (err) {
      const msg = err.response?.data?.message || 'Something went wrong';
      toast.error(msg);
    } finally {
      setLoading(false);
    }
  };

  const handleGoogleLogin = async () => {
    setGoogleLoading(true);
    try {
      await loginWithGoogle();
      toast.success('Welcome to SentinelAI!');
    } catch (err) {
      // Don't show error if user simply closed the popup
      if (err.code === 'auth/popup-closed-by-user' || err.code === 'auth/cancelled-popup-request') {
        return;
      }
      const msg = err.response?.data?.message || err.message || 'Google login failed';
      toast.error(msg);
    } finally {
      setGoogleLoading(false);
    }
  };

  return (
    <div className="login-page">
      {/* Background orbs */}
      <div className="login-bg-orb login-bg-orb-1" />
      <div className="login-bg-orb login-bg-orb-2" />

      {/* Animated grid lines */}
      <div style={{
        position: 'absolute', inset: 0, zIndex: 0, opacity: 0.03,
        backgroundImage: 'linear-gradient(rgba(99,102,241,1) 1px, transparent 1px), linear-gradient(90deg, rgba(99,102,241,1) 1px, transparent 1px)',
        backgroundSize: '50px 50px',
      }} />

      <div className="login-card" style={{ zIndex: 2 }}>
        {/* Logo */}
        <div className="login-logo">
          <div className="login-logo-icon">🛡️</div>
          <h1>SentinelAI</h1>
          <p>AI-Powered Web Application Firewall</p>
        </div>

        {/* Google Login Button */}
        <button
          type="button"
          className="google-login-btn"
          onClick={handleGoogleLogin}
          disabled={googleLoading || loading}
          id="google-login-button"
        >
          {googleLoading ? (
            <span style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <div className="spinner" style={{ width: 18, height: 18, borderWidth: 2 }} />
              Signing in with Google...
            </span>
          ) : (
            <>
              <GoogleIcon />
              <span>Continue with Google</span>
            </>
          )}
        </button>

        {/* Divider */}
        <div className="login-divider">
          <span>or</span>
        </div>

        {/* Tabs */}
        <div className="login-tabs">
          <button
            className={`login-tab${tab === 'login' ? ' active' : ''}`}
            onClick={() => setTab('login')}
          >Login</button>
          <button
            className={`login-tab${tab === 'register' ? ' active' : ''}`}
            onClick={() => setTab('register')}
          >Register</button>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit}>
          {tab === 'register' && (
            <div className="form-group">
              <label className="form-label">Username</label>
              <input
                name="username"
                value={form.username}
                onChange={handleChange}
                className="form-input"
                placeholder="johndoe"
                autoComplete="username"
              />
            </div>
          )}

          <div className="form-group">
            <label className="form-label">Email</label>
            <input
              ref={emailRef}
              name="email"
              type="email"
              value={form.email}
              onChange={handleChange}
              className="form-input"
              placeholder="admin@sentinelai.com"
              required
              autoComplete="email"
            />
          </div>

          <div className="form-group">
            <label className="form-label">Password</label>
            <input
              name="password"
              type="password"
              value={form.password}
              onChange={handleChange}
              className="form-input"
              placeholder="••••••••"
              required
              autoComplete="current-password"
            />
          </div>

          <button
            type="submit"
            className="btn btn-primary btn-lg"
            style={{ width: '100%', marginTop: 8, justifyContent: 'center' }}
            disabled={loading || googleLoading}
          >
            {loading ? (
              <span style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <div className="spinner" style={{ width: 18, height: 18, borderWidth: 2 }} />
                {tab === 'login' ? 'Signing in...' : 'Creating account...'}
              </span>
            ) : (
              tab === 'login' ? '🔐 Sign In' : '🚀 Create Account'
            )}
          </button>
        </form>

        {/* Features Strip */}
        <div style={{
          marginTop: 28, paddingTop: 20,
          borderTop: '1px solid var(--border)',
          display: 'flex', justifyContent: 'center', gap: 20,
          flexWrap: 'wrap',
        }}>
          {['🤖 AI Detection', '🔒 IP Blocking', '📊 Real-time Logs'].map(f => (
            <span key={f} style={{ fontSize: 12, color: 'var(--text-muted)' }}>{f}</span>
          ))}
        </div>
      </div>
    </div>
  );
}

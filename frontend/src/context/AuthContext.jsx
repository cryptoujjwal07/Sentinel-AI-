import { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { authAPI } from '../services/api';
import { signInWithGoogle } from '../config/firebase';

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(localStorage.getItem('sentinel_token'));
  const [loading, setLoading] = useState(true);       // Per-route auth check
  const [appLoading, setAppLoading] = useState(true);  // Initial app load (loading screen)

  // ── Initialize auth state on mount ────────────────────────────────────────
  useEffect(() => {
    const initAuth = async () => {
      const savedToken = localStorage.getItem('sentinel_token');
      if (savedToken) {
        try {
          // Verify token is still valid by calling /me
          const res = await authAPI.getMe();
          setUser(res.data.user);
          setToken(savedToken);
        } catch {
          // Token expired or invalid — clear everything
          localStorage.removeItem('sentinel_token');
          localStorage.removeItem('sentinel_user');
          setToken(null);
          setUser(null);
        }
      }
      setLoading(false);
    };
    initAuth();
  }, []);

  // ── Save auth data to state + localStorage ────────────────────────────────
  const saveAuth = useCallback((tokenValue, userValue) => {
    localStorage.setItem('sentinel_token', tokenValue);
    localStorage.setItem('sentinel_user', JSON.stringify(userValue));
    setToken(tokenValue);
    setUser(userValue);
  }, []);

  // ── Local email/password login ────────────────────────────────────────────
  const login = async (email, password) => {
    const res = await authAPI.login({ email, password });
    const { token, user } = res.data;
    saveAuth(token, user);
    return user;
  };

  // ── Local registration ────────────────────────────────────────────────────
  const register = async (username, email, password) => {
    const res = await authAPI.register({ username, email, password });
    const { token, user } = res.data;
    saveAuth(token, user);
    return user;
  };

  // ── Google Sign-In ────────────────────────────────────────────────────────
  const loginWithGoogle = async () => {
    // Step 1: Firebase popup → get ID token
    const idToken = await signInWithGoogle();
    // Step 2: Send token to backend for verification + JWT
    const res = await authAPI.googleLogin(idToken);
    const { token, user } = res.data;
    saveAuth(token, user);
    return user;
  };

  // ── Logout ────────────────────────────────────────────────────────────────
  const logout = () => {
    localStorage.removeItem('sentinel_token');
    localStorage.removeItem('sentinel_user');
    setToken(null);
    setUser(null);
  };

  // ── Mark app loading complete (called by LoadingScreen) ───────────────────
  const finishAppLoading = useCallback(() => {
    setAppLoading(false);
  }, []);

  return (
    <AuthContext.Provider value={{
      user,
      token,
      loading,
      appLoading,
      login,
      register,
      loginWithGoogle,
      logout,
      finishAppLoading,
      isAuthenticated: !!token,
    }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
};

export default AuthContext;

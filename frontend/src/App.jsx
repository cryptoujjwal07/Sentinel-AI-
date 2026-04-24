import { Routes, Route, Navigate } from 'react-router-dom';
import { useAuth } from './context/AuthContext';
import LoadingScreen from './components/LoadingScreen';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import Analytics from './pages/Analytics';
import Logs from './pages/Logs';
import Scanner from './pages/Scanner';
import Profiles from './pages/Profiles';
import Navbar from './components/Navbar';

// Protected route wrapper
const ProtectedRoute = ({ children }) => {
  const { isAuthenticated, loading } = useAuth();
  if (loading) return <div className="loading-screen"><div className="spinner" /></div>;
  return isAuthenticated ? children : <Navigate to="/login" replace />;
};

// Layout wrapper for authenticated pages
const AppLayout = ({ children }) => (
  <div className="app-layout">
    <Navbar />
    <main className="main-content">{children}</main>
  </div>
);

function App() {
  const { isAuthenticated, appLoading, finishAppLoading } = useAuth();

  // Show full-screen loading animation on initial app load
  if (appLoading) {
    return <LoadingScreen onFinished={finishAppLoading} />;
  }

  return (
    <Routes>
      <Route path="/login" element={isAuthenticated ? <Navigate to="/" replace /> : <Login />} />

      <Route path="/" element={
        <ProtectedRoute>
          <AppLayout><Dashboard /></AppLayout>
        </ProtectedRoute>
      } />
      <Route path="/analytics" element={
        <ProtectedRoute>
          <AppLayout><Analytics /></AppLayout>
        </ProtectedRoute>
      } />
      <Route path="/logs" element={
        <ProtectedRoute>
          <AppLayout><Logs /></AppLayout>
        </ProtectedRoute>
      } />
      <Route path="/scanner" element={
        <ProtectedRoute>
          <AppLayout><Scanner /></AppLayout>
        </ProtectedRoute>
      } />
      <Route path="/profiles" element={
        <ProtectedRoute>
          <AppLayout><Profiles /></AppLayout>
        </ProtectedRoute>
      } />

      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

export default App;

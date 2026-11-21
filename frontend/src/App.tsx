import React from 'react';
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import { ThemeProvider } from './context/ThemeContext';
import { ToastProvider } from './context/ToastContext';
import { AuthProvider, useAuth } from './context/AuthContext';
import { LiveEventsProvider } from './context/LiveEventsContext';
import { Layout } from './components/Layout';
import { LoginPage } from './pages/LoginPage';
import { DashboardPage } from './pages/DashboardPage';
import { GraphPage } from './pages/GraphPage';
import { AssetsPage } from './pages/AssetsPage';
import { DiffPage } from './pages/DiffPage';
import { ScansPage } from './pages/ScansPage';
import { SignaturesPage } from './pages/SignaturesPage';
import { AdminPage } from './pages/AdminPage';
import { PERMISSIONS } from './lib/permissions';

function ProtectedRoute({
  children,
  anyPerms,
}: {
  children: React.ReactNode;
  anyPerms?: string[];
}) {
  const { user, loading, canAny } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen bg-bg-primary flex items-center justify-center text-sm text-text-muted font-mono">
        Ładowanie AegisASI...
      </div>
    );
  }

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  if (anyPerms && anyPerms.length > 0 && !canAny(anyPerms)) {
    return (
      <div className="rounded-xl border border-rose-500/35 bg-rose-500/10 p-8 text-center space-y-2 max-w-lg mx-auto mt-12">
        <div className="text-lg font-bold text-rose-400">403 — Brak uprawnień</div>
        <p className="text-xs text-text-secondary">
          Twoja obecna rola nie posiada wymaganych uprawnień do wyświetlenia tej sekcji.
          Możesz przełączyć rolę w górnym menu, aby przetestować RBAC.
        </p>
      </div>
    );
  }

  return <>{children}</>;
}

function AppRoutes() {
  const { user, loading } = useAuth();

  return (
    <Routes>
      <Route
        path="/login"
        element={!loading && user ? <Navigate to="/" replace /> : <LoginPage />}
      />

      <Route
        path="/"
        element={
          <ProtectedRoute>
            <Layout />
          </ProtectedRoute>
        }
      >
        <Route
          index
          element={
            <ProtectedRoute anyPerms={[PERMISSIONS.DASHBOARD_READ]}>
              <DashboardPage />
            </ProtectedRoute>
          }
        />
        <Route
          path="graph"
          element={
            <ProtectedRoute anyPerms={[PERMISSIONS.ASSETS_READ]}>
              <GraphPage />
            </ProtectedRoute>
          }
        />
        <Route
          path="assets"
          element={
            <ProtectedRoute anyPerms={[PERMISSIONS.ASSETS_READ]}>
              <AssetsPage />
            </ProtectedRoute>
          }
        />
        <Route
          path="diff"
          element={
            <ProtectedRoute anyPerms={[PERMISSIONS.SCANS_READ]}>
              <DiffPage />
            </ProtectedRoute>
          }
        />
        <Route
          path="scans"
          element={
            <ProtectedRoute anyPerms={[PERMISSIONS.SCANS_READ]}>
              <ScansPage />
            </ProtectedRoute>
          }
        />
        <Route
          path="signatures"
          element={
            <ProtectedRoute anyPerms={[PERMISSIONS.SIGNATURES_READ]}>
              <SignaturesPage />
            </ProtectedRoute>
          }
        />
        <Route
          path="admin"
          element={
            <ProtectedRoute
              anyPerms={[
                PERMISSIONS.DEFECTDOJO_PUSH,
                PERMISSIONS.ADMIN_USERS,
                PERMISSIONS.ADMIN_ROLES,
                PERMISSIONS.ADMIN_SETTINGS,
                PERMISSIONS.ADMIN_AUDIT,
              ]}
            >
              <AdminPage />
            </ProtectedRoute>
          }
        />
      </Route>

      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

export default function App() {
  return (
    <ThemeProvider>
      <ToastProvider>
        <AuthProvider>
          <LiveEventsProvider>
            <BrowserRouter>
              <AppRoutes />
            </BrowserRouter>
          </LiveEventsProvider>
        </AuthProvider>
      </ToastProvider>
    </ThemeProvider>
  );
}

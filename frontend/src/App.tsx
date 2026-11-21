import React, { Suspense, lazy } from 'react';
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import { ThemeProvider } from './context/ThemeContext';
import { ToastProvider } from './context/ToastContext';
import { AuthProvider, useAuth } from './context/AuthContext';
import { LiveEventsProvider } from './context/LiveEventsContext';
import { Layout } from './components/Layout';
import { LoginPage } from './pages/LoginPage';
import { DashboardPage } from './pages/DashboardPage';
import { AssetsPage } from './pages/AssetsPage';
import { GalleryPage } from './pages/GalleryPage';
import { DiffPage } from './pages/DiffPage';
import { ScansPage } from './pages/ScansPage';
import { SignaturesPage } from './pages/SignaturesPage';
import { AdminPage } from './pages/AdminPage';
import { PoliciesPage } from './pages/PoliciesPage';
import { RemediationPage } from './pages/RemediationPage';
import { DigestPage } from './pages/DigestPage';
import { PERMISSIONS } from './lib/permissions';
import { TooltipProvider } from '@/components/ui/tooltip';
import { PeckLoader } from '@/components/Woodpecker';

// React Flow is the heaviest dependency; load the graph page only when it is opened.
const GraphPage = lazy(() => import('./pages/GraphPage').then((m) => ({ default: m.GraphPage })));

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
      <div className="flex min-h-screen items-center justify-center bg-background">
        <PeckLoader />
      </div>
    );
  }

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  if (anyPerms && anyPerms.length > 0 && !canAny(anyPerms)) {
    return (
      <div className="mx-auto mt-24 max-w-sm space-y-2 text-center">
        <div className="font-mono text-3xl font-semibold text-rose-600 dark:text-rose-400">403</div>
        <p className="text-xs tracking-wider text-muted-foreground uppercase">Missing permission (RBAC)</p>
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
              <Suspense
                fallback={
                  <div className="flex min-h-[60vh] items-center justify-center">
                    <PeckLoader />
                  </div>
                }
              >
                <GraphPage />
              </Suspense>
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
          path="gallery"
          element={
            <ProtectedRoute anyPerms={[PERMISSIONS.ASSETS_READ]}>
              <GalleryPage />
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
          path="remediation"
          element={
            <ProtectedRoute anyPerms={[PERMISSIONS.ASSETS_READ]}>
              <RemediationPage />
            </ProtectedRoute>
          }
        />
        <Route
          path="digest"
          element={
            <ProtectedRoute anyPerms={[PERMISSIONS.DASHBOARD_READ]}>
              <DigestPage />
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
          path="policies"
          element={
            <ProtectedRoute anyPerms={[PERMISSIONS.ASSETS_READ]}>
              <PoliciesPage />
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
            <TooltipProvider delay={200}>
              <BrowserRouter>
                <AppRoutes />
              </BrowserRouter>
            </TooltipProvider>
          </LiveEventsProvider>
        </AuthProvider>
      </ToastProvider>
    </ThemeProvider>
  );
}

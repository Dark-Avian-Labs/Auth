import { lazy, Suspense } from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';

import { APP_PATHS } from './paths';
import { Layout } from '../components/Layout/Layout';
import { useAuth } from '../features/auth/AuthContext';
import { RequireAuth } from '../features/auth/RequireAuth';

const LoginPage = lazy(() =>
  import('../features/auth/LoginPage').then((mod) => ({
    default: mod.LoginPage,
  })),
);
const HomePage = lazy(() =>
  import('../features/selector/HomePage').then((mod) => ({
    default: mod.HomePage,
  })),
);
const AdminPage = lazy(() =>
  import('../features/admin/AdminPage').then((mod) => ({
    default: mod.AdminPage,
  })),
);
const ProfilePage = lazy(() =>
  import('../features/profile/ProfilePage').then((mod) => ({
    default: mod.ProfilePage,
  })),
);
const LegalPage = lazy(() =>
  import('../features/legal/LegalPage').then((mod) => ({
    default: mod.LegalPage,
  })),
);

function RouteFallback() {
  return (
    <div className="flex min-h-screen items-center justify-center">
      <p className="text-sm text-muted">Loading...</p>
    </div>
  );
}

function LoginRoute() {
  const { auth } = useAuth();
  if (auth.status === 'ok') {
    return <Navigate to={APP_PATHS.home} replace />;
  }
  return <LoginPage />;
}

export function AppRoutes() {
  return (
    <Suspense fallback={<RouteFallback />}>
      <Routes>
        <Route element={<Layout />}>
          <Route path={APP_PATHS.login} element={<LoginRoute />} />
          <Route path={APP_PATHS.legal} element={<LegalPage />} />
          <Route
            path={APP_PATHS.home}
            element={
              <RequireAuth>
                <HomePage />
              </RequireAuth>
            }
          />
          <Route
            path={APP_PATHS.admin}
            element={
              <RequireAuth>
                <AdminPage />
              </RequireAuth>
            }
          />
          <Route
            path={APP_PATHS.profile}
            element={
              <RequireAuth>
                <ProfilePage />
              </RequireAuth>
            }
          />
        </Route>
      </Routes>
    </Suspense>
  );
}

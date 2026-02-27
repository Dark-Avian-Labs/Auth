import {
  Component,
  Fragment,
  lazy,
  Suspense,
  type ErrorInfo,
  type ReactNode,
} from 'react';
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

type RouteErrorBoundaryState = {
  hasError: boolean;
  isChunkError: boolean;
  retryCount: number;
};

function isChunkLoadError(error: unknown) {
  const message =
    error instanceof Error
      ? error.message
      : typeof error === 'string'
        ? error
        : '';
  const lowered = message.toLowerCase();
  return (
    lowered.includes('chunkloaderror') ||
    lowered.includes('loading chunk') ||
    lowered.includes('load chunk') ||
    lowered.includes('failed to fetch dynamically imported module') ||
    lowered.includes('importing a module script failed') ||
    lowered.includes('failed to fetch')
  );
}

class RouteErrorBoundary extends Component<
  { children: ReactNode },
  RouteErrorBoundaryState
> {
  state: RouteErrorBoundaryState = {
    hasError: false,
    isChunkError: false,
    retryCount: 0,
  };

  static getDerivedStateFromError(
    error: unknown,
  ): Partial<RouteErrorBoundaryState> {
    return {
      hasError: true,
      isChunkError: isChunkLoadError(error),
    };
  }

  componentDidCatch(error: unknown, errorInfo: ErrorInfo) {
    console.error('Route rendering failed', error, errorInfo);
  }

  private retry = () => {
    this.setState((prev) => ({
      hasError: false,
      isChunkError: false,
      retryCount: prev.retryCount + 1,
    }));
  };

  private reload = () => {
    window.location.reload();
  };

  render() {
    if (this.state.hasError) {
      return (
        <div className="flex min-h-screen flex-col items-center justify-center gap-3 px-4 text-center">
          <p className="text-sm text-muted">
            {this.state.isChunkError
              ? 'A network/chunk loading error occurred while opening this page.'
              : 'Something went wrong while loading this page.'}
          </p>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={this.retry}
              className="rounded-md bg-foreground px-3 py-1.5 text-sm text-background"
            >
              Retry
            </button>
            {this.state.isChunkError ? (
              <button
                type="button"
                onClick={this.reload}
                className="rounded-md border border-default px-3 py-1.5 text-sm"
              >
                Reload app
              </button>
            ) : null}
          </div>
        </div>
      );
    }

    return (
      <Fragment key={this.state.retryCount}>{this.props.children}</Fragment>
    );
  }
}

function RouteFallback() {
  return (
    <div
      className="flex min-h-screen items-center justify-center"
      role="status"
      aria-live="polite"
      aria-busy="true"
      aria-atomic="true"
    >
      <p className="text-sm text-muted">Loading...</p>
    </div>
  );
}

function LoginRoute() {
  const { auth } = useAuth();
  if (auth.status === 'ok') {
    return <Navigate to={APP_PATHS.home} replace />;
  }
  if (auth.status === 'loading') {
    return <RouteFallback />;
  }
  return auth.status === 'unauthenticated' ? <LoginPage /> : null;
}

function NotFoundPage() {
  return (
    <div className="flex min-h-screen flex-col items-center justify-center gap-2 px-4 text-center">
      <h1 className="text-lg font-semibold">Page not found</h1>
      <p className="text-sm text-muted">
        The page you requested does not exist.
      </p>
    </div>
  );
}

export function AppRoutes() {
  return (
    <RouteErrorBoundary>
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
            <Route path="*" element={<NotFoundPage />} />
          </Route>
        </Routes>
      </Suspense>
    </RouteErrorBoundary>
  );
}

import { useEffect, useMemo, useState, type ReactElement } from 'react';
import { Navigate, useLocation } from 'react-router-dom';

import { useAuth } from './AuthContext';
import { APP_PATHS } from '../../app/paths';

const MAX_AUTO_RETRIES = 5;
const BASE_RETRY_DELAY_MS = 1000;

export function RequireAuth({ children }: { children: ReactElement }) {
  const { auth, refresh, logout } = useAuth();
  const location = useLocation();
  const [nowMs, setNowMs] = useState(() => Date.now());
  const [retryCount, setRetryCount] = useState(0);
  const authErrorMessage = auth.error?.message;

  useEffect(() => {
    const timer =
      auth.status === 'rate_limited' &&
      typeof auth.rateLimitedUntilMs === 'number' &&
      auth.rateLimitedUntilMs > nowMs
        ? window.setInterval(() => {
            setNowMs(Date.now());
          }, 1000)
        : null;
    return () => {
      if (timer !== null) {
        window.clearInterval(timer);
      }
    };
  }, [auth.status, auth.rateLimitedUntilMs, nowMs]);

  const secondsRemaining = useMemo(() => {
    if (auth.status !== 'rate_limited' || !auth.rateLimitedUntilMs) return 0;
    return Math.max(0, Math.ceil((auth.rateLimitedUntilMs - nowMs) / 1000));
  }, [auth.status, auth.rateLimitedUntilMs, nowMs]);

  useEffect(() => {
    if (auth.status === 'rate_limited') return;
    setRetryCount(0);
  }, [auth.status]);

  useEffect(() => {
    let timer: number | null = null;
    if (
      auth.status === 'rate_limited' &&
      secondsRemaining === 0 &&
      retryCount < MAX_AUTO_RETRIES
    ) {
      const delayMs = BASE_RETRY_DELAY_MS * 2 ** retryCount;
      timer = window.setTimeout(() => {
        setRetryCount((count) => count + 1);
        void refresh();
      }, delayMs);
    }
    return () => {
      if (timer !== null) {
        window.clearTimeout(timer);
      }
    };
  }, [auth.status, secondsRemaining, retryCount, refresh]);

  if (auth.status === 'loading') {
    return (
      <div className="flex min-h-screen items-center justify-center p-6">
        <p className="text-muted">Checking session...</p>
      </div>
    );
  }

  if (auth.status === 'unauthenticated') {
    return <Navigate to={APP_PATHS.login} replace state={{ from: location }} />;
  }

  if (auth.status === 'forbidden') {
    return (
      <div className="flex min-h-screen items-center justify-center p-6">
        <div className="glass-panel max-w-md p-6 text-center">
          <h1 className="mb-2 text-xl font-semibold text-foreground">
            Access denied
          </h1>
          <p className="mb-4 text-sm text-muted">
            Your account is authenticated but does not have access to this
            application.
          </p>
          <button
            className="btn btn-accent"
            type="button"
            onClick={() => {
              void logout();
            }}
          >
            Logout
          </button>
        </div>
      </div>
    );
  }

  if (auth.status === 'error') {
    return (
      <div className="flex min-h-screen items-center justify-center p-6">
        <div className="glass-panel max-w-md p-6 text-center">
          <h1 className="mb-2 text-xl font-semibold text-foreground">
            Auth check failed
          </h1>
          <p className="mb-4 text-sm text-muted">
            {authErrorMessage ||
              'We could not verify your session right now. Please try again.'}
          </p>
          <button
            className="btn btn-accent"
            type="button"
            onClick={() => {
              void refresh();
            }}
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  if (auth.status === 'rate_limited') {
    return (
      <div className="flex min-h-screen items-center justify-center p-6">
        <div className="glass-panel max-w-md p-6 text-center">
          <h1 className="mb-2 text-xl font-semibold text-foreground">
            Too many requests
          </h1>
          <p className="mb-4 text-sm text-muted">
            Authentication checks are temporarily rate limited. Please wait
            before trying again.
          </p>
          <div className="mb-4 text-2xl font-semibold text-warning">
            {secondsRemaining}s
          </div>
          <button
            className="btn btn-accent"
            type="button"
            onClick={() => {
              void refresh();
            }}
            disabled={secondsRemaining > 0}
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  return children;
}

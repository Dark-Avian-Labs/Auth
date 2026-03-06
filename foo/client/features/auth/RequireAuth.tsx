import type { ReactElement } from 'react';
import { Navigate, useLocation } from 'react-router-dom';

import { useAuth } from './AuthContext';
import { APP_PATHS } from '../../app/paths';

export function RequireAuth({ children }: { children: ReactElement }) {
  const { auth } = useAuth();
  const location = useLocation();

  if (auth.status === 'loading') {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <p className="text-muted">Checking session...</p>
      </div>
    );
  }

  if (auth.status === 'unauthenticated') {
    return <Navigate to={APP_PATHS.login} replace state={{ from: location }} />;
  }

  return children;
}

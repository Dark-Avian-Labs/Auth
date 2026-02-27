import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react';

import type { AppSummary, AuthState, RemoteAuthState } from './types';
import { apiFetch, clearCsrfToken } from '../../utils/api';

interface AuthContextValue {
  auth: AuthState;
  refresh: () => Promise<void>;
  logout: (next?: string) => Promise<void>;
  updateProfile: (updates: {
    display_name?: string;
    email?: string;
    avatar?: number;
  }) => Promise<{ ok: boolean; error?: string }>;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

const DEFAULT_AUTH_STATE: AuthState = {
  status: 'loading',
  user: null,
  apps: [],
};

function isAppSummary(value: unknown): value is AppSummary {
  if (!value || typeof value !== 'object') {
    return false;
  }
  const app = value as Partial<AppSummary>;
  return (
    typeof app.id === 'string' &&
    typeof app.label === 'string' &&
    typeof app.subtitle === 'string' &&
    typeof app.url === 'string'
  );
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [auth, setAuth] = useState<AuthState>(DEFAULT_AUTH_STATE);

  const refresh = useCallback(async () => {
    try {
      const response = await fetch('/api/auth/me');
      if (!response.ok) {
        setAuth({ status: 'unauthenticated', user: null, apps: [] });
        return;
      }
      const body = (await response.json()) as RemoteAuthState;
      if (!body.authenticated || !body.user) {
        setAuth({ status: 'unauthenticated', user: null, apps: [] });
        return;
      }
      const apps = Array.isArray(body.apps)
        ? body.apps.filter(isAppSummary)
        : [];
      setAuth({ status: 'ok', user: body.user, apps });
    } catch {
      setAuth({ status: 'unauthenticated', user: null, apps: [] });
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const logout = useCallback(async (next?: string) => {
    try {
      await apiFetch('/api/auth/logout', { method: 'POST' });
    } catch {
      // Ignore network errors and continue with local redirect.
    } finally {
      clearCsrfToken();
      window.location.href = next || '/login';
    }
  }, []);

  const updateProfile = useCallback<AuthContextValue['updateProfile']>(
    async (updates) => {
      try {
        const response = await apiFetch('/api/auth/profile', {
          method: 'PATCH',
          body: JSON.stringify(updates),
        });
        const body = (await response.json().catch(() => null)) as {
          error?: string;
          user?: AuthState['user'];
        } | null;
        if (!response.ok) {
          return {
            ok: false,
            error: body?.error || 'Failed to update profile.',
          };
        }
        if (body?.user) {
          const updatedUser = body.user;
          setAuth((prev) => ({ ...prev, user: updatedUser }));
        } else {
          await refresh();
        }
        return { ok: true };
      } catch {
        return { ok: false, error: 'Failed to update profile.' };
      }
    },
    [refresh],
  );

  const value = useMemo<AuthContextValue>(
    () => ({ auth, refresh, logout, updateProfile }),
    [auth, refresh, logout, updateProfile],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return context;
}

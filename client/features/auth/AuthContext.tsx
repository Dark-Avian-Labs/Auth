import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react';

import { apiFetch, clearCsrfToken } from '../../utils/api';
import type { AppSummary, AuthState, RemoteAuthState } from './types';

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

function getRetryAfterMs(response: Response): number | null {
  const header = response.headers.get('Retry-After');
  if (header) {
    const asSeconds = Number.parseInt(header, 10);
    if (Number.isFinite(asSeconds) && asSeconds > 0) {
      return asSeconds * 1000;
    }
    const asDate = Date.parse(header);
    if (Number.isFinite(asDate)) {
      const delta = asDate - Date.now();
      if (delta > 0) return delta;
    }
  }
  return null;
}

function isSafeRelativePath(next: string): boolean {
  return (
    next.startsWith('/') &&
    !next.startsWith('//') &&
    !next.includes('//') &&
    !/^[a-zA-Z][a-zA-Z\d+\-.]*:/.test(next)
  );
}

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
        if (response.status === 429) {
          const retryAfterMs = getRetryAfterMs(response) ?? 30000;
          setAuth({
            status: 'rate_limited',
            user: null,
            apps: [],
            rateLimitedUntilMs: Date.now() + retryAfterMs,
          });
          return;
        }
        if (response.status === 401) {
          setAuth({ status: 'unauthenticated', user: null, apps: [] });
          return;
        }
        setAuth({
          status: 'error',
          user: null,
          apps: [],
          error: { message: `Auth check failed (${response.status})` },
        });
        return;
      }
      const body = (await response.json()) as RemoteAuthState;
      if (!body.authenticated || !body.user) {
        setAuth({ status: 'unauthenticated', user: null, apps: [] });
        return;
      }
      if (body.has_game_access === false) {
        setAuth((prev) => ({
          status: 'forbidden',
          user: body.user ?? prev.user,
          apps: [],
        }));
        return;
      }
      const apps = Array.isArray(body.apps) ? body.apps.filter(isAppSummary) : [];
      setAuth({ status: 'ok', user: body.user, apps });
    } catch (error) {
      const message = error instanceof Error ? error.message || error.toString() : String(error);
      setAuth({
        status: 'error',
        user: null,
        apps: [],
        error: { message },
      });
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const logout = useCallback(async (next?: string) => {
    const redirect = next && isSafeRelativePath(next) ? next : '/login';
    try {
      await apiFetch('/api/auth/logout', { method: 'POST' });
    } catch {
      // ignore
    } finally {
      clearCsrfToken();
      window.location.href = redirect;
    }
  }, []);

  const updateProfile = useCallback<AuthContextValue['updateProfile']>(
    async (updates) => {
      try {
        const response = await apiFetch('/api/auth/profile', {
          method: 'PATCH',
          headers: {
            'Content-Type': 'application/json',
          },
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

import { useState } from 'react';
import { Navigate, useLocation, useNavigate } from 'react-router-dom';

import { useAuth } from './AuthContext';
import { APP_PATHS } from '../../app/paths';
import { Button } from '../../components/ui/Button';
import { GlassCard } from '../../components/ui/GlassCard';
import { Input } from '../../components/ui/Input';
import { apiFetch } from '../../utils/api';

function isSafeRelativePath(next: string): boolean {
  if (next.includes('\\') || /%5c/i.test(next)) {
    return false;
  }
  let decodedNext: string;
  try {
    decodedNext = decodeURIComponent(next);
  } catch {
    decodedNext = next;
  }
  if (decodedNext.includes('\\')) {
    return false;
  }
  return (
    decodedNext.startsWith('/') &&
    !decodedNext.startsWith('//') &&
    !decodedNext.includes('//') &&
    !/^[a-zA-Z][a-zA-Z\d+\-.]*:/.test(decodedNext)
  );
}

function isAbsoluteHttpUrl(next: string): boolean {
  return /^https?:\/\//i.test(next);
}

function readNextFromLocation(search: string): string {
  const params = new URLSearchParams(search);
  const rawNext = params.get('next');
  if (!rawNext) {
    return APP_PATHS.home;
  }
  const next = rawNext.trim();
  return isSafeRelativePath(next) ? next : APP_PATHS.home;
}

export function LoginPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const { auth, refresh } = useAuth();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const next = readNextFromLocation(location.search);

  if (auth.status === 'ok') {
    return <Navigate to={APP_PATHS.home} replace />;
  }

  const handleSubmit = async () => {
    if (!username.trim() || !password.trim()) {
      setError('Username and password are required.');
      return;
    }
    setSaving(true);
    setError(null);
    try {
      const response = await apiFetch('/api/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username: username.trim(), password, next }),
      });
      const body = (await response.json().catch(() => null)) as {
        error?: string;
        next?: string;
      } | null;
      if (!response.ok) {
        setError(body?.error || 'Login failed.');
        return;
      }
      await refresh();
      if (typeof body?.next === 'string') {
        if (isAbsoluteHttpUrl(body.next)) {
          window.location.href = body.next;
          return;
        }
        if (isSafeRelativePath(body.next)) {
          navigate(body.next);
          return;
        }
      }
      navigate(APP_PATHS.home);
    } catch {
      setError('Login failed.');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="mx-auto flex min-h-[calc(100vh-150px)] items-center justify-center">
      <GlassCard className="w-full max-w-[420px] p-6">
        <h1 className="mb-2 text-center text-2xl font-semibold text-foreground">
          Sign in
        </h1>
        <p className="mb-4 text-center text-sm text-muted">
          Unified access for Parametric and Corpus.
        </p>
        <form
          className="space-y-3"
          onSubmit={(event) => {
            event.preventDefault();
            void handleSubmit();
          }}
        >
          <Input
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            aria-label="Username"
            autoComplete="username"
            placeholder="Username"
          />
          <Input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            aria-label="Password"
            autoComplete="current-password"
            placeholder="Password"
          />
          {error ? (
            <p className="text-sm text-red-400" role="alert" aria-atomic="true">
              {error}
            </p>
          ) : null}
          <div className="pt-1">
            <Button
              type="submit"
              variant="accent"
              className="w-full"
              disabled={saving}
            >
              {saving ? 'Signing in...' : 'Login'}
            </Button>
          </div>
        </form>
      </GlassCard>
    </div>
  );
}

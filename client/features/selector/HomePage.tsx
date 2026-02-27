import { Navigate, Link } from 'react-router-dom';

import { APP_PATHS } from '../../app/paths';
import { Button } from '../../components/ui/Button';
import { GlassCard } from '../../components/ui/GlassCard';
import { useAuth } from '../auth/AuthContext';

export function HomePage() {
  const { auth, logout } = useAuth();

  if (auth.status !== 'ok' || !auth.user) {
    return <Navigate to={APP_PATHS.login} replace />;
  }

  const cards = auth.apps;
  const isExternalUrl = (url: string) =>
    /^(?:[a-z][a-z0-9+.-]*:|\/\/)/i.test(url);

  return (
    <div className="mx-auto max-w-5xl space-y-6">
      <GlassCard className="p-6">
        <h1 className="text-2xl font-semibold text-foreground">
          Welcome, {auth.user.username}
        </h1>
        <p className="mt-2 text-sm text-muted">
          Choose an app to continue. Only apps you have access to are shown.
        </p>
      </GlassCard>

      {cards.length > 0 ? (
        <div className="grid gap-4 md:grid-cols-2">
          {cards.map((card) =>
            isExternalUrl(card.url) ? (
              <a
                key={card.id}
                href={card.url}
                target="_blank"
                rel="noopener noreferrer"
                className="glass-surface block rounded-xl border p-4 transition hover:border-[var(--color-accent)]"
              >
                <h2 className="text-lg font-semibold text-foreground">
                  {card.label}
                </h2>
                <p className="mt-1 text-sm text-muted">{card.subtitle}</p>
              </a>
            ) : (
              <Link
                key={card.id}
                to={card.url}
                className="glass-surface block rounded-xl border p-4 transition hover:border-[var(--color-accent)]"
              >
                <h2 className="text-lg font-semibold text-foreground">
                  {card.label}
                </h2>
                <p className="mt-1 text-sm text-muted">{card.subtitle}</p>
              </Link>
            ),
          )}
        </div>
      ) : (
        <GlassCard className="p-6">
          <p className="text-sm text-muted">
            No apps assigned to your account yet. Contact an administrator.
          </p>
        </GlassCard>
      )}

      <div className="flex gap-2">
        {auth.user.is_admin ? (
          <Button asChild variant="secondary">
            <Link to={APP_PATHS.admin}>Open Admin</Link>
          </Button>
        ) : null}
        <Button
          type="button"
          variant="secondary"
          onClick={() => logout(APP_PATHS.login)}
        >
          Logout
        </Button>
      </div>
    </div>
  );
}

import { useEffect, useState } from 'react';
import { Navigate } from 'react-router-dom';

import { APP_PATHS } from '../../app/paths';
import { Button } from '../../components/ui/Button';
import { GlassCard } from '../../components/ui/GlassCard';
import { Input } from '../../components/ui/Input';
import { apiFetch } from '../../utils/api';
import { useAuth } from '../auth/AuthContext';

interface PermissionEntry {
  app_id: string;
  permission: string;
}

interface AdminUser {
  id: number;
  username: string;
  is_admin: boolean;
  app_access: string[];
  permissions: PermissionEntry[];
}

function toPermissionPayload(value: string): string[] {
  return value
    .split(',')
    .map((item) => item.trim())
    .filter((item) => item.length > 0);
}

export function AdminPage() {
  const { auth } = useAuth();
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [loading, setLoading] = useState(true);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [newUsername, setNewUsername] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [newIsAdmin, setNewIsAdmin] = useState(false);

  useEffect(() => {
    let cancelled = false;
    if (!auth.user?.is_admin) {
      setLoading(false);
      return () => {
        cancelled = true;
      };
    }
    async function loadUsers() {
      setLoading(true);
      try {
        const response = await apiFetch('/api/admin/users');
        const body = (await response.json()) as {
          users?: AdminUser[];
          error?: string;
        };
        if (!response.ok) {
          if (!cancelled) setError(body.error || 'Failed to load users.');
          return;
        }
        if (!cancelled) setUsers(Array.isArray(body.users) ? body.users : []);
      } catch {
        if (!cancelled) setError('Failed to load users.');
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    loadUsers();
    return () => {
      cancelled = true;
    };
  }, [auth.user?.is_admin]);

  if (auth.status !== 'ok') {
    return <Navigate to={APP_PATHS.login} replace />;
  }

  if (!auth.user?.is_admin) {
    return <Navigate to={APP_PATHS.home} replace />;
  }

  const refreshUsers = async () => {
    const response = await apiFetch('/api/admin/users');
    const body = (await response.json()) as { users?: AdminUser[] };
    if (response.ok && Array.isArray(body.users)) {
      setUsers(body.users);
    }
  };

  const createUser = async () => {
    setError(null);
    setMessage(null);
    try {
      const response = await apiFetch('/api/admin/users', {
        method: 'POST',
        body: JSON.stringify({
          username: newUsername.trim(),
          password: newPassword,
          is_admin: newIsAdmin,
        }),
      });
      const body = (await response.json()) as { error?: string };
      if (!response.ok) {
        setError(body.error || 'Failed to create user.');
        return;
      }
      setMessage('User created.');
      setNewUsername('');
      setNewPassword('');
      setNewIsAdmin(false);
      await refreshUsers();
    } catch {
      setError('Failed to create user.');
    }
  };

  const toggleAdmin = async (user: AdminUser) => {
    const response = await apiFetch(`/api/admin/users/${user.id}`, {
      method: 'PATCH',
      body: JSON.stringify({ is_admin: !user.is_admin }),
    });
    const body = (await response.json().catch(() => null)) as {
      error?: string;
    } | null;
    if (!response.ok) {
      setError(body?.error || 'Failed to update role.');
      return;
    }
    setMessage('Role updated.');
    await refreshUsers();
  };

  const deleteUser = async (user: AdminUser) => {
    if (!window.confirm(`Delete ${user.username}?`)) return;
    const response = await apiFetch(`/api/admin/users/${user.id}`, {
      method: 'DELETE',
    });
    const body = (await response.json().catch(() => null)) as {
      error?: string;
    } | null;
    if (!response.ok) {
      setError(body?.error || 'Failed to delete user.');
      return;
    }
    setMessage('User deleted.');
    await refreshUsers();
  };

  const changePassword = async (user: AdminUser) => {
    const value = window.prompt(`Set new password for ${user.username}`);
    if (!value) return;
    const response = await apiFetch(`/api/admin/users/${user.id}`, {
      method: 'PATCH',
      body: JSON.stringify({ password: value }),
    });
    const body = (await response.json().catch(() => null)) as {
      error?: string;
    } | null;
    if (!response.ok) {
      setError(body?.error || 'Failed to update password.');
      return;
    }
    setMessage('Password updated.');
  };

  const updateAppAccess = async (
    user: AdminUser,
    appId: string,
    enabled: boolean,
  ) => {
    const response = await apiFetch(
      `/api/admin/users/${user.id}/apps/${encodeURIComponent(appId)}`,
      {
        method: 'PUT',
        body: JSON.stringify({ enabled }),
      },
    );
    const body = (await response.json().catch(() => null)) as {
      error?: string;
    } | null;
    if (!response.ok) {
      setError(body?.error || 'Failed to update app access.');
      return;
    }
    setMessage('App access updated.');
    await refreshUsers();
  };

  const updatePermissions = async (user: AdminUser, appId: string) => {
    const raw = window.prompt(
      `Permissions for ${user.username} on ${appId} (comma-separated)`,
      user.permissions
        .filter((entry) => entry.app_id === appId)
        .map((entry) => entry.permission)
        .join(','),
    );
    if (raw === null) return;
    const response = await apiFetch(`/api/admin/users/${user.id}/permissions`, {
      method: 'PUT',
      body: JSON.stringify({
        app_id: appId,
        permissions: toPermissionPayload(raw),
      }),
    });
    const body = (await response.json().catch(() => null)) as {
      error?: string;
    } | null;
    if (!response.ok) {
      setError(body?.error || 'Failed to update permissions.');
      return;
    }
    setMessage('Permissions updated.');
    await refreshUsers();
  };

  return (
    <div className="mx-auto max-w-6xl space-y-6">
      <GlassCard className="p-6">
        <h1 className="text-2xl font-semibold text-foreground">Admin Panel</h1>
        <p className="mt-1 text-sm text-muted">
          Manage users, roles, app access, and permissions.
        </p>
      </GlassCard>

      <GlassCard className="p-6">
        <h2 className="mb-3 text-lg font-semibold text-foreground">
          Create User
        </h2>
        <div className="grid gap-3 md:grid-cols-[1fr_1fr_auto_auto] md:items-center">
          <Input
            type="text"
            placeholder="Username"
            value={newUsername}
            onChange={(e) => setNewUsername(e.target.value)}
          />
          <Input
            type="password"
            placeholder="Password"
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
          />
          <label className="flex items-center gap-2 text-sm text-muted">
            <input
              type="checkbox"
              checked={newIsAdmin}
              onChange={(e) => setNewIsAdmin(e.target.checked)}
            />
            Admin
          </label>
          <Button type="button" variant="accent" onClick={createUser}>
            Create
          </Button>
        </div>
        {message ? (
          <p className="mt-3 text-sm text-green-400">{message}</p>
        ) : null}
        {error ? <p className="mt-3 text-sm text-red-400">{error}</p> : null}
      </GlassCard>

      <GlassCard className="overflow-hidden p-0">
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-sm">
            <thead>
              <tr className="text-left text-muted">
                <th className="px-4 py-3">User</th>
                <th className="px-4 py-3">Role</th>
                <th className="px-4 py-3">App Access</th>
                <th className="px-4 py-3">Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td className="px-4 py-3 text-muted" colSpan={4}>
                    Loading users...
                  </td>
                </tr>
              ) : (
                users.map((user) => (
                  <tr key={user.id} className="border-t border-white/10">
                    <td className="px-4 py-3">{user.username}</td>
                    <td className="px-4 py-3">
                      {user.is_admin ? 'Admin' : 'User'}
                    </td>
                    <td className="px-4 py-3">
                      {['parametric', 'corpus'].map((appId) => {
                        const hasAccess = user.app_access.includes(appId);
                        return (
                          <button
                            key={`${user.id}-${appId}`}
                            className="mr-2 rounded border border-white/20 px-2 py-1 text-xs"
                            type="button"
                            onClick={() =>
                              updateAppAccess(user, appId, !hasAccess)
                            }
                          >
                            {appId}:{hasAccess ? 'on' : 'off'}
                          </button>
                        );
                      })}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap gap-2">
                        <Button
                          type="button"
                          variant="secondary"
                          className="h-8 px-3 text-xs"
                          onClick={() => toggleAdmin(user)}
                        >
                          {user.is_admin ? 'Remove admin' : 'Make admin'}
                        </Button>
                        <Button
                          type="button"
                          variant="secondary"
                          className="h-8 px-3 text-xs"
                          onClick={() => changePassword(user)}
                        >
                          Change password
                        </Button>
                        <Button
                          type="button"
                          variant="secondary"
                          className="h-8 px-3 text-xs"
                          onClick={() => updatePermissions(user, 'parametric')}
                        >
                          Param perms
                        </Button>
                        <Button
                          type="button"
                          variant="secondary"
                          className="h-8 px-3 text-xs"
                          onClick={() => updatePermissions(user, 'corpus')}
                        >
                          Corpus perms
                        </Button>
                        {auth.user?.id !== user.id ? (
                          <Button
                            type="button"
                            variant="danger"
                            className="h-8 px-3 text-xs"
                            onClick={() => deleteUser(user)}
                          >
                            Delete
                          </Button>
                        ) : null}
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </GlassCard>
    </div>
  );
}

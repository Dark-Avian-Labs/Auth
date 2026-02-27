import { useEffect, useRef, useState } from 'react';
import { Navigate } from 'react-router-dom';

import { AVAILABLE_APPS } from '../../app/config';
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
  const availableApps = AVAILABLE_APPS ?? [];
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [usersError, setUsersError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [newUsername, setNewUsername] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [newIsAdmin, setNewIsAdmin] = useState(false);
  const [passwordUser, setPasswordUser] = useState<AdminUser | null>(null);
  const [passwordValue, setPasswordValue] = useState('');
  const [passwordSubmitting, setPasswordSubmitting] = useState(false);
  const passwordInputId = 'admin-password-input';
  const previousFocusRef = useRef<HTMLElement | null>(null);

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
    setUsersError(null);
    try {
      const response = await apiFetch('/api/admin/users');
      if (!response.ok) {
        const responseText = await response.text().catch(() => '');
        console.error('Failed to refresh users.', {
          status: response.status,
          text: responseText,
        });
        setUsersError(
          `Failed to refresh users (status ${response.status})${
            responseText ? `: ${responseText}` : '.'
          }`,
        );
        return;
      }

      const body = (await response.json()) as { users?: AdminUser[] };
      if (Array.isArray(body.users)) {
        setUsers(body.users);
      }
    } catch (caught) {
      console.error('Error while refreshing users.', caught);
      setUsersError(
        caught instanceof Error ? caught.message : 'Failed to refresh users.',
      );
    }
  };

  const createUser = async () => {
    setError(null);
    setMessage(null);
    const trimmedUsername = newUsername.trim();
    if (!trimmedUsername) {
      setMessage(null);
      setError('Username is required.');
      return;
    }
    if (!newPassword) {
      setMessage(null);
      setError('Password is required.');
      return;
    }
    try {
      const response = await apiFetch('/api/admin/users', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          username: trimmedUsername,
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
    setError(null);
    setMessage(null);
    try {
      const response = await apiFetch(`/api/admin/users/${user.id}`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
        },
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
    } catch (caught) {
      setError(
        caught instanceof Error
          ? caught.message
          : 'Network error updating role.',
      );
    }
  };

  const deleteUser = async (user: AdminUser) => {
    if (!window.confirm(`Delete ${user.username}?`)) return;
    setError(null);
    setMessage(null);
    try {
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
    } catch (caught) {
      setError(
        caught instanceof Error
          ? caught.message
          : 'Network error deleting user.',
      );
    }
  };

  const closePasswordModal = () => {
    setPasswordUser(null);
    setPasswordValue('');
    setPasswordSubmitting(false);
    previousFocusRef.current?.focus();
  };

  const openPasswordModal = (user: AdminUser, trigger?: EventTarget | null) => {
    if (trigger instanceof HTMLElement) {
      previousFocusRef.current = trigger;
    } else if (document.activeElement instanceof HTMLElement) {
      previousFocusRef.current = document.activeElement;
    } else {
      previousFocusRef.current = null;
    }
    setPasswordUser(user);
    setPasswordValue('');
  };

  const changePassword = async (user: AdminUser, value: string) => {
    setError(null);
    setMessage(null);
    try {
      const response = await apiFetch(`/api/admin/users/${user.id}`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
        },
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
      closePasswordModal();
    } catch (caught) {
      setError(
        caught instanceof Error
          ? caught.message
          : 'Network error updating password.',
      );
    }
  };

  const updateAppAccess = async (
    user: AdminUser,
    appId: string,
    enabled: boolean,
  ) => {
    setError(null);
    setMessage(null);
    try {
      const response = await apiFetch(
        `/api/admin/users/${user.id}/apps/${encodeURIComponent(appId)}`,
        {
          method: 'PUT',
          headers: {
            'Content-Type': 'application/json',
          },
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
    } catch (caught) {
      setError(
        caught instanceof Error
          ? caught.message
          : 'Network error updating app access.',
      );
    }
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
    setError(null);
    setMessage(null);
    try {
      const response = await apiFetch(
        `/api/admin/users/${user.id}/permissions`,
        {
          method: 'PUT',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            app_id: appId,
            permissions: toPermissionPayload(raw),
          }),
        },
      );
      const body = (await response.json().catch(() => null)) as {
        error?: string;
      } | null;
      if (!response.ok) {
        setError(body?.error || 'Failed to update permissions.');
        return;
      }
      setMessage('Permissions updated.');
      await refreshUsers();
    } catch (caught) {
      setError(
        caught instanceof Error
          ? caught.message
          : 'Network error updating permissions.',
      );
    }
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
        {usersError ? (
          <p className="px-4 pt-4 text-sm text-red-400">{usersError}</p>
        ) : null}
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
                      {availableApps.map((appId) => {
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
                        {auth.user?.id === user.id && user.is_admin ? (
                          <Button
                            type="button"
                            variant="secondary"
                            className="h-8 px-3 text-xs"
                            disabled
                            title="You cannot remove your own admin role."
                          >
                            Own admin role
                          </Button>
                        ) : (
                          <Button
                            type="button"
                            variant="secondary"
                            className="h-8 px-3 text-xs"
                            onClick={() => toggleAdmin(user)}
                          >
                            {user.is_admin ? 'Remove admin' : 'Make admin'}
                          </Button>
                        )}
                        <Button
                          type="button"
                          variant="secondary"
                          className="h-8 px-3 text-xs"
                          onClick={(event) =>
                            openPasswordModal(user, event.currentTarget)
                          }
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

      {passwordUser ? (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
          role="dialog"
          aria-modal="true"
          aria-labelledby="admin-password-title"
          onMouseDown={(event) => {
            if (event.target === event.currentTarget && !passwordSubmitting) {
              closePasswordModal();
            }
          }}
        >
          <GlassCard
            className="w-full max-w-md p-6"
            onKeyDown={(event) => {
              if (event.key === 'Escape' && !passwordSubmitting) {
                event.preventDefault();
                closePasswordModal();
              }
            }}
          >
            <h2
              id="admin-password-title"
              className="text-lg font-semibold text-foreground"
            >
              Change password for {passwordUser.username}
            </h2>
            <label
              htmlFor={passwordInputId}
              className="mt-3 block text-sm text-muted"
            >
              New password
            </label>
            <input
              id={passwordInputId}
              type="password"
              autoComplete="new-password"
              className="form-input mt-2 w-full"
              value={passwordValue}
              autoFocus
              onChange={(event) => setPasswordValue(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === 'Enter') {
                  event.preventDefault();
                  if (!passwordUser || passwordSubmitting) return;
                  const nextValue = passwordValue;
                  if (!nextValue) {
                    setMessage(null);
                    setError('Password is required.');
                    return;
                  }
                  setPasswordSubmitting(true);
                  void changePassword(passwordUser, nextValue).finally(() => {
                    setPasswordSubmitting(false);
                  });
                }
              }}
            />
            <div className="mt-4 flex justify-end gap-2">
              <Button
                type="button"
                variant="secondary"
                onClick={closePasswordModal}
                disabled={passwordSubmitting}
              >
                Cancel
              </Button>
              <Button
                type="button"
                variant="accent"
                onClick={() => {
                  if (!passwordUser || passwordSubmitting) return;
                  const nextValue = passwordValue;
                  if (!nextValue) {
                    setMessage(null);
                    setError('Password is required.');
                    return;
                  }
                  setPasswordSubmitting(true);
                  void changePassword(passwordUser, nextValue).finally(() => {
                    setPasswordSubmitting(false);
                  });
                }}
                disabled={passwordSubmitting}
              >
                {passwordSubmitting ? 'Saving...' : 'Confirm'}
              </Button>
            </div>
          </GlassCard>
        </div>
      ) : null}
    </div>
  );
}

import { useEffect, useRef, useState, type KeyboardEvent } from 'react';
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

const PERMISSION_COLUMNS = ['read', 'write', 'create', 'update', 'delete', 'admin'] as const;

const DEFAULT_CODEX_MODULES = ['warframe', 'epic7'];

const MODULE_LABELS: Record<string, string> = {
  warframe: 'Warframe',
  epic7: 'Epic 7',
  codex: 'Codex',
};

function cloneAdminUser(user: AdminUser): AdminUser {
  return {
    ...user,
    app_access: [...user.app_access],
    permissions: user.permissions.map((p) => ({ ...p })),
  };
}

function permissionsForApp(user: AdminUser, appId: string): string[] {
  return user.permissions
    .filter((e) => e.app_id === appId)
    .map((e) => e.permission)
    .sort();
}

function sortedCopy(list: string[]): string[] {
  return [...list].sort();
}

function permsListsEqual(a: string[], b: string[]): boolean {
  if (a.length !== b.length) return false;
  const x = sortedCopy(a);
  const y = sortedCopy(b);
  return x.every((v, i) => v === y[i]);
}

export function AdminPage() {
  const { auth } = useAuth();
  const fallbackApps = AVAILABLE_APPS ?? [];
  const [adminAppIds, setAdminAppIds] = useState<string[]>(fallbackApps);
  const [codexModuleIds, setCodexModuleIds] = useState<string[]>(DEFAULT_CODEX_MODULES);
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

  const [matrixUser, setMatrixUser] = useState<AdminUser | null>(null);
  const [matrixAccess, setMatrixAccess] = useState<Record<string, boolean>>({});
  const [matrixPerms, setMatrixPerms] = useState<Record<string, string[]>>({});
  const [matrixSubmitting, setMatrixSubmitting] = useState(false);
  const matrixBaselineRef = useRef<AdminUser | null>(null);

  const passwordInputId = 'admin-password-input';
  const previousFocusRef = useRef<HTMLElement | null>(null);
  const passwordModalRef = useRef<HTMLDivElement | null>(null);
  const matrixModalRef = useRef<HTMLDivElement | null>(null);

  const getPasswordModalFocusableElements = () => {
    const modalElement = passwordModalRef.current;
    if (!modalElement) return [] as HTMLElement[];

    const focusableSelector =
      'a[href], area[href], input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled]), button:not([disabled]), [contenteditable="true"], [tabindex]:not([tabindex="-1"])';

    return Array.from(modalElement.querySelectorAll<HTMLElement>(focusableSelector));
  };

  const getMatrixModalFocusableElements = () => {
    const modalElement = matrixModalRef.current;
    if (!modalElement) return [] as HTMLElement[];

    const focusableSelector =
      'a[href], area[href], input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled]), button:not([disabled]), [contenteditable="true"], [tabindex]:not([tabindex="-1"])';

    return Array.from(modalElement.querySelectorAll<HTMLElement>(focusableSelector));
  };

  const codexModuleSet = new Set(codexModuleIds);
  const standaloneAppIds = adminAppIds.filter((id) => id !== 'codex' && !codexModuleSet.has(id));
  const codexGroupVisible = adminAppIds.includes('codex') || codexModuleIds.length > 0;

  const isAppManageable = (appId: string) => adminAppIds.includes(appId);

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
          app_ids?: string[];
          codex_module_ids?: string[];
          error?: string;
        };
        if (!response.ok) {
          if (!cancelled) setError(body.error || 'Failed to load users.');
          return;
        }
        if (!cancelled) {
          setUsers(Array.isArray(body.users) ? body.users : []);
          if (Array.isArray(body.app_ids) && body.app_ids.length > 0) {
            setAdminAppIds(body.app_ids);
          }
          if (Array.isArray(body.codex_module_ids) && body.codex_module_ids.length > 0) {
            setCodexModuleIds(body.codex_module_ids);
          }
        }
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

  useEffect(() => {
    if (!passwordUser) return;

    const focusableElements = getPasswordModalFocusableElements();
    if (focusableElements.length > 0) {
      focusableElements[0].focus();
      return;
    }

    passwordModalRef.current?.focus();
  }, [passwordUser]);

  useEffect(() => {
    if (!matrixUser) return;

    const focusableElements = getMatrixModalFocusableElements();
    if (focusableElements.length > 0) {
      focusableElements[0].focus();
      return;
    }

    matrixModalRef.current?.focus();
  }, [matrixUser]);

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

      const body = (await response.json()) as {
        users?: AdminUser[];
        app_ids?: string[];
        codex_module_ids?: string[];
      };
      if (Array.isArray(body.users)) {
        setUsers(body.users);
      }
      if (Array.isArray(body.app_ids) && body.app_ids.length > 0) {
        setAdminAppIds(body.app_ids);
      }
      if (Array.isArray(body.codex_module_ids) && body.codex_module_ids.length > 0) {
        setCodexModuleIds(body.codex_module_ids);
      }
    } catch (caught) {
      console.error('Error while refreshing users.', caught);
      setUsersError(caught instanceof Error ? caught.message : 'Failed to refresh users.');
    }
  };

  const initMatrixDraft = (user: AdminUser) => {
    const access: Record<string, boolean> = {};
    const perms: Record<string, string[]> = {};
    const ids = new Set<string>([...adminAppIds, ...codexModuleIds]);
    for (const id of ids) {
      access[id] = user.app_access.includes(id);
      perms[id] = permissionsForApp(user, id);
    }
    setMatrixAccess(access);
    setMatrixPerms(perms);
  };

  const openMatrixModal = (user: AdminUser, trigger?: EventTarget | null) => {
    if (trigger instanceof HTMLElement) {
      previousFocusRef.current = trigger;
    } else if (document.activeElement instanceof HTMLElement) {
      previousFocusRef.current = document.activeElement;
    } else {
      previousFocusRef.current = null;
    }
    matrixBaselineRef.current = cloneAdminUser(user);
    initMatrixDraft(user);
    setMatrixUser(user);
  };

  const closeMatrixModal = () => {
    setMatrixUser(null);
    matrixBaselineRef.current = null;
    setMatrixSubmitting(false);
    previousFocusRef.current?.focus();
  };

  const setAccess = (appId: string, enabled: boolean) => {
    if (!isAppManageable(appId)) return;
    setMatrixAccess((prev) => ({ ...prev, [appId]: enabled }));
    if (!enabled) {
      setMatrixPerms((prev) => ({ ...prev, [appId]: [] }));
    }
  };

  const togglePerm = (appId: string, perm: string) => {
    if (!isAppManageable(appId)) return;
    if (!matrixAccess[appId]) return;
    setMatrixPerms((prev) => {
      const cur = prev[appId] ?? [];
      const has = cur.includes(perm);
      const next = has ? cur.filter((p) => p !== perm) : [...cur, perm];
      return { ...prev, [appId]: next };
    });
  };

  const saveMatrixModal = async () => {
    const baseline = matrixBaselineRef.current;
    if (!matrixUser || !baseline) return;

    setMatrixSubmitting(true);
    setError(null);
    setMessage(null);
    try {
      for (const appId of adminAppIds) {
        const wasOn = baseline.app_access.includes(appId);
        const nowOn = matrixAccess[appId] === true;
        const wasPerms = permissionsForApp(baseline, appId);
        const nowPerms = nowOn ? sortedCopy(matrixPerms[appId] ?? []) : [];

        if (wasOn === nowOn && permsListsEqual(wasPerms, nowPerms)) {
          continue;
        }

        const accessRes = await apiFetch(
          `/api/admin/users/${matrixUser.id}/apps/${encodeURIComponent(appId)}`,
          {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled: nowOn }),
          },
        );
        if (!accessRes.ok) {
          const body = (await accessRes.json().catch(() => null)) as { error?: string } | null;
          setError(body?.error || `Failed to update access for ${appId}.`);
          return;
        }

        const permRes = await apiFetch(`/api/admin/users/${matrixUser.id}/permissions`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ app_id: appId, permissions: nowPerms }),
        });
        if (!permRes.ok) {
          const body = (await permRes.json().catch(() => null)) as { error?: string } | null;
          setError(body?.error || `Failed to update permissions for ${appId}.`);
          return;
        }
      }

      setMessage('Access and permissions updated.');
      closeMatrixModal();
      await refreshUsers();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Network error while saving.');
    } finally {
      setMatrixSubmitting(false);
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
      setError(caught instanceof Error ? caught.message : 'Network error updating role.');
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
      setError(caught instanceof Error ? caught.message : 'Network error deleting user.');
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
      setError(caught instanceof Error ? caught.message : 'Network error updating password.');
    }
  };

  const submitPasswordChange = () => {
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
  };

  function renderPermissionMatrix(appId: string, manageable: boolean) {
    const on = matrixAccess[appId] === true;
    const list = matrixPerms[appId] ?? [];
    const canEdit = manageable && on;
    return (
      <div className="mt-3 overflow-x-auto rounded border border-white/10 bg-black/20 p-2">
        <table className="w-full min-w-[320px] border-collapse text-center text-xs">
          <thead>
            <tr className="text-muted">
              {PERMISSION_COLUMNS.map((col) => (
                <th key={col} className="px-1 py-1 font-medium capitalize">
                  {col}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            <tr>
              {PERMISSION_COLUMNS.map((col) => {
                const has = list.includes(col);
                return (
                  <td key={col} className="p-1 align-middle">
                    <button
                      type="button"
                      disabled={!canEdit || matrixSubmitting}
                      className={`min-h-[2rem] w-full min-w-[2.25rem] rounded border px-1 py-1 text-sm font-semibold transition-colors disabled:cursor-not-allowed disabled:opacity-40 ${
                        has
                          ? 'border-emerald-500/50 bg-emerald-500/10 text-emerald-300'
                          : 'text-muted border-white/15 bg-white/5 hover:border-white/25'
                      }`}
                      aria-pressed={has}
                      onClick={() => togglePerm(appId, col)}
                    >
                      {has ? '✓' : '✕'}
                    </button>
                  </td>
                );
              })}
            </tr>
          </tbody>
        </table>
      </div>
    );
  }

  function renderAppBlock(appId: string, label: string, indent: boolean) {
    const on = matrixAccess[appId] === true;
    const manageable = isAppManageable(appId);
    return (
      <div
        className={`border-t border-white/10 py-4 first:border-t-0 first:pt-0 ${indent ? 'ml-1 border-l border-white/10 pl-4' : ''}`}
      >
        <div className="flex flex-wrap items-center gap-3">
          <label
            className={`flex items-center gap-2 text-sm font-medium ${manageable ? 'text-foreground cursor-pointer' : 'text-foreground/80 cursor-default'}`}
          >
            <input
              type="checkbox"
              className="rounded border-white/30"
              checked={on}
              disabled={matrixSubmitting || !manageable}
              onChange={(e) => setAccess(appId, e.target.checked)}
            />
            <span>{label}</span>
          </label>
          <span className="text-muted font-mono text-xs">{appId}</span>
        </div>
        {!manageable ? (
          <p className="mt-2 text-xs text-amber-400/95">
            Add <span className="font-mono">{appId}</span> to Auth{' '}
            <span className="font-mono">APP_LIST</span> to edit access and permissions here (values
            shown are current).
          </p>
        ) : null}
        {on ? (
          renderPermissionMatrix(appId, manageable)
        ) : manageable ? (
          <p className="text-muted mt-2 text-xs">Grant access to configure capabilities.</p>
        ) : null}
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-6xl space-y-6">
      <GlassCard className="p-6">
        <h1 className="text-foreground text-2xl font-semibold">Admin Panel</h1>
        <p className="text-muted mt-1 text-sm">Manage users, roles, app access, and permissions.</p>
      </GlassCard>

      <GlassCard className="p-6">
        <h2 className="text-foreground mb-3 text-lg font-semibold">Create User</h2>
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
          <label className="text-muted flex items-center gap-2 text-sm">
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
        {message ? <p className="mt-3 text-sm text-green-400">{message}</p> : null}
        {error ? <p className="mt-3 text-sm text-red-400">{error}</p> : null}
      </GlassCard>

      <GlassCard className="overflow-hidden p-0">
        {usersError ? <p className="px-4 pt-4 text-sm text-red-400">{usersError}</p> : null}
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-sm">
            <thead>
              <tr className="text-muted text-left">
                <th className="px-4 py-3">User</th>
                <th className="px-4 py-3">Role</th>
                <th className="px-4 py-3">Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td className="text-muted px-4 py-3" colSpan={3}>
                    Loading users...
                  </td>
                </tr>
              ) : (
                users.map((user) => (
                  <tr key={user.id} className="border-t border-white/10">
                    <td className="px-4 py-3">{user.username}</td>
                    <td className="px-4 py-3">{user.is_admin ? 'Admin' : 'User'}</td>
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap gap-2">
                        <Button
                          type="button"
                          variant="accent"
                          className="h-8 px-3 text-xs"
                          onClick={(event) => openMatrixModal(user, event.currentTarget)}
                        >
                          Permissions
                        </Button>
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
                          onClick={(event) => openPasswordModal(user, event.currentTarget)}
                        >
                          Change password
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
          onClick={(event) => {
            if (event.target === event.currentTarget && !passwordSubmitting) {
              closePasswordModal();
            }
          }}
        >
          <div
            ref={passwordModalRef}
            className="w-full max-w-md"
            tabIndex={-1}
            onKeyDown={(event: KeyboardEvent<HTMLDivElement>) => {
              if (event.key === 'Escape' && !passwordSubmitting) {
                event.preventDefault();
                closePasswordModal();
                return;
              }

              if (event.key !== 'Tab') {
                return;
              }

              const focusableElements = getPasswordModalFocusableElements();
              if (focusableElements.length === 0) {
                event.preventDefault();
                passwordModalRef.current?.focus();
                return;
              }

              const firstElement = focusableElements[0];
              const lastElement = focusableElements[focusableElements.length - 1];
              const activeElement = document.activeElement as HTMLElement | null;
              const modalElement = passwordModalRef.current;

              if (event.shiftKey) {
                if (
                  !activeElement ||
                  activeElement === firstElement ||
                  !modalElement?.contains(activeElement)
                ) {
                  event.preventDefault();
                  lastElement.focus();
                }
                return;
              }

              if (
                !activeElement ||
                activeElement === lastElement ||
                !modalElement?.contains(activeElement)
              ) {
                event.preventDefault();
                firstElement.focus();
              }
            }}
          >
            <GlassCard className="p-6">
              <h2 id="admin-password-title" className="text-foreground text-lg font-semibold">
                Change password for {passwordUser.username}
              </h2>
              <label htmlFor={passwordInputId} className="text-muted mt-3 block text-sm">
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
                    submitPasswordChange();
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
                  onClick={submitPasswordChange}
                  disabled={passwordSubmitting}
                >
                  {passwordSubmitting ? 'Saving...' : 'Confirm'}
                </Button>
              </div>
            </GlassCard>
          </div>
        </div>
      ) : null}

      {matrixUser ? (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
          role="dialog"
          aria-modal="true"
          aria-labelledby="admin-matrix-title"
          onClick={(event) => {
            if (event.target === event.currentTarget && !matrixSubmitting) {
              closeMatrixModal();
            }
          }}
        >
          <div
            ref={matrixModalRef}
            className="max-h-[90vh] w-full max-w-4xl overflow-y-auto"
            tabIndex={-1}
            onKeyDown={(event: KeyboardEvent<HTMLDivElement>) => {
              if (event.key === 'Escape' && !matrixSubmitting) {
                event.preventDefault();
                closeMatrixModal();
                return;
              }

              if (event.key !== 'Tab') {
                return;
              }

              const focusableElements = getMatrixModalFocusableElements();
              if (focusableElements.length === 0) {
                event.preventDefault();
                matrixModalRef.current?.focus();
                return;
              }

              const firstElement = focusableElements[0];
              const lastElement = focusableElements[focusableElements.length - 1];
              const activeElement = document.activeElement as HTMLElement | null;
              const modalElement = matrixModalRef.current;

              if (event.shiftKey) {
                if (
                  !activeElement ||
                  activeElement === firstElement ||
                  !modalElement?.contains(activeElement)
                ) {
                  event.preventDefault();
                  lastElement.focus();
                }
                return;
              }

              if (
                !activeElement ||
                activeElement === lastElement ||
                !modalElement?.contains(activeElement)
              ) {
                event.preventDefault();
                firstElement.focus();
              }
            }}
          >
            <GlassCard className="p-6">
              <h2 id="admin-matrix-title" className="text-foreground text-lg font-semibold">
                Access & permissions — {matrixUser.username}
              </h2>
              <p className="text-muted mt-2 text-sm">
                Toggle each app to grant access, then set capabilities. Codex modules (games) are
                listed under Codex; you can edit them only if each module id is also in Auth{' '}
                <span className="text-foreground/80 font-mono">APP_LIST</span> (configure on the
                server). Module ids come from{' '}
                <span className="text-foreground/80 font-mono">CODEX_MODULE_APP_IDS</span> (default
                warframe, epic7).
              </p>

              <div className="mt-6 space-y-2">
                {standaloneAppIds.map((appId) => (
                  <div key={appId}>
                    {renderAppBlock(appId, MODULE_LABELS[appId] ?? appId, false)}
                  </div>
                ))}

                {codexGroupVisible ? (
                  <div className="border-t border-white/15 pt-2">
                    <h3 className="text-foreground mb-1 text-sm font-semibold tracking-wide uppercase">
                      Codex
                    </h3>
                    {adminAppIds.includes('codex')
                      ? renderAppBlock('codex', MODULE_LABELS.codex ?? 'Codex', false)
                      : null}
                    {codexModuleIds.map((appId) => (
                      <div key={appId}>
                        {renderAppBlock(appId, MODULE_LABELS[appId] ?? appId, true)}
                      </div>
                    ))}
                  </div>
                ) : null}
              </div>

              <div className="mt-6 flex justify-end gap-2 border-t border-white/10 pt-4">
                <Button
                  type="button"
                  variant="secondary"
                  onClick={closeMatrixModal}
                  disabled={matrixSubmitting}
                >
                  Cancel
                </Button>
                <Button
                  type="button"
                  variant="accent"
                  onClick={() => void saveMatrixModal()}
                  disabled={matrixSubmitting}
                >
                  {matrixSubmitting ? 'Saving...' : 'Save changes'}
                </Button>
              </div>
            </GlassCard>
          </div>
        </div>
      ) : null}
    </div>
  );
}

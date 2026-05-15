import {
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent,
  type RefObject,
} from 'react';
import { Navigate } from 'react-router-dom';

import { AVAILABLE_APPS } from '../../app/config';
import { APP_PATHS } from '../../app/paths';
import { Button } from '../../components/ui/Button';
import { FormSelect, type FormSelectOption } from '../../components/ui/FormSelect';
import { GlassCard } from '../../components/ui/GlassCard';
import { Input } from '../../components/ui/Input';
import { apiFetch } from '../../utils/api';
import { useAuth } from '../auth/AuthContext';

type AppRole = 'user' | 'admin';

interface AppRoleEntry {
  app_id: string;
  role: AppRole;
}

interface AdminUser {
  id: number;
  username: string;
  is_admin: boolean;
  app_access: string[];
  app_roles: AppRoleEntry[];
}

const ROLE_OPTIONS: FormSelectOption<AppRole>[] = [
  { value: 'user', label: 'User' },
  { value: 'admin', label: 'Admin' },
];

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
    app_roles: user.app_roles.map((r) => ({ ...r })),
  };
}

function effectiveRoleForApp(user: AdminUser, appId: string): AppRole {
  const row = user.app_roles.find((e) => e.app_id === appId);
  return row?.role === 'admin' ? 'admin' : 'user';
}

function trapModalFocus(
  event: KeyboardEvent<HTMLDivElement>,
  modalRef: RefObject<HTMLDivElement | null>,
  focusableSelector: string,
  enabled: boolean,
) {
  if (!enabled || event.key !== 'Tab') return;

  const modalElement = modalRef.current;
  if (!modalElement) return;

  const focusableElements = Array.from(
    modalElement.querySelectorAll<HTMLElement>(focusableSelector),
  );
  if (focusableElements.length === 0) {
    event.preventDefault();
    modalRef.current?.focus();
    return;
  }

  const firstElement = focusableElements[0];
  const lastElement = focusableElements[focusableElements.length - 1];
  const activeElement = document.activeElement as HTMLElement | null;

  if (event.shiftKey) {
    if (!activeElement || activeElement === firstElement || !modalElement.contains(activeElement)) {
      event.preventDefault();
      lastElement.focus();
    }
    return;
  }

  if (!activeElement || activeElement === lastElement || !modalElement.contains(activeElement)) {
    event.preventDefault();
    firstElement.focus();
  }
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

  const [addUserOpen, setAddUserOpen] = useState(false);
  const [addUsername, setAddUsername] = useState('');
  const [addPassword, setAddPassword] = useState('');
  const [addSubmitting, setAddSubmitting] = useState(false);

  const [passwordUser, setPasswordUser] = useState<AdminUser | null>(null);
  const [passwordValue, setPasswordValue] = useState('');
  const [passwordSubmitting, setPasswordSubmitting] = useState(false);

  const [deleteUser, setDeleteUser] = useState<AdminUser | null>(null);
  const [deleteSubmitting, setDeleteSubmitting] = useState(false);

  const [matrixUser, setMatrixUser] = useState<AdminUser | null>(null);
  const [matrixServiceAdmin, setMatrixServiceAdmin] = useState(false);
  const [matrixAccess, setMatrixAccess] = useState<Record<string, boolean>>({});
  const [matrixRoles, setMatrixRoles] = useState<Record<string, AppRole>>({});
  const [matrixSubmitting, setMatrixSubmitting] = useState(false);
  const matrixBaselineRef = useRef<AdminUser | null>(null);

  const passwordInputId = 'admin-password-input';
  const addPasswordInputId = useId();
  const previousFocusRef = useRef<HTMLElement | null>(null);
  const passwordModalRef = useRef<HTMLDivElement | null>(null);
  const addUserModalRef = useRef<HTMLDivElement | null>(null);
  const deleteModalRef = useRef<HTMLDivElement | null>(null);
  const matrixModalRef = useRef<HTMLDivElement | null>(null);

  const focusableSelector =
    'a[href], area[href], input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled]), button:not([disabled]), [contenteditable="true"], [tabindex]:not([tabindex="-1"])';

  const codexModuleSet = new Set(codexModuleIds);
  const standaloneAppIds = adminAppIds.filter((id) => id !== 'codex' && !codexModuleSet.has(id));
  const codexGroupVisible = adminAppIds.includes('codex') || codexModuleIds.length > 0;

  const managedGameIds = useMemo(
    () => Array.from(new Set([...adminAppIds, ...codexModuleIds])).sort(),
    [adminAppIds, codexModuleIds],
  );

  const isAppManageable = (appId: string) =>
    adminAppIds.includes(appId) || codexModuleIds.includes(appId);

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
          setUsers(
            Array.isArray(body.users)
              ? body.users.map((u) => ({
                  ...u,
                  app_roles: Array.isArray(u.app_roles) ? u.app_roles : [],
                }))
              : [],
          );
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
    const focusableElements = Array.from(
      passwordModalRef.current?.querySelectorAll<HTMLElement>(focusableSelector) ?? [],
    );
    if (focusableElements.length > 0) {
      focusableElements[0].focus();
      return;
    }
    passwordModalRef.current?.focus();
  }, [passwordUser, focusableSelector]);

  useEffect(() => {
    if (!addUserOpen) return;
    const focusableElements = Array.from(
      addUserModalRef.current?.querySelectorAll<HTMLElement>(focusableSelector) ?? [],
    );
    if (focusableElements.length > 0) {
      focusableElements[0].focus();
      return;
    }
    addUserModalRef.current?.focus();
  }, [addUserOpen, focusableSelector]);

  useEffect(() => {
    if (!deleteUser) return;
    const focusableElements = Array.from(
      deleteModalRef.current?.querySelectorAll<HTMLElement>(focusableSelector) ?? [],
    );
    if (focusableElements.length > 0) {
      focusableElements[0].focus();
      return;
    }
    deleteModalRef.current?.focus();
  }, [deleteUser, focusableSelector]);

  useEffect(() => {
    if (!matrixUser) return;
    const focusableElements = Array.from(
      matrixModalRef.current?.querySelectorAll<HTMLElement>(focusableSelector) ?? [],
    );
    if (focusableElements.length > 0) {
      focusableElements[0].focus();
      return;
    }
    matrixModalRef.current?.focus();
  }, [matrixUser, focusableSelector]);

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
        setUsers(
          body.users.map((u) => ({
            ...u,
            app_roles: Array.isArray(u.app_roles) ? u.app_roles : [],
          })),
        );
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
    const roles: Record<string, AppRole> = {};
    for (const id of managedGameIds) {
      access[id] = user.app_access.includes(id);
      roles[id] = effectiveRoleForApp(user, id);
    }
    setMatrixServiceAdmin(user.is_admin);
    setMatrixAccess(access);
    setMatrixRoles(roles);
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
      setMatrixRoles((prev) => ({ ...prev, [appId]: 'user' }));
    }
  };

  const saveMatrixModal = async () => {
    const baseline = matrixBaselineRef.current;
    if (!matrixUser || !baseline) return;

    setMatrixSubmitting(true);
    setError(null);
    setMessage(null);
    try {
      if (matrixServiceAdmin !== baseline.is_admin) {
        const patchRes = await apiFetch(`/api/admin/users/${matrixUser.id}`, {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ is_admin: matrixServiceAdmin }),
        });
        if (!patchRes.ok) {
          const body = (await patchRes.json().catch(() => null)) as { error?: string } | null;
          setError(body?.error || 'Failed to update service admin.');
          return;
        }
      }

      for (const appId of managedGameIds) {
        const wasOn = baseline.app_access.includes(appId);
        const nowOn = matrixAccess[appId] === true;
        if (wasOn !== nowOn) {
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
        }
      }

      for (const appId of managedGameIds) {
        const nowOn = matrixAccess[appId] === true;
        if (!nowOn) continue;
        const wasOnBefore = baseline.app_access.includes(appId);
        const prevRole = wasOnBefore ? effectiveRoleForApp(baseline, appId) : 'user';
        const nextRole = matrixRoles[appId] === 'admin' ? 'admin' : 'user';
        if (prevRole !== nextRole) {
          const roleRes = await apiFetch(`/api/admin/users/${matrixUser.id}/roles`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              app_id: appId,
              role: nextRole === 'admin' ? 'admin' : null,
            }),
          });
          if (!roleRes.ok) {
            const body = (await roleRes.json().catch(() => null)) as { error?: string } | null;
            setError(body?.error || `Failed to update role for ${appId}.`);
            return;
          }
        }
      }

      setMessage('Access and roles updated.');
      closeMatrixModal();
      await refreshUsers();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Network error while saving.');
    } finally {
      setMatrixSubmitting(false);
    }
  };

  const submitAddUser = async () => {
    setError(null);
    setMessage(null);
    const trimmedUsername = addUsername.trim();
    if (!trimmedUsername) {
      setError('Username is required.');
      return;
    }
    if (!addPassword) {
      setError('Password is required.');
      return;
    }
    if (addPassword.length < 8) {
      setError('Password must be at least 8 characters.');
      return;
    }
    setAddSubmitting(true);
    try {
      const response = await apiFetch('/api/admin/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: trimmedUsername,
          password: addPassword,
          is_admin: false,
        }),
      });
      const body = (await response.json()) as { error?: string };
      if (!response.ok) {
        setError(body.error || 'Failed to create user.');
        return;
      }
      setMessage('User created.');
      setAddUsername('');
      setAddPassword('');
      setAddUserOpen(false);
      await refreshUsers();
    } catch {
      setError('Failed to create user.');
    } finally {
      setAddSubmitting(false);
    }
  };

  const confirmDeleteUser = async () => {
    if (!deleteUser) return;
    setDeleteSubmitting(true);
    setError(null);
    setMessage(null);
    try {
      const response = await apiFetch(`/api/admin/users/${deleteUser.id}`, {
        method: 'DELETE',
      });
      const body = (await response.json().catch(() => null)) as { error?: string } | null;
      if (!response.ok) {
        setError(body?.error || 'Failed to delete user.');
        return;
      }
      setMessage('User deleted.');
      setDeleteUser(null);
      await refreshUsers();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Network error deleting user.');
    } finally {
      setDeleteSubmitting(false);
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
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: value }),
      });
      const body = (await response.json().catch(() => null)) as { error?: string } | null;
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
      setError('Password is required.');
      return;
    }
    setPasswordSubmitting(true);
    void changePassword(passwordUser, nextValue).finally(() => {
      setPasswordSubmitting(false);
    });
  };

  const editingSelf = matrixUser !== null && auth.user?.id === matrixUser.id;

  function renderAppRow(appId: string, label: string, indent: boolean) {
    const on = matrixAccess[appId] === true;
    const manageable = isAppManageable(appId);
    const roleId = `admin-matrix-role-${appId}`;
    return (
      <div
        key={appId}
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
          <p className="text-warning/95 mt-2 text-xs">
            This app id is not in the configured deploy or Codex module list.
          </p>
        ) : null}
        {on && manageable ? (
          <div className="mt-3 max-w-xs">
            <label htmlFor={roleId} className="text-muted mb-1 block text-xs">
              Role
            </label>
            <FormSelect
              id={roleId}
              value={matrixRoles[appId] ?? 'user'}
              options={ROLE_OPTIONS}
              disabled={matrixSubmitting}
              onChange={(value) =>
                setMatrixRoles((prev) => ({
                  ...prev,
                  [appId]: value,
                }))
              }
            />
          </div>
        ) : manageable && !on ? (
          <p className="text-muted mt-2 text-xs">Grant access to assign a role.</p>
        ) : null}
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-6xl space-y-6">
      <GlassCard className="p-6">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h1 className="text-foreground text-2xl font-semibold">Admin Panel</h1>
            <p className="text-muted mt-1 text-sm">
              Manage users, service admin, app access, and per-app roles.
            </p>
          </div>
          <Button type="button" variant="accent" onClick={() => setAddUserOpen(true)}>
            Add user
          </Button>
        </div>
      </GlassCard>

      <GlassCard className="overflow-hidden p-0">
        {usersError ? <p className="text-danger px-4 pt-4 text-sm">{usersError}</p> : null}
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-sm">
            <thead>
              <tr className="text-muted text-left">
                <th className="px-4 py-3">User</th>
                <th className="px-4 py-3">Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td className="text-muted px-4 py-3" colSpan={2}>
                    Loading users...
                  </td>
                </tr>
              ) : (
                users.map((user) => (
                  <tr key={user.id} className="border-t border-white/10">
                    <td className="px-4 py-3">{user.username}</td>
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap items-center gap-2">
                        <Button
                          type="button"
                          variant="secondary"
                          className="h-8 px-3 text-xs"
                          onClick={(event) => openPasswordModal(user, event.currentTarget)}
                        >
                          Change password
                        </Button>
                        <Button
                          type="button"
                          variant="accent"
                          className="h-8 px-3 text-xs"
                          onClick={(event) => openMatrixModal(user, event.currentTarget)}
                        >
                          Permissions
                        </Button>
                        <span className="min-w-[1rem] flex-1" aria-hidden="true" />
                        {auth.user?.id !== user.id ? (
                          <Button
                            type="button"
                            variant="danger"
                            className="h-8 shrink-0 px-3 text-xs"
                            onClick={() => setDeleteUser(user)}
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

      {message ? <p className="text-success text-sm">{message}</p> : null}
      {error ? <p className="text-danger text-sm">{error}</p> : null}

      {addUserOpen ? (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
          role="dialog"
          aria-modal="true"
          aria-labelledby="admin-add-user-title"
          onClick={(event) => {
            if (event.target === event.currentTarget && !addSubmitting) {
              setAddUserOpen(false);
            }
          }}
        >
          <div
            ref={addUserModalRef}
            className="w-full max-w-md"
            tabIndex={-1}
            onKeyDown={(event) => {
              if (event.key === 'Escape' && !addSubmitting) {
                event.preventDefault();
                setAddUserOpen(false);
                return;
              }
              trapModalFocus(event, addUserModalRef, focusableSelector, !addSubmitting);
            }}
          >
            <GlassCard className="p-6">
              <h2 id="admin-add-user-title" className="text-foreground text-lg font-semibold">
                Add user
              </h2>
              <div className="mt-4 grid gap-3">
                <Input
                  id="auth-admin-add-username"
                  name="username"
                  type="text"
                  placeholder="Username"
                  value={addUsername}
                  onChange={(e) => setAddUsername(e.target.value)}
                  aria-label="New user username"
                />
                <Input
                  id={addPasswordInputId}
                  name="new-password"
                  type="password"
                  placeholder="Password"
                  value={addPassword}
                  onChange={(e) => setAddPassword(e.target.value)}
                  aria-label="New user password"
                  autoComplete="new-password"
                  onKeyDown={(event) => {
                    if (event.key === 'Enter') {
                      event.preventDefault();
                      void submitAddUser();
                    }
                  }}
                />
              </div>
              <div className="mt-4 flex justify-end gap-2">
                <Button
                  type="button"
                  variant="secondary"
                  onClick={() => setAddUserOpen(false)}
                  disabled={addSubmitting}
                >
                  Cancel
                </Button>
                <Button
                  type="button"
                  variant="accent"
                  onClick={() => void submitAddUser()}
                  disabled={addSubmitting}
                >
                  {addSubmitting ? 'Creating...' : 'Create'}
                </Button>
              </div>
            </GlassCard>
          </div>
        </div>
      ) : null}

      {deleteUser ? (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
          role="dialog"
          aria-modal="true"
          aria-labelledby="admin-delete-title"
          onClick={(event) => {
            if (event.target === event.currentTarget && !deleteSubmitting) {
              setDeleteUser(null);
            }
          }}
        >
          <div
            ref={deleteModalRef}
            className="w-full max-w-md"
            tabIndex={-1}
            onKeyDown={(event) => {
              if (event.key === 'Escape' && !deleteSubmitting) {
                event.preventDefault();
                setDeleteUser(null);
                return;
              }
              trapModalFocus(event, deleteModalRef, focusableSelector, !deleteSubmitting);
            }}
          >
            <GlassCard className="p-6">
              <h2 id="admin-delete-title" className="text-foreground text-lg font-semibold">
                Delete user
              </h2>
              <p className="text-muted mt-2 text-sm">
                Permanently delete{' '}
                <span className="text-foreground font-medium">{deleteUser.username}</span>? This
                cannot be undone.
              </p>
              <div className="mt-4 flex justify-end gap-2">
                <Button
                  type="button"
                  variant="secondary"
                  onClick={() => setDeleteUser(null)}
                  disabled={deleteSubmitting}
                >
                  Cancel
                </Button>
                <Button
                  type="button"
                  variant="danger"
                  onClick={() => void confirmDeleteUser()}
                  disabled={deleteSubmitting}
                >
                  {deleteSubmitting ? 'Deleting...' : 'Delete'}
                </Button>
              </div>
            </GlassCard>
          </div>
        </div>
      ) : null}

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
            onKeyDown={(event) => {
              if (event.key === 'Escape' && !passwordSubmitting) {
                event.preventDefault();
                closePasswordModal();
                return;
              }
              trapModalFocus(event, passwordModalRef, focusableSelector, !passwordSubmitting);
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
            onKeyDown={(event) => {
              if (event.key === 'Escape' && !matrixSubmitting) {
                event.preventDefault();
                closeMatrixModal();
                return;
              }
              trapModalFocus(event, matrixModalRef, focusableSelector, !matrixSubmitting);
            }}
          >
            <GlassCard className="p-6">
              <h2 id="admin-matrix-title" className="text-foreground text-lg font-semibold">
                Permissions — {matrixUser.username}
              </h2>
              <p className="text-muted mt-2 text-sm">
                Service administrators can manage users on this Auth deployment. Per-app roles apply
                when the user has access to that app or Codex submodule.
              </p>

              <div className="mt-6 border-b border-white/10 pb-4">
                <label className="text-foreground flex cursor-pointer items-center gap-2 text-sm font-medium">
                  <input
                    type="checkbox"
                    className="rounded border-white/30"
                    checked={matrixServiceAdmin}
                    disabled={matrixSubmitting}
                    onChange={(e) => {
                      if (matrixSubmitting) return;
                      if (editingSelf && matrixUser.is_admin && !e.target.checked) return;
                      setMatrixServiceAdmin(e.target.checked);
                    }}
                  />
                  <span>Auth service administrator</span>
                </label>
                {editingSelf && matrixUser.is_admin ? (
                  <p className="text-muted mt-2 text-xs">
                    You cannot remove your own service admin role from here.
                  </p>
                ) : null}
              </div>

              <div className="mt-6 space-y-2">
                {standaloneAppIds.map((appId) => (
                  <div key={appId}>{renderAppRow(appId, MODULE_LABELS[appId] ?? appId, false)}</div>
                ))}

                {codexGroupVisible ? (
                  <div className="border-t border-white/15 pt-2">
                    <h3 className="text-foreground mb-1 text-sm font-semibold tracking-wide uppercase">
                      Codex
                    </h3>
                    {adminAppIds.includes('codex')
                      ? renderAppRow('codex', MODULE_LABELS.codex ?? 'Codex', false)
                      : null}
                    {codexModuleIds.map((appId) => (
                      <div key={appId}>
                        {renderAppRow(appId, MODULE_LABELS[appId] ?? appId, true)}
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

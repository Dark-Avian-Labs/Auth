import { useEffect, useState } from 'react';
import { useLocation } from 'react-router-dom';

import { ALLOWED_NEXT_ORIGINS } from '../../app/config';
import { Button } from '../../components/ui/Button';
import { GlassCard } from '../../components/ui/GlassCard';
import { Input } from '../../components/ui/Input';
import { Modal } from '../../components/ui/Modal';
import { apiFetch } from '../../utils/api';
import {
  getProfileIconSrc,
  PROFILE_AVATAR_IDS,
} from '../../utils/profileIcons';
import { useAuth } from '../auth/AuthContext';

export function ProfilePage() {
  const location = useLocation();
  const { auth, updateProfile } = useAuth();
  const profile = auth.user;
  const [displayName, setDisplayName] = useState('');
  const [email, setEmail] = useState('');
  const [avatar, setAvatar] = useState(1);
  const [saveStatus, setSaveStatus] = useState<{
    type: 'success' | 'error';
    message: string;
  } | null>(null);
  const [saving, setSaving] = useState(false);
  const [showChangePassword, setShowChangePassword] = useState(false);
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [passwordStatus, setPasswordStatus] = useState<{
    type: 'success' | 'error';
    message: string;
  } | null>(null);
  const [passwordSaving, setPasswordSaving] = useState(false);

  const resolveNextTarget = (): string | null => {
    const params = new URLSearchParams(location.search);
    const next = params.get('next');
    if (!next) {
      return null;
    }
    if (next.startsWith('/') && !next.startsWith('//')) {
      return next;
    }
    try {
      const url = new URL(next);
      if (url.protocol !== 'http:' && url.protocol !== 'https:') {
        return null;
      }
      const allowedOrigins = new Set([
        window.location.origin,
        ...ALLOWED_NEXT_ORIGINS,
      ]);
      if (!allowedOrigins.has(url.origin)) {
        return null;
      }
      return url.toString();
    } catch {
      return null;
    }
  };
  const nextTarget = resolveNextTarget();

  useEffect(() => {
    if (!profile) return;
    setDisplayName(profile.display_name ?? '');
    setEmail(profile.email ?? '');
    const avatarId = Number(profile.avatar);
    setAvatar(
      Number.isInteger(avatarId) && avatarId >= 1 && avatarId <= 16
        ? avatarId
        : 1,
    );
  }, [profile]);

  if (!profile) {
    return (
      <div className="mx-auto max-w-4xl">
        <GlassCard className="p-6">
          <p className="text-sm text-muted">Unable to load profile data.</p>
        </GlassCard>
      </div>
    );
  }

  const handleSave = async () => {
    if (saving) {
      return;
    }

    setSaving(true);
    try {
      const result = await updateProfile({
        display_name: displayName.trim(),
        email: email.trim(),
        avatar,
      });
      setSaveStatus({
        type: result.ok ? 'success' : 'error',
        message: result.ok ? 'Profile saved.' : result.error || 'Save failed.',
      });
    } catch {
      setSaveStatus({
        type: 'error',
        message: 'Save failed.',
      });
    } finally {
      setSaving(false);
    }
  };

  const handleChangePassword = async () => {
    const current = currentPassword;
    const next = newPassword;
    const confirm = confirmPassword;
    if (!current || !next) {
      setPasswordStatus({
        type: 'error',
        message: 'Current password and new password are required.',
      });
      return;
    }
    if (next.length < 8) {
      setPasswordStatus({
        type: 'error',
        message: 'New password must be at least 8 characters.',
      });
      return;
    }
    if (next !== confirm) {
      setPasswordStatus({ type: 'error', message: 'Passwords do not match.' });
      return;
    }

    setPasswordSaving(true);
    try {
      const response = await apiFetch('/api/auth/change-password', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          current_password: current,
          new_password: next,
        }),
      });
      const body = (await response.json().catch(() => null)) as {
        error?: string;
      } | null;
      if (!response.ok) {
        setPasswordStatus({
          type: 'error',
          message: body?.error || 'Failed to change password.',
        });
        return;
      }
      setPasswordStatus({ type: 'success', message: 'Password updated.' });
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
    } catch {
      setPasswordStatus({
        type: 'error',
        message: 'Failed to change password.',
      });
    } finally {
      setPasswordSaving(false);
    }
  };

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      <GlassCard className="p-6">
        <h1 className="text-2xl font-semibold text-foreground">Profile</h1>
        <p className="mt-1 text-sm text-muted">
          Manage your account profile centrally for all apps.
        </p>
        {nextTarget ? (
          <div className="mt-4">
            <Button type="button" variant="secondary" href={nextTarget}>
              Back to app
            </Button>
          </div>
        ) : null}
      </GlassCard>

      <GlassCard className="p-6">
        <h2 className="mb-3 text-lg font-semibold text-foreground">
          Profile Icon
        </h2>
        <div className="profile-icon-grid">
          {PROFILE_AVATAR_IDS.map((id) => (
            <button
              key={id}
              type="button"
              className={`profile-icon-option ${avatar === id ? 'profile-icon-option--selected' : ''}`}
              onClick={() => {
                setAvatar(id);
                setSaveStatus(null);
              }}
              aria-label={`Select profile icon ${id}`}
            >
              <img
                src={getProfileIconSrc(id)}
                alt=""
                className="profile-icon-option__image"
              />
            </button>
          ))}
        </div>
      </GlassCard>

      <GlassCard className="p-6">
        <div className="grid gap-4 md:grid-cols-2">
          <div>
            <label
              htmlFor="profile-username"
              className="mb-1.5 block text-sm text-muted"
            >
              Username
            </label>
            <Input
              id="profile-username"
              type="text"
              readOnlyStyle
              value={profile.username}
              readOnly
            />
          </div>
          <div>
            <label
              htmlFor="profile-role"
              className="mb-1.5 block text-sm text-muted"
            >
              Role
            </label>
            <Input
              id="profile-role"
              type="text"
              readOnlyStyle
              value={profile.is_admin ? 'Admin' : 'User'}
              readOnly
            />
          </div>
          <div>
            <label
              htmlFor="profile-name"
              className="mb-1.5 block text-sm text-muted"
            >
              Name
            </label>
            <Input
              id="profile-name"
              type="text"
              value={displayName}
              onChange={(e) => {
                setDisplayName(e.target.value);
                setSaveStatus(null);
              }}
              placeholder="Display name"
            />
          </div>
          <div>
            <label
              htmlFor="profile-email"
              className="mb-1.5 block text-sm text-muted"
            >
              Email
            </label>
            <Input
              id="profile-email"
              type="email"
              value={email}
              onChange={(e) => {
                setEmail(e.target.value);
                setSaveStatus(null);
              }}
              placeholder="you@example.com"
            />
          </div>
        </div>

        <div className="mt-5 flex flex-wrap items-center justify-end gap-3">
          <Button
            type="button"
            variant="secondary"
            onClick={() => {
              setShowChangePassword(true);
              setPasswordStatus(null);
            }}
          >
            Change Password
          </Button>
          <Button
            type="button"
            variant="accent"
            onClick={handleSave}
            disabled={saving}
          >
            {saving ? 'Saving...' : 'Save'}
          </Button>
        </div>
        {saveStatus && (
          <p
            className={`mt-3 text-sm ${saveStatus.type === 'success' ? 'text-success' : 'text-danger'}`}
          >
            {saveStatus.message}
          </p>
        )}
      </GlassCard>

      <Modal
        open={showChangePassword}
        className="max-w-md"
        onClose={() => {
          setShowChangePassword(false);
          setPasswordStatus(null);
        }}
      >
        <h3 className="mb-3 text-lg font-semibold text-foreground">
          Change Password
        </h3>
        <div className="space-y-3">
          <Input
            type="password"
            placeholder="Current password"
            value={currentPassword}
            autoComplete="current-password"
            onChange={(e) => setCurrentPassword(e.target.value)}
          />
          <Input
            type="password"
            placeholder="New password"
            value={newPassword}
            autoComplete="new-password"
            onChange={(e) => setNewPassword(e.target.value)}
          />
          <Input
            type="password"
            placeholder="Confirm new password"
            value={confirmPassword}
            autoComplete="new-password"
            onChange={(e) => setConfirmPassword(e.target.value)}
          />
        </div>
        {passwordStatus && (
          <p
            className={`mt-3 text-sm ${passwordStatus.type === 'success' ? 'text-success' : 'text-danger'}`}
          >
            {passwordStatus.message}
          </p>
        )}
        <div className="mt-4 flex justify-end gap-2">
          <Button
            type="button"
            variant="secondary"
            className="text-sm"
            onClick={() => {
              setShowChangePassword(false);
              setPasswordStatus(null);
            }}
          >
            Close
          </Button>
          <Button
            type="button"
            variant="accent"
            className="text-sm"
            onClick={handleChangePassword}
            disabled={passwordSaving}
          >
            {passwordSaving ? 'Saving...' : 'Update Password'}
          </Button>
        </div>
      </Modal>
    </div>
  );
}

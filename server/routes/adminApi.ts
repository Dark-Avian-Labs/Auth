import {
  Router,
  type NextFunction,
  type Request,
  type Response,
} from 'express';
import { rateLimit } from 'express-rate-limit';

import {
  hashPassword,
  requestIp,
  requireAdmin,
  revokeSessionsForUser,
} from '../auth/service.js';
import {
  appendAuditLog,
  db,
  getGamesForUsers,
  getUserById,
  listPermissionsForUsers,
  replacePermissions,
  setAppAccess,
} from '../db/authDb.js';

export const adminApiRouter = Router();
const ALLOWED_PERMISSIONS = new Set<string>([
  'read',
  'write',
  'create',
  'update',
  'delete',
  'admin',
]);

const adminLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
});

adminApiRouter.use(adminLimiter, requireAdmin);

function sanitizeUsername(raw: string): string {
  const normalized = raw
    .normalize('NFKC')
    .trim()
    .toLowerCase()
    .replace(/\s+/g, '');
  if (!/^[a-z0-9._-]{3,40}$/.test(normalized)) {
    return '';
  }
  return normalized;
}

function isSqliteConstraintError(error: unknown): boolean {
  if (!error || typeof error !== 'object') {
    return false;
  }
  const code =
    'code' in error && typeof error.code === 'string' ? error.code : '';
  const message =
    'message' in error && typeof error.message === 'string'
      ? error.message
      : '';
  return code === 'SQLITE_CONSTRAINT' || message.includes('SQLITE_CONSTRAINT');
}

adminApiRouter.get('/users', (_req: Request, res: Response) => {
  const users = db
    .prepare(
      'SELECT id, username, is_admin, created_at FROM users ORDER BY created_at ASC',
    )
    .all() as Array<{
    id: number;
    username: string;
    is_admin: number;
    created_at: string;
  }>;
  const userIds = users.map((user) => user.id);
  const gamesByUserId = getGamesForUsers(userIds);
  const permissionsByUserId = listPermissionsForUsers(userIds);
  const payload = users.map((user) => ({
    ...user,
    is_admin: Boolean(user.is_admin),
    app_access: gamesByUserId[user.id] ?? [],
    permissions: permissionsByUserId[user.id] ?? [],
  }));
  res.json({ users: payload });
});

adminApiRouter.post(
  '/users',
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const username = sanitizeUsername(String(req.body?.username ?? ''));
      const password = String(req.body?.password ?? '');
      const isAdmin = Boolean(req.body?.is_admin);
      if (!username || !password) {
        res.status(400).json({
          error:
            'username and password are required (username: a-z, 0-9, . _ -)',
        });
        return;
      }
      if (password.length < 8 || password.length > 128) {
        res
          .status(400)
          .json({ error: 'Password must be between 8 and 128 characters.' });
        return;
      }

      const hash = await hashPassword(password);
      let createdUserId = 0;
      try {
        const result = db
          .prepare(
            'INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)',
          )
          .run(username, hash, isAdmin ? 1 : 0);
        createdUserId = Number(result.lastInsertRowid);
      } catch (error) {
        if (isSqliteConstraintError(error)) {
          res.status(400).json({ error: 'Username already exists' });
          return;
        }
        throw error;
      }

      appendAuditLog({
        actorUserId: req.session.user_id!,
        eventType: 'admin.user.create',
        targetType: 'user',
        targetId: String(createdUserId),
        detailsJson: JSON.stringify({ username, isAdmin }),
        ip: requestIp(req),
      });
      res.json({ success: true, user_id: createdUserId });
    } catch (error) {
      next(error);
    }
  },
);

adminApiRouter.patch(
  '/users/:id',
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = parseInt(String(req.params.id), 10);
      if (!Number.isInteger(userId) || userId <= 0) {
        res.status(400).json({ error: 'Invalid user id' });
        return;
      }

      const updates: string[] = [];
      const values: Array<string | number> = [];
      const changes: Record<string, string | boolean> = {};
      let passwordUpdated = false;
      if (typeof req.body?.username === 'string' && req.body.username.trim()) {
        const username = sanitizeUsername(req.body.username);
        if (!username) {
          res.status(400).json({ error: 'Invalid username format.' });
          return;
        }
        const existing = db
          .prepare(
            'SELECT id FROM users WHERE LOWER(username) = LOWER(?) AND id != ?',
          )
          .get(username, userId) as { id: number } | undefined;
        if (existing) {
          res.status(409).json({ error: 'Username already exists' });
          return;
        }
        updates.push('username = ?');
        values.push(username);
        changes.username = username;
      }
      if (typeof req.body?.is_admin === 'boolean') {
        updates.push('is_admin = ?');
        values.push(req.body.is_admin ? 1 : 0);
        changes.is_admin = req.body.is_admin;
      }
      if (
        typeof req.body?.password === 'string' &&
        req.body.password.length > 0
      ) {
        if (req.body.password.length < 8) {
          res
            .status(400)
            .json({ error: 'Password must be at least 8 characters.' });
          return;
        }
        updates.push('password_hash = ?');
        values.push(await hashPassword(req.body.password));
        passwordUpdated = true;
        changes.password_hash = '[updated]';
      }
      if (updates.length === 0) {
        res.status(400).json({ error: 'No updates provided' });
        return;
      }

      values.push(userId);
      const result = db
        .prepare(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`)
        .run(...values);
      if (result.changes < 1) {
        res.status(404).json({ error: 'User not found' });
        return;
      }
      if (typeof req.body?.is_admin === 'boolean' || passwordUpdated) {
        revokeSessionsForUser(userId);
      }
      appendAuditLog({
        actorUserId: req.session.user_id!,
        eventType: 'admin.user.update',
        targetType: 'user',
        targetId: String(userId),
        detailsJson: JSON.stringify({ changes }),
        ip: requestIp(req),
      });
      res.json({ success: true });
    } catch (error) {
      next(error);
    }
  },
);

adminApiRouter.delete('/users/:id', (req: Request, res: Response) => {
  const userId = parseInt(String(req.params.id), 10);
  if (!Number.isInteger(userId) || userId <= 0) {
    res.status(400).json({ error: 'Invalid user id' });
    return;
  }
  if (req.session.user_id === userId) {
    res.status(400).json({ error: 'Cannot delete your own account' });
    return;
  }
  const result = db.prepare('DELETE FROM users WHERE id = ?').run(userId);
  if (result.changes < 1) {
    res.status(404).json({ error: 'User not found' });
    return;
  }
  revokeSessionsForUser(userId);
  appendAuditLog({
    actorUserId: req.session.user_id!,
    eventType: 'admin.user.delete',
    targetType: 'user',
    targetId: String(userId),
    ip: requestIp(req),
  });
  res.json({ success: true });
});

adminApiRouter.put('/users/:id/apps/:appId', (req: Request, res: Response) => {
  const userId = parseInt(String(req.params.id), 10);
  const appId = String(req.params.appId || '').trim();
  if (!Number.isInteger(userId) || userId <= 0 || !appId) {
    res.status(400).json({ error: 'Invalid user id or app id' });
    return;
  }
  const user = getUserById(userId);
  if (!user) {
    res.status(404).json({ error: 'User not found' });
    return;
  }
  const enabled = Boolean(req.body?.enabled);
  setAppAccess(userId, appId, enabled);
  appendAuditLog({
    actorUserId: req.session.user_id!,
    eventType: 'admin.user.app_access.update',
    targetType: 'user',
    targetId: String(userId),
    detailsJson: JSON.stringify({ appId, enabled }),
    ip: requestIp(req),
  });
  res.json({ success: true });
});

adminApiRouter.put('/users/:id/permissions', (req: Request, res: Response) => {
  const userId = parseInt(String(req.params.id), 10);
  const appId = String(req.body?.app_id ?? '').trim();
  const rawPermissions: unknown[] = Array.isArray(req.body?.permissions)
    ? req.body.permissions
    : [];

  if (!Number.isInteger(userId) || userId <= 0 || !appId) {
    res.status(400).json({ error: 'Invalid user id or app_id' });
    return;
  }
  const user = getUserById(userId);
  if (!user) {
    res.status(404).json({ error: 'User not found' });
    return;
  }

  const hasInvalidType = rawPermissions.some(
    (value) => typeof value !== 'string',
  );
  if (hasInvalidType) {
    res.status(400).json({ error: 'permissions must be an array of strings' });
    return;
  }
  const normalizedPermissions = (rawPermissions as string[]).map((value) =>
    value.trim().toLowerCase(),
  );

  const unknownPermissions = normalizedPermissions.filter(
    (permission) =>
      permission.length > 0 && !ALLOWED_PERMISSIONS.has(permission),
  );
  if (unknownPermissions.length > 0) {
    res.status(400).json({
      error: `Unknown permissions: ${Array.from(new Set(unknownPermissions)).join(', ')}`,
    });
    return;
  }

  const validatedPermissions: string[] = Array.from(
    new Set(
      normalizedPermissions.filter(
        (permission) =>
          permission.length > 0 && ALLOWED_PERMISSIONS.has(permission),
      ),
    ),
  );

  replacePermissions(userId, appId, validatedPermissions);
  appendAuditLog({
    actorUserId: req.session.user_id!,
    eventType: 'admin.user.permissions.update',
    targetType: 'user',
    targetId: String(userId),
    detailsJson: JSON.stringify({ appId, permissions: validatedPermissions }),
    ip: requestIp(req),
  });
  res.json({ success: true });
});

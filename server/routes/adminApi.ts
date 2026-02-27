import { Router, type Request, type Response } from 'express';
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
  getGamesForUser,
  getUserByUsername,
  listPermissions,
  replacePermissions,
  setAppAccess,
} from '../db/authDb.js';

export const adminApiRouter = Router();

const adminLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
});

adminApiRouter.use(adminLimiter, requireAdmin);

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
  const payload = users.map((user) => ({
    ...user,
    is_admin: Boolean(user.is_admin),
    app_access: getGamesForUser(user.id),
    permissions: listPermissions(user.id),
  }));
  res.json({ users: payload });
});

adminApiRouter.post('/users', async (req: Request, res: Response) => {
  const username = String(req.body?.username ?? '').trim();
  const password = String(req.body?.password ?? '');
  const isAdmin = Boolean(req.body?.is_admin);
  if (!username || !password) {
    res.status(400).json({ error: 'username and password are required.' });
    return;
  }
  if (password.length < 8) {
    res.status(400).json({ error: 'Password must be at least 8 characters.' });
    return;
  }
  if (getUserByUsername(username)) {
    res.status(400).json({ error: 'Username already exists' });
    return;
  }

  const hash = await hashPassword(password);
  const result = db
    .prepare(
      'INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)',
    )
    .run(username, hash, isAdmin ? 1 : 0);
  const createdUserId = Number(result.lastInsertRowid);
  appendAuditLog({
    actorUserId: req.session.user_id!,
    eventType: 'admin.user.create',
    targetType: 'user',
    targetId: String(createdUserId),
    detailsJson: JSON.stringify({ username, isAdmin }),
    ip: requestIp(req),
  });
  res.json({ success: true, user_id: createdUserId });
});

adminApiRouter.patch('/users/:id', async (req: Request, res: Response) => {
  const userId = parseInt(String(req.params.id), 10);
  if (!Number.isInteger(userId) || userId <= 0) {
    res.status(400).json({ error: 'Invalid user id' });
    return;
  }

  const updates: string[] = [];
  const values: Array<string | number> = [];
  if (typeof req.body?.username === 'string' && req.body.username.trim()) {
    updates.push('username = ?');
    values.push(req.body.username.trim());
  }
  if (typeof req.body?.is_admin === 'boolean') {
    updates.push('is_admin = ?');
    values.push(req.body.is_admin ? 1 : 0);
  }
  if (typeof req.body?.password === 'string' && req.body.password.length > 0) {
    if (req.body.password.length < 8) {
      res
        .status(400)
        .json({ error: 'Password must be at least 8 characters.' });
      return;
    }
    updates.push('password_hash = ?');
    values.push(await hashPassword(req.body.password));
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
  if (typeof req.body?.is_admin === 'boolean') {
    revokeSessionsForUser(userId);
  }
  appendAuditLog({
    actorUserId: req.session.user_id!,
    eventType: 'admin.user.update',
    targetType: 'user',
    targetId: String(userId),
    detailsJson: JSON.stringify({ updates }),
    ip: requestIp(req),
  });
  res.json({ success: true });
});

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
  const permissions = Array.isArray(req.body?.permissions)
    ? req.body.permissions.filter(
        (value: unknown): value is string => typeof value === 'string',
      )
    : [];

  if (!Number.isInteger(userId) || userId <= 0 || !appId) {
    res.status(400).json({ error: 'Invalid user id or app_id' });
    return;
  }
  replacePermissions(userId, appId, permissions);
  appendAuditLog({
    actorUserId: req.session.user_id!,
    eventType: 'admin.user.permissions.update',
    targetType: 'user',
    targetId: String(userId),
    detailsJson: JSON.stringify({ appId, permissions }),
    ip: requestIp(req),
  });
  res.json({ success: true });
});

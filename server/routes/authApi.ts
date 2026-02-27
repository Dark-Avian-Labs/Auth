import { Router, type Request, type Response } from 'express';
import { rateLimit } from 'express-rate-limit';

import {
  buildAppCards,
  clearAuthCookies,
  hashPassword,
  requestIp,
  requireAuth,
  revokeSessionsForUser,
  sanitizeNextUrl,
  verifyPassword,
} from '../auth/service.js';
import {
  appendAuditLog,
  db,
  getGamesForUser,
  getUserById,
  getUserByUsername,
  hasAppAccess,
  listPermissions,
} from '../db/authDb.js';

export function createAuthApiRouter(csrfToken: (req: Request) => string) {
  const authRouter = Router();

  const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 120,
    standardHeaders: true,
    legacyHeaders: false,
  });
  const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    standardHeaders: true,
    legacyHeaders: false,
  });
  const passwordLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 15,
    standardHeaders: true,
    legacyHeaders: false,
  });
  const profileLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 60,
    standardHeaders: true,
    legacyHeaders: false,
  });

  authRouter.use(authLimiter);

  const removeControlChars = (value: string): string => {
    let output = '';
    for (const char of value) {
      const code = char.charCodeAt(0);
      if (code <= 31 || code === 127) {
        continue;
      }
      output += char;
    }
    return output;
  };

  const sanitizePlainText = (input: string, maxLength: number): string => {
    const normalized = input
      .normalize('NFKC')
      .split('\r')
      .join('')
      .split('\n')
      .join('');
    const safe = removeControlChars(normalized).replace(/[<>]/g, '').trim();
    return safe.slice(0, maxLength);
  };

  const sanitizeEmail = (input: string): string => {
    const normalized = sanitizePlainText(input, 254).toLowerCase();
    if (!normalized) {
      return '';
    }
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(normalized) ? normalized : '';
  };

  authRouter.get('/csrf', (req: Request, res: Response) => {
    res.json({ csrfToken: csrfToken(req) });
  });

  authRouter.post(
    '/login',
    loginLimiter,
    async (req: Request, res: Response) => {
      const username = String(req.body?.username ?? '').trim();
      const password = String(req.body?.password ?? '');
      const nextInput =
        typeof req.body?.next === 'string' && req.body.next.length > 0
          ? req.body.next
          : '';
      const next = sanitizeNextUrl(nextInput, '/');

      if (!username || !password) {
        res.status(400).json({ error: 'Username and password are required.' });
        return;
      }

      const user = getUserByUsername(username);
      if (!user) {
        appendAuditLog({
          actorUserId: null,
          eventType: 'auth.login.failed',
          targetType: 'user',
          targetId: username.toLowerCase(),
          detailsJson: JSON.stringify({ reason: 'user_not_found' }),
          ip: requestIp(req),
        });
        res.status(401).json({ error: 'Invalid username or password.' });
        return;
      }

      const valid = await verifyPassword(password, user.password_hash);
      if (!valid) {
        appendAuditLog({
          actorUserId: user.id,
          eventType: 'auth.login.failed',
          targetType: 'user',
          targetId: String(user.id),
          detailsJson: JSON.stringify({ reason: 'invalid_password' }),
          ip: requestIp(req),
        });
        res.status(401).json({ error: 'Invalid username or password.' });
        return;
      }

      req.session.regenerate((err) => {
        if (err) {
          res.status(500).json({ error: 'Failed to create session' });
          return;
        }
        req.session.user_id = user.id;
        req.session.username = user.username;
        req.session.is_admin = Boolean(user.is_admin);
        req.session.login_time = Date.now();
        req.session.save((saveErr) => {
          if (saveErr) {
            res.status(500).json({ error: 'Failed to persist session' });
            return;
          }
          appendAuditLog({
            actorUserId: user.id,
            eventType: 'auth.login.success',
            targetType: 'session',
            targetId: String(req.sessionID),
            detailsJson: JSON.stringify({ next }),
            ip: requestIp(req),
          });
          res.json({
            success: true,
            user: {
              id: user.id,
              username: user.username,
              is_admin: Boolean(user.is_admin),
              display_name: user.display_name ?? '',
              email: user.email ?? '',
              avatar: user.avatar ?? 1,
            },
            next,
          });
        });
      });
    },
  );

  authRouter.post('/logout', (req: Request, res: Response) => {
    const actorUserId =
      typeof req.session.user_id === 'number' ? req.session.user_id : null;
    req.session.destroy(() => {
      clearAuthCookies(res);
      appendAuditLog({
        actorUserId,
        eventType: 'auth.logout',
        targetType: 'session',
        ip: requestIp(req),
      });
      res.json({ success: true });
    });
  });

  authRouter.get('/me', (req: Request, res: Response) => {
    const appId =
      typeof req.query.app === 'string' && req.query.app.length > 0
        ? req.query.app
        : null;
    if (typeof req.session.user_id !== 'number' || req.session.user_id <= 0) {
      res.json({ authenticated: false, has_game_access: false });
      return;
    }

    const userId = req.session.user_id;
    const user = getUserById(userId);
    if (!user) {
      res.json({ authenticated: false, has_game_access: false });
      return;
    }

    const gameAccess = appId ? hasAppAccess(userId, appId) : true;
    const permissions = listPermissions(userId, appId ?? undefined).map(
      (row) => `${row.app_id}:${row.permission}`,
    );

    res.json({
      authenticated: true,
      has_game_access: gameAccess,
      user: {
        id: user.id,
        username: user.username,
        is_admin: Boolean(user.is_admin),
        display_name: user.display_name ?? '',
        email: user.email ?? '',
        avatar: user.avatar ?? 1,
      },
      app_access: getGamesForUser(userId),
      apps: buildAppCards(userId),
      permissions,
    });
  });

  authRouter.get(
    '/profile',
    requireAuth,
    profileLimiter,
    (req: Request, res: Response) => {
      const user = getUserById(req.session.user_id!);
      if (!user) {
        res.status(404).json({ error: 'User not found' });
        return;
      }
      res.json({
        user: {
          id: user.id,
          username: user.username,
          is_admin: Boolean(user.is_admin),
          display_name: user.display_name ?? '',
          email: user.email ?? '',
          avatar: user.avatar ?? 1,
        },
      });
    },
  );

  authRouter.patch(
    '/profile',
    requireAuth,
    profileLimiter,
    (req: Request, res: Response) => {
      const user = getUserById(req.session.user_id!);
      if (!user) {
        res.status(404).json({ error: 'User not found' });
        return;
      }

      const updates: string[] = [];
      const values: Array<string | number> = [];
      if (typeof req.body?.display_name === 'string') {
        const displayName = sanitizePlainText(req.body.display_name, 80);
        updates.push('display_name = ?');
        values.push(displayName);
      }
      if (typeof req.body?.email === 'string') {
        const rawEmail = sanitizePlainText(req.body.email, 254);
        const email = sanitizeEmail(req.body.email);
        if (rawEmail.length > 0 && email.length === 0) {
          res.status(400).json({ error: 'Invalid email format.' });
          return;
        }
        updates.push('email = ?');
        values.push(email);
      }
      if (req.body?.avatar !== undefined) {
        const avatar = Number(req.body.avatar);
        if (!Number.isInteger(avatar) || avatar < 1 || avatar > 16) {
          res.status(400).json({ error: 'Avatar must be between 1 and 16.' });
          return;
        }
        updates.push('avatar = ?');
        values.push(avatar);
      }

      if (updates.length === 0) {
        res.status(400).json({ error: 'No profile updates provided.' });
        return;
      }

      values.push(user.id);
      db.prepare(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`).run(
        ...values,
      );
      const updated = getUserById(user.id);
      if (!updated) {
        res.status(500).json({ error: 'Failed to load updated profile.' });
        return;
      }
      appendAuditLog({
        actorUserId: user.id,
        eventType: 'auth.profile.update',
        targetType: 'user',
        targetId: String(user.id),
        detailsJson: JSON.stringify({ updates }),
        ip: requestIp(req),
      });
      res.json({
        success: true,
        user: {
          id: updated.id,
          username: updated.username,
          is_admin: Boolean(updated.is_admin),
          display_name: updated.display_name ?? '',
          email: updated.email ?? '',
          avatar: updated.avatar ?? 1,
        },
      });
    },
  );

  authRouter.post(
    '/change-password',
    requireAuth,
    passwordLimiter,
    async (req: Request, res: Response) => {
      const currentPassword = String(req.body?.current_password ?? '');
      const newPassword = String(req.body?.new_password ?? '');
      if (!currentPassword || !newPassword) {
        res
          .status(400)
          .json({ error: 'current_password and new_password are required.' });
        return;
      }
      if (newPassword.length < 8) {
        res
          .status(400)
          .json({ error: 'Password must be at least 8 characters.' });
        return;
      }

      const user = getUserById(req.session.user_id!);
      if (!user) {
        res.status(404).json({ error: 'User not found' });
        return;
      }
      const valid = await verifyPassword(currentPassword, user.password_hash);
      if (!valid) {
        appendAuditLog({
          actorUserId: user.id,
          eventType: 'auth.password_change.failed',
          targetType: 'user',
          targetId: String(user.id),
          detailsJson: JSON.stringify({ reason: 'invalid_current_password' }),
          ip: requestIp(req),
        });
        res.status(400).json({ error: 'Current password is incorrect' });
        return;
      }

      const hash = await hashPassword(newPassword);
      db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(
        hash,
        user.id,
      );
      revokeSessionsForUser(user.id);
      appendAuditLog({
        actorUserId: user.id,
        eventType: 'auth.password_change.success',
        targetType: 'user',
        targetId: String(user.id),
        ip: requestIp(req),
      });
      res.json({ success: true });
    },
  );

  authRouter.post('/logout-all', requireAuth, (req: Request, res: Response) => {
    const userId = req.session.user_id!;
    revokeSessionsForUser(userId);
    appendAuditLog({
      actorUserId: userId,
      eventType: 'auth.logout_all',
      targetType: 'user',
      targetId: String(userId),
      ip: requestIp(req),
    });
    clearAuthCookies(res);
    res.json({ success: true });
  });

  return authRouter;
}

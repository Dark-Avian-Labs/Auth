import argon2 from 'argon2';
import Database from 'better-sqlite3';
import cookieParser from 'cookie-parser';
import { csrfSync } from 'csrf-sync';
import express from 'express';
import { rateLimit } from 'express-rate-limit';
import session from 'express-session';
import { createRequire } from 'module';
import path from 'path';

import {
  db,
  CENTRAL_DB_PATH,
  createSchema,
  getGamesForUser,
  getUserById,
  getUserByUsername,
  hasAppAccess,
  listPermissions,
  appendAuditLog,
  replacePermissions,
  setAppAccess,
} from './db.js';

const require = createRequire(import.meta.url);
const SQLiteStore = require('better-sqlite3-session-store')(
  session,
) as new (options: {
  client: Database.Database;
  expired: { clear: boolean; intervalMs: number };
}) => session.Store;

try {
  process.loadEnvFile(path.join(process.cwd(), '.env'));
} catch {
  // Ignore when .env is absent; environment may be injected by PM2/systemd.
}

const PORT = parseInt(process.env.PORT ?? '3010', 10);
const HOST = process.env.HOST ?? '127.0.0.1';
const SESSION_SECRET = process.env.SESSION_SECRET;
if (!SESSION_SECRET || SESSION_SECRET.length < 32) {
  throw new Error(
    'Set SESSION_SECRET to at least 32 chars for the Auth service.',
  );
}

const COOKIE_DOMAIN = process.env.AUTH_COOKIE_DOMAIN ?? '.shark5060.net';
const COOKIE_NAME = process.env.AUTH_COOKIE_NAME ?? 'shark.auth.sid';
const AUTH_PUBLIC_BASE_URL =
  process.env.AUTH_PUBLIC_BASE_URL ?? 'https://auth.shark5060.net';
const TRUST_PROXY =
  process.env.TRUST_PROXY === '1' || process.env.TRUST_PROXY === 'true';
const ALLOWED_APP_ORIGINS = (
  process.env.AUTH_ALLOWED_ORIGINS ??
  'https://parametric.shark5060.net,https://corpus.shark5060.net'
)
  .split(',')
  .map((v) => v.trim())
  .filter((v) => v.length > 0);
const ALLOWED_NEXT_ORIGINS = (
  process.env.AUTH_ALLOWED_NEXT_ORIGINS ?? ALLOWED_APP_ORIGINS.join(',')
)
  .split(',')
  .map((v) => v.trim())
  .filter((v) => v.length > 0);

createSchema();
console.log(`[Auth] Central DB ready (${CENTRAL_DB_PATH})`);

const app = express();
if (TRUST_PROXY) app.set('trust proxy', 1);
app.use(cookieParser());
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));

const STATIC_ROOT = process.cwd();
const staticAssetLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
});
app.get('/favicon.ico', staticAssetLimiter, (_req, res) => {
  res.sendFile(path.join(STATIC_ROOT, 'favicon.ico'));
});
app.get('/branding/feathers.png', staticAssetLimiter, (_req, res) => {
  res.sendFile(path.join(STATIC_ROOT, 'feathers.png'));
});

const sessionStore = new SQLiteStore({
  client: db,
  expired: { clear: true, intervalMs: 15 * 60 * 1000 },
});

app.use(
  session({
    name: COOKIE_NAME,
    store: sessionStore,
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 7 * 24 * 60 * 60 * 1000,
      httpOnly: true,
      secure: true,
      sameSite: 'none',
      domain: COOKIE_DOMAIN,
    },
  }),
);

const { csrfSynchronisedProtection, generateToken } = csrfSync({
  getTokenFromRequest: (req: express.Request) => {
    if (req.body?._csrf) return String(req.body._csrf);
    const q = req.query?._csrf;
    if (Array.isArray(q)) return String(q[0] ?? '');
    if (typeof q === 'string') return q;
    const header = req.headers['x-csrf-token'] ?? req.headers['x-xsrf-token'];
    if (Array.isArray(header)) return String(header[0] ?? '');
    if (typeof header === 'string') return header;
    return '';
  },
  getTokenFromState: (req) => {
    const sess = req.session;
    if (!sess) return null;
    return sess.csrfToken ?? null;
  },
  storeTokenInState: (req, token) => {
    if (req.session) req.session.csrfToken = token;
  },
});

function parseUrlSafe(url: string): URL | null {
  try {
    return new URL(url);
  } catch {
    return null;
  }
}

function isAllowedOrigin(url: URL, allowlist: string[]): boolean {
  return allowlist.includes(url.origin);
}

function sanitizeNextUrl(
  input: string | undefined,
  fallbackPath: string,
): string {
  const fallback = new URL(fallbackPath, AUTH_PUBLIC_BASE_URL).toString();
  if (!input || input.length < 1) return fallback;
  const parsed = parseUrlSafe(input);
  if (!parsed) return fallback;
  if (!isAllowedOrigin(parsed, ALLOWED_NEXT_ORIGINS)) return fallback;
  return parsed.toString();
}

function requestIp(req: express.Request): string {
  const forwarded = req.headers['x-forwarded-for'];
  if (Array.isArray(forwarded) && forwarded.length > 0) {
    return String(forwarded[0]).split(',')[0]?.trim() ?? req.ip ?? 'unknown';
  }
  if (typeof forwarded === 'string' && forwarded.length > 0) {
    return forwarded.split(',')[0]?.trim() ?? req.ip ?? 'unknown';
  }
  return req.ip ?? 'unknown';
}

function corsAllowlist(
  req: express.Request,
  res: express.Response,
  next: express.NextFunction,
): void {
  const origin = req.headers.origin;
  if (typeof origin === 'string' && ALLOWED_APP_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader(
      'Access-Control-Allow-Headers',
      'Content-Type, X-CSRF-Token, X-XSRF-Token',
    );
    res.setHeader(
      'Access-Control-Allow-Methods',
      'GET,POST,PATCH,PUT,DELETE,OPTIONS',
    );
  }
  if (req.method === 'OPTIONS') {
    res.status(204).end();
    return;
  }
  next();
}

app.use(corsAllowlist);

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use('/api', authLimiter);

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

const adminLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
});

async function verifyPassword(
  password: string,
  hash: string,
): Promise<boolean> {
  try {
    return await argon2.verify(hash, password);
  } catch {
    return false;
  }
}

async function hashPassword(password: string): Promise<string> {
  return await argon2.hash(password, {
    type: argon2.argon2id,
    memoryCost: 19 * 1024,
    timeCost: 2,
    parallelism: 1,
  });
}

function requireAuth(
  req: express.Request,
  res: express.Response,
  next: express.NextFunction,
): void {
  if (typeof req.session.user_id === 'number' && req.session.user_id > 0) {
    next();
    return;
  }
  res.status(401).json({ error: 'Authentication required' });
}

function requireAdmin(
  req: express.Request,
  res: express.Response,
  next: express.NextFunction,
): void {
  if (typeof req.session.user_id !== 'number' || req.session.user_id <= 0) {
    res.status(401).json({ error: 'Authentication required' });
    return;
  }
  if (!req.session.is_admin) {
    res.status(403).json({ error: 'Admin access required' });
    return;
  }
  next();
}

app.get('/login', (req, res) => {
  const nextInput =
    typeof req.query.next === 'string' && req.query.next.length > 0
      ? req.query.next
      : '';
  const next = sanitizeNextUrl(nextInput, '/');
  const csrfToken = generateToken(req);
  const loginHtml = `<!doctype html>
<html>
  <head>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1"/>
    <title>Auth Login</title>
    <link rel="icon" href="/favicon.ico" />
    <style>
      body {
        margin: 0;
        min-height: 100vh;
        display: grid;
        place-items: center;
        background: #0f1015;
        color: #f5f6fb;
        font-family: system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
      }
      .auth-box {
        width: min(92vw, 380px);
        background: #171925;
        border: 1px solid #2a2f45;
        border-radius: 12px;
        padding: 24px 20px;
        box-shadow: 0 12px 32px rgba(0, 0, 0, 0.28);
      }
      .brand {
        display: block;
        width: 120px;
        max-width: 40%;
        margin: 0 auto 10px;
      }
      h1 {
        margin: 0 0 16px;
        text-align: center;
        font-size: 1.25rem;
      }
      form {
        display: grid;
        gap: 10px;
      }
      input,
      button {
        font: inherit;
        border-radius: 8px;
        border: 1px solid #343a57;
        padding: 10px 12px;
      }
      input {
        background: #0f1220;
        color: #f5f6fb;
      }
      button {
        cursor: pointer;
        background: #8d140f;
        border-color: #8d140f;
        color: #fff;
        font-weight: 600;
      }
    </style>
  </head>
  <body>
    <main class="auth-box">
      <img class="brand" src="/branding/feathers.png" alt="Auth branding" />
      <h1>Auth Login</h1>
      <form method="post" action="/api/auth/login">
        <input type="text" name="username" placeholder="Username" required />
        <input type="password" name="password" placeholder="Password" required />
        <input type="hidden" name="_csrf" value="${csrfToken.replace(/"/g, '&quot;')}" />
        <input type="hidden" name="next" value="${next.replace(/"/g, '&quot;')}" />
        <button type="submit">Login</button>
      </form>
    </main>
  </body>
</html>`;
  res.type('html').send(loginHtml);
});

app.get('/logout', (req, res) => {
  const nextInput =
    typeof req.query.next === 'string' && req.query.next.length > 0
      ? req.query.next
      : '';
  const next = sanitizeNextUrl(nextInput, '/login');
  req.session.destroy(() => {
    res.clearCookie(COOKIE_NAME, {
      httpOnly: true,
      secure: true,
      sameSite: 'none',
      domain: COOKIE_DOMAIN,
    });
    res.redirect(next);
  });
});

app.get('/api/auth/csrf', requireAuth, (req, res) => {
  const token = generateToken(req);
  res.json({ csrfToken: token });
});

app.post(
  '/api/auth/login',
  loginLimiter,
  csrfSynchronisedProtection,
  async (req, res) => {
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
    const ok = await verifyPassword(password, user.password_hash);
    if (!ok) {
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
        const payload = {
          success: true,
          user: {
            id: user.id,
            username: user.username,
            is_admin: Boolean(user.is_admin),
          },
          next,
        };
        if (
          req.headers.accept?.includes('text/html') &&
          next &&
          /^https?:\/\//.test(next)
        ) {
          res.redirect(next);
          return;
        }
        res.json(payload);
      });
    });
  },
);

app.post('/api/auth/logout', csrfSynchronisedProtection, (req, res) => {
  const actorUserId =
    typeof req.session.user_id === 'number' ? req.session.user_id : null;
  req.session.destroy(() => {
    res.clearCookie(COOKIE_NAME, {
      httpOnly: true,
      secure: true,
      sameSite: 'none',
      domain: COOKIE_DOMAIN,
    });
    appendAuditLog({
      actorUserId,
      eventType: 'auth.logout',
      targetType: 'session',
      ip: requestIp(req),
    });
    res.json({ success: true });
  });
});

app.get('/api/auth/me', (req, res) => {
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
    },
    app_access: getGamesForUser(userId),
    permissions,
  });
});

app.post(
  '/api/auth/change-password',
  requireAuth,
  passwordLimiter,
  csrfSynchronisedProtection,
  async (req, res) => {
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
    const ok = await verifyPassword(currentPassword, user.password_hash);
    if (!ok) {
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
    db.prepare('DELETE FROM sessions WHERE sess LIKE ?').run(
      `%"user_id":${user.id}%`,
    );
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

app.post(
  '/api/auth/logout-all',
  requireAuth,
  csrfSynchronisedProtection,
  (req, res) => {
    const userId = req.session.user_id!;
    db.prepare('DELETE FROM sessions WHERE sess LIKE ?').run(
      `%"user_id":${userId}%`,
    );
    appendAuditLog({
      actorUserId: userId,
      eventType: 'auth.logout_all',
      targetType: 'user',
      targetId: String(userId),
      ip: requestIp(req),
    });
    res.clearCookie(COOKIE_NAME, {
      httpOnly: true,
      secure: true,
      sameSite: 'none',
      domain: COOKIE_DOMAIN,
    });
    res.json({ success: true });
  },
);

app.get('/api/admin/users', adminLimiter, requireAdmin, (_req, res) => {
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

app.post(
  '/api/admin/users',
  adminLimiter,
  requireAdmin,
  csrfSynchronisedProtection,
  async (req, res) => {
    const username = String(req.body?.username ?? '').trim();
    const password = String(req.body?.password ?? '');
    const isAdmin = Boolean(req.body?.is_admin);
    if (!username || !password) {
      res.status(400).json({ error: 'username and password are required.' });
      return;
    }
    if (password.length < 8) {
      res
        .status(400)
        .json({ error: 'Password must be at least 8 characters.' });
      return;
    }
    const existing = getUserByUsername(username);
    if (existing) {
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
  },
);

app.patch(
  '/api/admin/users/:id',
  adminLimiter,
  requireAdmin,
  csrfSynchronisedProtection,
  async (req, res) => {
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
    appendAuditLog({
      actorUserId: req.session.user_id!,
      eventType: 'admin.user.update',
      targetType: 'user',
      targetId: String(userId),
      detailsJson: JSON.stringify({ updates }),
      ip: requestIp(req),
    });
    res.json({ success: true });
  },
);

app.delete(
  '/api/admin/users/:id',
  adminLimiter,
  requireAdmin,
  csrfSynchronisedProtection,
  (req, res) => {
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
    appendAuditLog({
      actorUserId: req.session.user_id!,
      eventType: 'admin.user.delete',
      targetType: 'user',
      targetId: String(userId),
      ip: requestIp(req),
    });
    res.json({ success: true });
  },
);

app.put(
  '/api/admin/users/:id/apps/:appId',
  adminLimiter,
  requireAdmin,
  csrfSynchronisedProtection,
  (req, res) => {
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
  },
);

app.put(
  '/api/admin/users/:id/permissions',
  adminLimiter,
  requireAdmin,
  csrfSynchronisedProtection,
  (req, res) => {
    const userId = parseInt(String(req.params.id), 10);
    const appId = String(req.body?.app_id ?? '').trim();
    const permissions = Array.isArray(req.body?.permissions)
      ? req.body.permissions.filter(
          (p: unknown): p is string => typeof p === 'string',
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
  },
);

app.get('/admin', (_req, res) => {
  res
    .type('html')
    .send(
      '<h1>Central Auth Admin</h1><p>Use API endpoints at /api/admin/users for user and permission management.</p>',
    );
});

app.use('/api', (_req, res) => {
  res.status(404).json({ error: 'Not found' });
});

app.listen(PORT, HOST, () => {
  console.log(`[Auth] Running at http://${HOST}:${PORT}`);
});

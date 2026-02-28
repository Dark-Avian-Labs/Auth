import cookieParser from 'cookie-parser';
import { csrfSync } from 'csrf-sync';
import express, { type Request, type Response } from 'express';
import { rateLimit } from 'express-rate-limit';
import session from 'express-session';
import helmet from 'helmet';
import { createRequire } from 'module';
import path from 'path';

import { requireAdmin, sanitizeNextUrl } from './auth/service.js';
import {
  ALLOWED_APP_ORIGINS,
  APP_NAME,
  AUTH_COOKIE_DOMAIN,
  HOST,
  NODE_ENV,
  PORT,
  PROJECT_ROOT,
  SECURE_COOKIES,
  SESSION_COOKIE_NAME,
  SESSION_SECRET,
  TRUST_PROXY,
  ensureDataDirs,
} from './config.js';
import { createSchema, db } from './db/authDb.js';
import { adminApiRouter } from './routes/adminApi.js';
import { createAuthApiRouter } from './routes/authApi.js';

const require = createRequire(import.meta.url);
const SQLiteStore = require('better-sqlite3-session-store')(session);

ensureDataDirs();
createSchema();
console.log(`[${APP_NAME}] Central DB ready`);

const app = express();
if (TRUST_PROXY) app.set('trust proxy', 1);
if (NODE_ENV === 'production' && SECURE_COOKIES && !TRUST_PROXY) {
  throw new Error(
    'TRUST_PROXY must be enabled in production with secure cookies.',
  );
}

app.use(helmet());
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

const baselineLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 1200,
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) =>
    req.path === '/healthz' ||
    req.path === '/favicon.ico' ||
    /^\/assets\/.+\.(?:css|js|png|jpe?g|gif|webp|svg|ico|woff2?)$/i.test(
      req.path,
    ),
});
app.use(baselineLimiter);

const readinessLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
});

const sessionStore = new SQLiteStore({
  client: db,
  expired: { clear: true, intervalMs: 15 * 60 * 1000 },
});

const cookieOptions: express.CookieOptions = {
  maxAge: 7 * 24 * 60 * 60 * 1000,
  httpOnly: true,
  secure: SECURE_COOKIES,
  sameSite: SECURE_COOKIES ? 'none' : 'lax',
  domain: AUTH_COOKIE_DOMAIN,
};

app.use(
  session({
    name: SESSION_COOKIE_NAME,
    store: sessionStore,
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: cookieOptions,
  }),
);

const { csrfSynchronisedProtection, generateToken } = csrfSync({
  getTokenFromRequest: (req: Request) => {
    if (req.body?._csrf) return req.body._csrf as string;
    const header = req.headers['x-csrf-token'] || req.headers['x-xsrf-token'];
    return (Array.isArray(header) ? header[0] : header) ?? null;
  },
  getTokenFromState: (req) => {
    const sessionData = req.session;
    if (!sessionData) return null;
    return (sessionData as { csrf_token?: string }).csrf_token ?? null;
  },
  storeTokenInState: (req, token) => {
    if (req.session) {
      req.session.csrf_token = token as string;
    }
  },
});
app.use(csrfSynchronisedProtection);

app.use((req, res, next) => {
  (res.locals as { csrfToken?: string }).csrfToken = generateToken(req);
  next();
});

function corsAllowlist(
  req: Request,
  res: Response,
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
app.use(
  '/api/auth',
  createAuthApiRouter((req) => generateToken(req)),
);
app.use('/api/admin', adminApiRouter);

app.get('/logout', (req, res) => {
  const fetchSiteHeader = req.headers['sec-fetch-site'];
  const fetchSite = Array.isArray(fetchSiteHeader)
    ? fetchSiteHeader[0]
    : fetchSiteHeader;
  if (fetchSite === 'cross-site') {
    res.status(403).json({ error: 'Cross-site logout is not allowed.' });
    return;
  }

  const nextInput =
    typeof req.query.next === 'string' && req.query.next.length > 0
      ? req.query.next
      : '';
  const next = sanitizeNextUrl(nextInput, '/login');
  req.session.destroy((err) => {
    if (err) {
      console.error('[Session] Failed to destroy session:', err);
    }
    res.clearCookie(SESSION_COOKIE_NAME, {
      httpOnly: true,
      secure: SECURE_COOKIES,
      sameSite: 'none',
      domain: AUTH_COOKIE_DOMAIN,
    });
    res.redirect(next);
  });
});

app.use('/api', (_req, res) => {
  res.status(404).json({ error: 'Not found' });
});

app.get('/healthz', (_req, res) => {
  res.json({ status: 'ok', app: APP_NAME });
});

app.get('/readyz', readinessLimiter, (_req, res) => {
  try {
    db.prepare('SELECT 1').get();
    res.json({ status: 'ready', app: APP_NAME });
  } catch {
    res.status(503).json({ status: 'not_ready', app: APP_NAME });
  }
});

const publicPageLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 1200,
  standardHeaders: true,
  legacyHeaders: false,
});
const staticAssetLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5000,
  standardHeaders: true,
  legacyHeaders: false,
});

const clientDir = path.join(PROJECT_ROOT, 'dist', 'client');
const clientIndexPath = path.join(clientDir, 'index.html');
app.use(
  '/assets',
  staticAssetLimiter,
  express.static(path.join(clientDir, 'assets'), {
    maxAge: '1y',
    immutable: true,
  }),
);
app.use(publicPageLimiter, express.static(clientDir, { maxAge: '1h' }));

function ensureAuthenticatedPage(
  req: Request,
  res: Response,
  next: express.NextFunction,
): void {
  if (typeof req.session.user_id === 'number' && req.session.user_id > 0) {
    next();
    return;
  }
  res.redirect('/login');
}

app.get('/favicon.ico', publicPageLimiter, (_req, res) => {
  res.sendFile(path.join(PROJECT_ROOT, 'favicon.ico'));
});

app.get('/login', publicPageLimiter, (_req, res) => {
  res.sendFile(clientIndexPath);
});
app.get('/legal', publicPageLimiter, (_req, res) => {
  res.sendFile(clientIndexPath);
});
app.get('/admin', publicPageLimiter, requireAdmin, (_req, res) => {
  res.sendFile(clientIndexPath);
});
app.get('/profile', publicPageLimiter, ensureAuthenticatedPage, (_req, res) => {
  res.sendFile(clientIndexPath);
});
app.get('/', publicPageLimiter, ensureAuthenticatedPage, (_req, res) => {
  res.sendFile(clientIndexPath);
});

app.use(
  (err: unknown, _req: Request, res: Response, _next: express.NextFunction) => {
    const error = err as Partial<Error> & {
      status?: number;
      statusCode?: number;
    };
    console.error('[Error]', error.stack ?? error.message);
    const status =
      typeof error.status === 'number'
        ? error.status
        : typeof error.statusCode === 'number'
          ? error.statusCode
          : error.name === 'ForbiddenError'
            ? 403
            : 500;
    const safeMessage =
      NODE_ENV === 'production' && status >= 500
        ? 'Internal server error'
        : (error.message ?? 'Internal server error');
    res.status(status).json({ error: safeMessage });
  },
);

const server = app.listen(PORT, HOST, () => {
  console.log(
    `[${APP_NAME}] Server running on http://${HOST}:${PORT} (${NODE_ENV})`,
  );
});

const SHUTDOWN_TIMEOUT_MS = 10_000;
let shutdownStarted = false;
function shutdown(): void {
  if (shutdownStarted) return;
  shutdownStarted = true;

  function closeAndExit(): void {
    try {
      db.close();
    } catch (err) {
      console.error('[Shutdown] Failed to close DB:', err);
    }
    process.exit(0);
  }
  const timeout = setTimeout(() => closeAndExit(), SHUTDOWN_TIMEOUT_MS);
  server.close(() => {
    clearTimeout(timeout);
    closeAndExit();
  });
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

export default app;

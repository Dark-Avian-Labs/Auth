import { createRequire } from 'module';
import path from 'path';

import cookieParser from 'cookie-parser';
import { csrfSync } from 'csrf-sync';
import express, { type Request, type Response } from 'express';
import { rateLimit } from 'express-rate-limit';
import session from 'express-session';
import helmet from 'helmet';

import { requireAdminPage, requireAuthPage, sanitizeNextUrl } from './auth/service.js';
import {
  ALLOWED_APP_ORIGINS,
  APP_NAME,
  AUTH_PUBLIC_BASE_URL,
  APP_VERSION,
  AUTH_COOKIE_DOMAIN,
  HOST,
  NODE_ENV,
  PORT,
  PROJECT_ROOT,
  SECURE_COOKIES,
  SESSION_COOKIE_NAME,
  SESSION_SECRET,
  SHUTDOWN_TIMEOUT_MS,
  TRUST_PROXY,
  ensureDataDirs,
} from './config.js';
import { createSchema, db, migrateSchema } from './db/authDb.js';
import { getRequestId, requestIdMiddleware } from './http/requestId.js';
import { log } from './logger.js';
import { adminApiRouter } from './routes/adminApi.js';
import { createAuthApiRouter } from './routes/authApi.js';
import { secFetchSiteIsCrossSite } from './secFetchSite.js';

const require = createRequire(import.meta.url);
const SQLiteStore = require('better-sqlite3-session-store')(session);

ensureDataDirs();
createSchema();
migrateSchema();
log('info', 'Central DB ready', { app: APP_NAME });

const app = express();
if (TRUST_PROXY) app.set('trust proxy', 1);
if (NODE_ENV === 'production' && SECURE_COOKIES && !TRUST_PROXY) {
  throw new Error('TRUST_PROXY must be enabled in production with secure cookies.');
}

app.use(helmet());
app.use(requestIdMiddleware);
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
    req.path === '/readyz' ||
    req.path === '/api/version' ||
    req.path === '/favicon.ico' ||
    /^\/assets\/.+\.(?:css|js|png|jpe?g|gif|webp|svg|ico|woff2?)$/i.test(req.path),
});
app.use(baselineLimiter);

const sessionStore = new SQLiteStore({
  client: db,
  expired: { clear: true, intervalMs: 15 * 60 * 1000 },
});

const cookieOptions: express.CookieOptions = {
  path: '/',
  maxAge: 7 * 24 * 60 * 60 * 1000,
  httpOnly: true,
  secure: SECURE_COOKIES,
  sameSite: SECURE_COOKIES ? 'none' : 'lax',
  domain: AUTH_COOKIE_DOMAIN,
};

const sessionCookieClearOptions: Pick<
  express.CookieOptions,
  'path' | 'httpOnly' | 'secure' | 'sameSite' | 'domain'
> = {
  path: cookieOptions.path,
  httpOnly: cookieOptions.httpOnly,
  secure: cookieOptions.secure,
  sameSite: cookieOptions.sameSite,
  domain: cookieOptions.domain,
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

const CSRF_PROTECTED_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

app.use((req: Request, res: Response, next) => {
  if (!CSRF_PROTECTED_METHODS.has(req.method.toUpperCase())) {
    next();
    return;
  }

  if (secFetchSiteIsCrossSite(req)) {
    res.status(403).json({ error: 'Cross-site request blocked', code: 'CSRF_ORIGIN_INVALID' });
    return;
  }

  const originHeader = req.headers.origin;
  const origin = Array.isArray(originHeader) ? originHeader[0] : originHeader;
  if (typeof origin === 'string' && origin.length > 0) {
    const allowedOrigins = new Set<string>([AUTH_PUBLIC_BASE_URL, ...ALLOWED_APP_ORIGINS]);
    if (!allowedOrigins.has(origin)) {
      res.status(403).json({ error: 'Origin not allowed', code: 'CSRF_ORIGIN_INVALID' });
      return;
    }
  }

  next();
});

function corsAllowlist(req: Request, res: Response, next: express.NextFunction): void {
  const origin = req.headers.origin;
  if (typeof origin === 'string' && ALLOWED_APP_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-CSRF-Token, X-XSRF-Token');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PATCH,PUT,DELETE,OPTIONS');
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

app.post('/logout', (req, res) => {
  const nextInput =
    typeof req.query.next === 'string' && req.query.next.length > 0 ? req.query.next : '';
  const next = sanitizeNextUrl(nextInput, '/login');
  req.session.destroy((err) => {
    if (err) {
      log('error', 'Failed to destroy session during logout', {
        requestId: getRequestId(res),
        err: err instanceof Error ? err.message : String(err),
      });
    }
    res.clearCookie(SESSION_COOKIE_NAME, sessionCookieClearOptions);
    res.redirect(next);
  });
});

app.get('/logout', (_req, res) => {
  res.set('Allow', 'POST');
  return res.status(405).json({ error: 'Use POST /logout' });
});

app.get('/api/version', (_req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.json({ version: APP_VERSION });
});

app.use('/api', (_req, res) => {
  res.status(404).json({ error: 'Not found' });
});

app.get('/healthz', (_req, res) => {
  res.json({ status: 'ok', app: APP_NAME });
});

app.get('/readyz', (_req, res) => {
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

app.get('/favicon.ico', publicPageLimiter, (_req, res) => {
  res.sendFile(path.join(PROJECT_ROOT, 'favicon.ico'));
});

app.get('/login', publicPageLimiter, (_req, res) => {
  res.sendFile(clientIndexPath);
});
app.get('/legal', publicPageLimiter, (_req, res) => {
  res.sendFile(clientIndexPath);
});
app.get('/admin', publicPageLimiter, requireAdminPage, (_req, res) => {
  res.sendFile(clientIndexPath);
});
app.get('/profile', publicPageLimiter, requireAuthPage, (_req, res) => {
  res.sendFile(clientIndexPath);
});
app.get('/', publicPageLimiter, requireAuthPage, (_req, res) => {
  res.sendFile(clientIndexPath);
});

app.use((err: unknown, _req: Request, res: Response, _next: express.NextFunction) => {
  const error = err as Partial<Error> & {
    status?: number;
    statusCode?: number;
    code?: string;
  };
  const message = error.message || '';
  const lowerMessage = message.toLowerCase();
  const isNamedCsrfError =
    error.name === 'CsrfError' || (error.constructor && error.constructor.name === 'CsrfError');
  const isForbiddenError =
    error.name === 'ForbiddenError' ||
    (error.constructor && error.constructor.name === 'ForbiddenError');
  const isCsrfError =
    isNamedCsrfError ||
    error.code === 'EBADCSRFTOKEN' ||
    (isForbiddenError && lowerMessage.includes('csrf'));
  if (isCsrfError) {
    res.setHeader('X-CSRF-Error', '1');
    res.status(403).json({ error: 'Invalid CSRF token', code: 'CSRF_INVALID' });
    return;
  }

  const status =
    typeof error.status === 'number'
      ? error.status
      : typeof error.statusCode === 'number'
        ? error.statusCode
        : error.name === 'ForbiddenError'
          ? 403
          : 500;
  const isClientError = status >= 400 && status < 500;
  log(isClientError ? 'warn' : 'error', 'Unhandled request error', {
    requestId: getRequestId(res),
    status,
    err: error.stack ?? message,
  });
  const safeMessage =
    isClientError && typeof error.message === 'string' && error.message.trim().length > 0
      ? error.message.trim()
      : status >= 500
        ? 'Internal server error'
        : 'Request error';
  res.status(status).json({ error: safeMessage });
});

const server = app.listen(PORT, HOST, () => {
  log('info', `${APP_NAME} server listening`, { host: HOST, port: PORT, nodeEnv: NODE_ENV });
});

let shutdownStarted = false;
function shutdown(): void {
  if (shutdownStarted) return;
  shutdownStarted = true;

  function closeAndExit(exitCode: number): void {
    try {
      db.close();
    } catch (err) {
      log('error', 'Failed to close DB during shutdown', {
        err: err instanceof Error ? err.message : String(err),
      });
      exitCode = 1;
    }
    process.exit(exitCode);
  }

  const hardTimeout = setTimeout(() => {
    log('warn', 'Shutdown timeout reached; forcing exit', { timeoutMs: SHUTDOWN_TIMEOUT_MS });
    closeAndExit(1);
  }, SHUTDOWN_TIMEOUT_MS);

  server.close((err) => {
    clearTimeout(hardTimeout);
    if (err) {
      log('error', 'HTTP server close failed', {
        err: err instanceof Error ? err.message : String(err),
      });
      closeAndExit(1);
      return;
    }
    closeAndExit(0);
  });
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

export default app;

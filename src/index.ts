import argon2 from 'argon2';
import Database from 'better-sqlite3';
import cookieParser from 'cookie-parser';
import { csrfSync } from 'csrf-sync';
import express from 'express';
import { rateLimit } from 'express-rate-limit';
import session from 'express-session';
import fs from 'fs';
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

const AUTH_PUBLIC_BASE_URL =
  process.env.AUTH_PUBLIC_BASE_URL ?? 'https://auth.shark5060.net';
function deriveCookieDomain(): string | undefined {
  const explicitRaw = process.env.AUTH_COOKIE_DOMAIN?.trim();
  if (explicitRaw && explicitRaw.length > 0) {
    const explicit = explicitRaw;
    try {
      const authHost = new URL(AUTH_PUBLIC_BASE_URL).hostname.toLowerCase();
      const normalized = explicit.replace(/^\./, '').toLowerCase();
      if (normalized === authHost) {
        const parts = authHost.split('.');
        if (parts.length >= 2) {
          return `.${parts.slice(-2).join('.')}`;
        }
      }
    } catch {
      // ignore parse errors and keep explicit domain
    }
    return explicit;
  }

  try {
    const authHost = new URL(AUTH_PUBLIC_BASE_URL).hostname.toLowerCase();
    const parts = authHost.split('.');
    if (parts.length >= 2) {
      return `.${parts.slice(-2).join('.')}`;
    }
  } catch {
    // ignore and use fallback
  }

  return '.shark5060.net';
}
const COOKIE_DOMAIN = deriveCookieDomain();
const COOKIE_NAME = process.env.AUTH_COOKIE_NAME ?? 'shark.auth.sid';
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

function preferredAppUrl(keyword: string, fallback: string): string {
  const match = ALLOWED_APP_ORIGINS.find((origin) =>
    origin.toLowerCase().includes(keyword),
  );
  return match ?? fallback;
}

const PARAMETRIC_URL = preferredAppUrl(
  'parametric',
  'https://parametric.shark5060.net',
);
const CORPUS_URL = preferredAppUrl('corpus', 'https://corpus.shark5060.net');
const APP_URL_BY_ID: Record<string, string> = {
  parametric: PARAMETRIC_URL,
  corpus: CORPUS_URL,
};
const APP_META_BY_ID: Record<string, { label: string; subtitle: string }> = {
  parametric: {
    label: 'Parametric',
    subtitle: 'Build planning and management',
  },
  corpus: {
    label: 'Corpus',
    subtitle: 'Collection tracking',
  },
};
const SHARED_THEME_STORAGE_KEY = 'dal.theme.mode';
const SHARED_THEME_COOKIE = 'dal.theme.mode';
const SHARED_THEME_COOKIE_DOMAIN = '.shark5060.net';
const SHARED_THEME_MAX_AGE_SECONDS = 60 * 60 * 24 * 365;

function escapeHtml(input: string): string {
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function resolveThemeModeFromRequest(req: express.Request): 'light' | 'dark' {
  const cookieTheme =
    typeof req.cookies?.[SHARED_THEME_COOKIE] === 'string'
      ? req.cookies[SHARED_THEME_COOKIE]
      : '';
  return cookieTheme === 'light' ? 'light' : 'dark';
}

function renderSharedThemeScript(defaultMode: 'light' | 'dark'): string {
  return `<script>
(() => {
  const THEME_KEY = ${JSON.stringify(SHARED_THEME_STORAGE_KEY)};
  const THEME_COOKIE = ${JSON.stringify(SHARED_THEME_COOKIE)};
  const THEME_COOKIE_DOMAIN = ${JSON.stringify(SHARED_THEME_COOKIE_DOMAIN)};
  const ONE_YEAR_SECONDS = ${SHARED_THEME_MAX_AGE_SECONDS};
  const DEFAULT_MODE = ${JSON.stringify(defaultMode)};

  const readCookie = (name) => {
    const encoded = name + '=';
    const parts = document.cookie.split(';');
    for (const part of parts) {
      const trimmed = part.trim();
      if (trimmed.startsWith(encoded)) {
        return decodeURIComponent(trimmed.slice(encoded.length));
      }
    }
    return '';
  };

  const normalize = (value) => (value === 'light' ? 'light' : 'dark');
  const secure = window.location.protocol === 'https:' ? '; Secure' : '';

  const writeCookie = (mode) => {
    const base = THEME_COOKIE + '=' + encodeURIComponent(mode) + '; Max-Age=' + ONE_YEAR_SECONDS + '; Path=/; SameSite=Lax' + secure;
    document.cookie = base;
    document.cookie = base + '; Domain=' + THEME_COOKIE_DOMAIN;
  };

  const syncButton = (mode) => {
    const toggleBtn = document.getElementById('theme-toggle-btn');
    const toggleIcon = document.getElementById('theme-toggle-icon');
    if (!toggleBtn || !toggleIcon) return;
    const next = mode === 'dark' ? 'light' : 'dark';
    toggleBtn.setAttribute('aria-label', 'Switch to ' + next + ' mode');
    toggleBtn.setAttribute('title', 'Switch to ' + next + ' mode');
    toggleIcon.textContent = mode === 'dark' ? '☀' : '☾';
  };

  const applyTheme = (mode) => {
    const normalized = normalize(mode);
    document.documentElement.classList.remove('theme-light', 'theme-dark');
    document.documentElement.classList.add('theme-' + normalized);
    window.localStorage.setItem(THEME_KEY, normalized);
    writeCookie(normalized);
    syncButton(normalized);
  };

  const stored = window.localStorage.getItem(THEME_KEY);
  const cookieTheme = readCookie(THEME_COOKIE);
  applyTheme(normalize(stored || cookieTheme || DEFAULT_MODE));

  const toggleBtn = document.getElementById('theme-toggle-btn');
  if (toggleBtn) {
    toggleBtn.addEventListener('click', () => {
      const current = document.documentElement.classList.contains('theme-light') ? 'light' : 'dark';
      applyTheme(current === 'dark' ? 'light' : 'dark');
    });
  }
})();
</script>`;
}

const APP_ROOT = process.cwd();
const BACKGROUND_ART = (() => {
  try {
    return fs.readFileSync(path.join(APP_ROOT, 'background.txt'), 'utf-8');
  } catch {
    return '';
  }
})();
const BACKGROUND_ART_HTML = escapeHtml(BACKGROUND_ART);

createSchema();
console.log(`[Auth] Central DB ready (${CENTRAL_DB_PATH})`);

const app = express();
if (TRUST_PROXY) app.set('trust proxy', 1);
app.use(cookieParser());
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));

const STATIC_ROOT = APP_ROOT;
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

app.get('/', (req, res) => {
  if (typeof req.session.user_id !== 'number' || req.session.user_id <= 0) {
    res.redirect('/login');
    return;
  }

  const userId = req.session.user_id;
  const username =
    typeof req.session.username === 'string' ? req.session.username : 'User';
  const appAccess = getGamesForUser(userId);
  const isAdmin = Boolean(req.session.is_admin);
  const themeMode = resolveThemeModeFromRequest(req);

  const cards = appAccess
    .map((appId) => {
      const appUrl = APP_URL_BY_ID[appId];
      if (!appUrl) return null;
      const meta = APP_META_BY_ID[appId] ?? {
        label: appId,
        subtitle: 'Open app',
      };
      return `<a class="app-card" href="${escapeHtml(appUrl)}">
        <h2>${escapeHtml(meta.label)}</h2>
        <p>${escapeHtml(meta.subtitle)}</p>
      </a>`;
    })
    .filter((item): item is string => typeof item === 'string');

  const selectorHtml = `<!doctype html>
<html class="theme-${themeMode}">
  <head>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1"/>
    <title>Dark Avian Labs Apps</title>
    <link rel="icon" href="/favicon.ico" />
    ${renderSharedThemeScript(themeMode)}
    <style>
      :root {
        --color-foreground: #f8fafc;
        --color-muted: #c7c7cf;
        --color-accent: rgb(99, 99, 255);
        --color-glass: rgba(255, 255, 255, 0.024);
        --color-glass-border: rgba(255, 255, 255, 0.08);
        --color-bg-start: #000000;
        --color-bg-end: #0f172a;
        --color-bg-glow: rgba(100, 116, 139, 0.2);
      }
      body {
        margin: 0;
        min-height: 100dvh;
        color: var(--color-foreground);
        font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
        background:
          radial-gradient(circle at 10% 10%, var(--color-bg-glow), transparent 40%),
          radial-gradient(circle at 85% 15%, var(--color-bg-glow), transparent 45%),
          linear-gradient(to bottom, var(--color-bg-start) 0%, var(--color-bg-end) 100%);
        overflow-x: hidden;
      }
      .bg-art {
        white-space: pre;
        color: color-mix(in srgb, var(--color-foreground) 5%, transparent);
        z-index: 0;
        pointer-events: none;
        user-select: none;
        font-family: 'Courier New', Courier, monospace;
        font-size: 10px;
        line-height: 1.2;
        position: fixed;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
      }
      .wrap {
        position: relative;
        z-index: 10;
        max-width: 980px;
        margin: 0 auto;
        padding: 24px;
      }
      .top-brand {
        display: inline-flex;
        align-items: center;
        gap: 10px;
        margin-bottom: 18px;
      }
      .top-brand img {
        width: 30px;
        height: 30px;
        object-fit: contain;
      }
      .top-brand span {
        font-weight: 700;
        letter-spacing: 0.01em;
      }
      .theme-toggle-fab {
        position: fixed;
        top: 20px;
        right: 20px;
        z-index: 15;
        width: 40px;
        height: 40px;
        border-radius: 999px;
        border: 1px solid var(--color-glass-border);
        background: var(--color-glass);
        color: var(--color-muted);
        cursor: pointer;
      }
      html.theme-light {
        --color-foreground: #0f172a;
        --color-muted: #475569;
        --color-glass: rgba(255, 255, 255, 0.68);
        --color-glass-border: rgba(15, 23, 42, 0.2);
        --color-bg-start: #dbe4f1;
        --color-bg-end: #f8fafc;
        --color-bg-glow: rgba(148, 163, 184, 0.28);
      }
      .glass {
        border-radius: 18px;
        background: var(--color-glass);
        border: 1px solid var(--color-glass-border);
        box-shadow:
          0 8px 32px rgba(0, 0, 0, 0.25),
          inset 0 1px 0 rgba(255, 255, 255, 0.14),
          inset 0 -1px 0 rgba(0, 0, 0, 0.12);
        backdrop-filter: blur(12px) saturate(1.2);
      }
      .panel {
        padding: 20px;
      }
      .panel h1 {
        margin: 0 0 6px;
        font-size: 1.35rem;
      }
      .subtitle {
        margin: 0;
        color: var(--color-muted);
      }
      .meta {
        margin-top: 8px;
        color: var(--color-muted);
        font-size: 0.92rem;
      }
      .apps {
        display: flex;
        flex-wrap: wrap;
        gap: 14px;
        margin-top: 18px;
      }
      .app-card {
        min-width: 220px;
        flex: 1 1 240px;
        text-decoration: none;
        color: var(--color-foreground);
        border: 1px solid color-mix(in srgb, var(--color-accent) 45%, transparent);
        border-radius: 12px;
        padding: 16px;
        background: color-mix(in srgb, var(--color-accent) 10%, transparent);
        transition: background 0.2s, border-color 0.2s;
      }
      .app-card:hover {
        background: color-mix(in srgb, var(--color-accent) 18%, transparent);
        border-color: var(--color-accent);
      }
      .app-card h2 {
        margin: 0 0 6px;
        font-size: 1.1rem;
      }
      .app-card p {
        margin: 0;
        color: var(--color-muted);
        font-size: 0.92rem;
      }
      .actions {
        display: flex;
        gap: 10px;
        margin-top: 18px;
      }
      .btn {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        border-radius: 10px;
        border: 1px solid rgba(255, 255, 255, 0.16);
        padding: 8px 12px;
        text-decoration: none;
        color: var(--color-muted);
        background: rgba(255, 255, 255, 0.04);
        transition: all 0.2s;
      }
      .btn:hover {
        color: var(--color-foreground);
        border-color: rgba(255, 255, 255, 0.3);
      }
      .empty {
        margin-top: 18px;
        color: var(--color-muted);
      }
    </style>
  </head>
  <body>
    ${BACKGROUND_ART_HTML ? `<div class="bg-art">${BACKGROUND_ART_HTML}</div>` : ''}
    <button id="theme-toggle-btn" class="theme-toggle-fab" type="button" aria-label="Toggle theme" title="Toggle theme"><span id="theme-toggle-icon" aria-hidden="true">☀</span></button>
    <main class="wrap">
      <div class="top-brand">
        <img src="/branding/feathers.png" alt="Dark Avian Labs feather mark" />
        <span>Dark Avian Labs</span>
      </div>
      <section class="glass panel">
        <h1>Welcome, ${escapeHtml(username)}</h1>
        <p class="subtitle">Choose an app to continue.</p>
        <p class="meta">Only apps you have access to are shown.</p>
        ${
          cards.length > 0
            ? `<div class="apps">${cards.join('')}</div>`
            : '<p class="empty">No apps assigned to your account yet. Contact an administrator.</p>'
        }
        <div class="actions">
          ${isAdmin ? '<a class="btn" href="/admin">Open Admin</a>' : ''}
          <a class="btn" href="/logout">Logout</a>
        </div>
      </section>
    </main>
  </body>
</html>`;

  res.type('html').send(selectorHtml);
});

app.get('/login', (req, res) => {
  const nextInput =
    typeof req.query.next === 'string' && req.query.next.length > 0
      ? req.query.next
      : '';
  const next = sanitizeNextUrl(nextInput, '/');
  const csrfToken = generateToken(req);
  const themeMode = resolveThemeModeFromRequest(req);
  const loginHtml = `<!doctype html>
<html class="theme-${themeMode}">
  <head>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1"/>
    <title>Dark Avian Labs Login</title>
    <link rel="icon" href="/favicon.ico" />
    ${renderSharedThemeScript(themeMode)}
    <style>
      :root {
        --color-foreground: #f8fafc;
        --color-muted: #c7c7cf;
        --color-accent: rgb(99, 99, 255);
        --color-accent-weak: color-mix(in srgb, var(--color-accent) 11%, transparent);
        --color-glass: rgba(255, 255, 255, 0.024);
        --color-glass-border: rgba(255, 255, 255, 0.08);
        --color-glass-border-hover: rgba(255, 255, 255, 0.2);
        --color-bg-start: #000000;
        --color-bg-end: #0f172a;
        --color-bg-glow: rgba(100, 116, 139, 0.2);
      }
      body {
        margin: 0;
        min-height: 100dvh;
        color: var(--color-foreground);
        font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
        background:
          radial-gradient(circle at 10% 10%, var(--color-bg-glow), transparent 40%),
          radial-gradient(circle at 85% 15%, var(--color-bg-glow), transparent 45%),
          linear-gradient(to bottom, var(--color-bg-start) 0%, var(--color-bg-end) 100%);
        overflow-x: hidden;
      }
      .center {
        position: relative;
        z-index: 10;
        min-height: 100dvh;
        box-sizing: border-box;
        display: grid;
        place-items: center;
        padding: 20px;
      }
      .bg-art {
        white-space: pre;
        color: color-mix(in srgb, var(--color-foreground) 5%, transparent);
        z-index: 0;
        pointer-events: none;
        user-select: none;
        font-family: 'Courier New', Courier, monospace;
        font-size: 10px;
        line-height: 1.2;
        position: fixed;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
      }
      .glass {
        position: relative;
        overflow: hidden;
        border-radius: 18px;
        background: var(--color-glass);
        border: 1px solid var(--color-glass-border);
        box-shadow:
          0 8px 32px rgba(0, 0, 0, 0.25),
          inset 0 1px 0 rgba(255, 255, 255, 0.14),
          inset 0 -1px 0 rgba(0, 0, 0, 0.12);
        backdrop-filter: blur(12px) saturate(1.2);
      }
      .auth-box {
        width: min(92vw, 420px);
        padding: 24px 20px;
      }
      .top-brand {
        position: fixed;
        top: 20px;
        left: 20px;
        z-index: 15;
        display: inline-flex;
        align-items: center;
        gap: 10px;
      }
      .top-brand img {
        width: 28px;
        height: 28px;
        object-fit: contain;
      }
      .top-brand span {
        font-weight: 700;
        letter-spacing: 0.01em;
      }
      .theme-toggle-fab {
        position: fixed;
        top: 20px;
        right: 20px;
        z-index: 15;
        width: 40px;
        height: 40px;
        border-radius: 999px;
        border: 1px solid var(--color-glass-border);
        background: var(--color-glass);
        color: var(--color-muted);
        cursor: pointer;
      }
      html.theme-light {
        --color-foreground: #0f172a;
        --color-muted: #475569;
        --color-glass: rgba(255, 255, 255, 0.68);
        --color-glass-border: rgba(15, 23, 42, 0.2);
        --color-glass-border-hover: rgba(15, 23, 42, 0.3);
        --color-bg-start: #dbe4f1;
        --color-bg-end: #f8fafc;
        --color-bg-glow: rgba(148, 163, 184, 0.28);
      }
      html.theme-light input {
        background: rgba(255, 255, 255, 0.9);
        color: #0f172a;
        border-color: rgba(15, 23, 42, 0.2);
      }
      .hero-brand {
        display: block;
        width: 128px;
        height: 128px;
        object-fit: contain;
        margin: 0 auto 8px;
      }
      h2 {
        margin: 0 0 6px;
        text-align: center;
        font-size: 1.35rem;
      }
      .subtitle {
        text-align: center;
        margin: 0 0 14px;
        color: var(--color-muted);
        font-size: 0.9rem;
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
        border-color: var(--color-accent);
        background: var(--color-accent-weak);
        color: var(--color-accent);
        font-weight: 700;
      }
      button:hover {
        border-color: var(--color-glass-border-hover);
      }
    </style>
  </head>
  <body>
    ${BACKGROUND_ART_HTML ? `<div class="bg-art">${BACKGROUND_ART_HTML}</div>` : ''}
    <button id="theme-toggle-btn" class="theme-toggle-fab" type="button" aria-label="Toggle theme" title="Toggle theme"><span id="theme-toggle-icon" aria-hidden="true">☀</span></button>
    <div class="top-brand">
      <img src="/branding/feathers.png" alt="Dark Avian Labs feather mark" />
      <span>Dark Avian Labs Login</span>
    </div>
    <div class="center">
      <main class="auth-box glass">
        <img class="hero-brand" src="/branding/feathers.png" alt="Dark Avian Labs feather mark" />
        <h2>Sign in</h2>
        <p class="subtitle">Unified access for Parametric and Corpus.</p>
        <form method="post" action="/api/auth/login">
          <input type="text" name="username" placeholder="Username" required />
          <input type="password" name="password" placeholder="Password" required />
          <input type="hidden" name="_csrf" value="${csrfToken.replace(/"/g, '&quot;')}" />
          <input type="hidden" name="next" value="${next.replace(/"/g, '&quot;')}" />
          <button type="submit">Login</button>
        </form>
      </main>
    </div>
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

app.get('/admin', requireAdmin, (req, res) => {
  const csrfToken = generateToken(req);
  const themeMode = resolveThemeModeFromRequest(req);
  const currentUserId =
    typeof req.session.user_id === 'number' ? req.session.user_id : null;
  const adminHtml = `<!doctype html>
<html class="theme-${themeMode}">
  <head>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1"/>
    <title>Dark Avian Labs Admin</title>
    <meta name="csrf-token" content="${csrfToken.replace(/"/g, '&quot;')}" />
    ${renderSharedThemeScript(themeMode)}
    <style>
      :root { --fg:#f8fafc; --muted:#c7c7cf; --accent:#6363ff; --glass:rgba(255,255,255,.024); --border:rgba(255,255,255,.08); --bg1:#020617; --bg2:#0b1020; }
      body { margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center; padding:20px; overflow-x:hidden; color:var(--fg); font-family:system-ui,-apple-system,'Segoe UI',Roboto,Arial,sans-serif; background:linear-gradient(180deg,var(--bg1) 0%,var(--bg2) 100%); }
      .bg-art { white-space:pre; color:color-mix(in srgb,var(--fg) 5%,transparent); pointer-events:none; user-select:none; font-family:'Courier New',monospace; font-size:10px; line-height:1.2; position:fixed; top:50%; left:50%; transform:translate(-50%,-50%); }
      .wrap { position:relative; z-index:2; width:min(1200px,96vw); margin:0; }
      .glass { border-radius:18px; background:var(--glass); border:1px solid var(--border); box-shadow:0 8px 32px rgba(0,0,0,.25),inset 0 1px 0 rgba(255,255,255,.14),inset 0 -1px 0 rgba(0,0,0,.12); backdrop-filter:blur(12px) saturate(1.2); }
      .card { padding:16px; margin-bottom:14px; }
      .row { display:flex; gap:8px; flex-wrap:wrap; align-items:center; }
      .btn, input { font:inherit; border-radius:10px; border:1px solid rgba(255,255,255,.16); padding:8px 11px; color:var(--fg); background:rgba(255,255,255,.04); }
      .btn { cursor:pointer; text-decoration:none; display:inline-flex; align-items:center; }
      .btn:hover { border-color:rgba(255,255,255,.32); }
      .btn-accent { border-color:var(--accent); color:var(--accent); background:color-mix(in srgb,var(--accent) 12%,transparent); }
      .muted { color:var(--muted); }
      .msg { margin-top:8px; font-size:.9rem; }
      .ok { color:#7be495; } .err { color:#ff8b8b; }
      table { width:100%; border-collapse:collapse; }
      th, td { border-top:1px solid rgba(255,255,255,.08); padding:9px 7px; vertical-align:middle; font-size:.92rem; }
      .badge { display:inline-flex; padding:2px 8px; border-radius:999px; font-size:.75rem; border:1px solid rgba(255,255,255,.22); }
      .badge.admin { color:#f7d088; background:rgba(215,172,97,.14); border-color:rgba(215,172,97,.35); }
      .badge.user { color:#9fb0d0; background:rgba(100,116,139,.16); border-color:rgba(100,116,139,.35); }
      .modal { position:fixed; inset:0; background:rgba(0,0,0,.62); z-index:20; display:none; align-items:center; justify-content:center; padding:18px; }
      .modal.show { display:flex; }
      .modal-card { width:min(860px,96vw); max-height:85vh; overflow:auto; }
      .perm-table td, .perm-table th { font-size:.86rem; }
      .subperm { display:inline-flex; margin:2px 6px 2px 0; padding:2px 8px; border-radius:999px; font-size:.76rem; border:1px solid rgba(99,99,255,.3); color:#d2d6ff; background:rgba(99,99,255,.14); }
      .split { display:flex; gap:6px; flex-wrap:wrap; align-items:center; }
      .top-brand { position: fixed; top: 20px; left: 20px; z-index: 15; display: inline-flex; align-items: center; gap: 10px; }
      .top-brand img { width: 28px; height: 28px; object-fit: contain; }
      .top-brand span { font-weight: 700; letter-spacing: 0.01em; }
      .theme-toggle-fab { position: fixed; top: 20px; right: 20px; z-index: 15; width: 40px; height: 40px; border-radius: 999px; border: 1px solid var(--border); background: var(--glass); color: var(--muted); cursor: pointer; }
      html.theme-light { --fg:#0f172a; --muted:#475569; --glass:rgba(255,255,255,.78); --border:rgba(15,23,42,.2); --bg1:#dbe4f1; --bg2:#f8fafc; }
    </style>
  </head>
  <body>
    ${BACKGROUND_ART_HTML ? `<div class="bg-art">${BACKGROUND_ART_HTML}</div>` : ''}
    <button id="theme-toggle-btn" class="theme-toggle-fab" type="button" aria-label="Toggle theme" title="Toggle theme"><span id="theme-toggle-icon" aria-hidden="true">☀</span></button>
    <div class="top-brand">
      <img src="/branding/feathers.png" alt="Dark Avian Labs feather mark" />
      <span>Dark Avian Labs Admin</span>
    </div>
    <div class="wrap">
      <section class="glass card">
        <h1 style="margin:0 0 8px;">Central Dark Avian Labs Admin</h1>
        <p class="muted" style="margin:0 0 10px;">Manage users and app permissions.</p>
        <div class="row">
          <a class="btn" href="${PARAMETRIC_URL}">Back to Parametric</a>
          <a class="btn" href="${CORPUS_URL}">Back to Corpus</a>
          <form method="GET" action="/logout"><button class="btn" type="submit">Logout</button></form>
        </div>
      </section>

      <section class="glass card">
        <h2 style="margin:0 0 10px;">Create User</h2>
        <div class="row">
          <input id="new-username" placeholder="Username" />
          <input id="new-password" type="password" placeholder="Password" />
          <label class="split"><input id="new-admin" type="checkbox" /> Admin</label>
          <button id="create-user" class="btn btn-accent" type="button">Create</button>
        </div>
        <div id="msg" class="msg muted"></div>
      </section>

      <section class="glass card">
        <h2 style="margin:0 0 10px;">Users</h2>
        <table>
          <thead><tr><th>ID</th><th>User</th><th>Role</th><th>Actions</th></tr></thead>
          <tbody id="users-body"><tr><td colspan="4" class="muted">Loading...</td></tr></tbody>
        </table>
      </section>
    </div>

    <div id="cfg-modal" class="modal">
      <div class="glass card modal-card">
        <div class="split" style="justify-content:space-between; margin-bottom:8px;">
          <h3 id="cfg-title" style="margin:0;">User Config</h3>
          <button id="cfg-close" class="btn" type="button">Close</button>
        </div>
        <table class="perm-table">
          <thead><tr><th>App</th><th>Access</th><th>Permissions</th><th>Update</th></tr></thead>
          <tbody id="cfg-body"></tbody>
        </table>
      </div>
    </div>

    <script>
      const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content || '';
      const currentUserId = ${currentUserId === null ? 'null' : String(currentUserId)};
      const defaultApps = ['parametric', 'corpus'];
      const usersById = new Map();
      let activeUserId = null;

      function showMessage(text, isError = false) {
        const node = document.getElementById('msg');
        if (!node) return;
        node.textContent = text;
        node.className = 'msg ' + (isError ? 'err' : 'ok');
      }

      async function api(url, options = {}) {
        const headers = Object.assign({ 'Content-Type':'application/json', 'X-CSRF-Token': csrfToken }, options.headers || {});
        const response = await fetch(url, Object.assign({}, options, { headers }));
        let body = null; try { body = await response.json(); } catch {}
        return { response, body };
      }

      function permissionEntries(user) {
        if (!Array.isArray(user.permissions)) return [];
        return user.permissions
          .map((entry) => {
            if (entry && typeof entry === 'object') {
              const app_id = String(entry.app_id || '').trim();
              const permission = String(entry.permission || '').trim();
              if (app_id && permission) return { app_id, permission };
              return null;
            }
            if (typeof entry === 'string' && entry.includes(':')) {
              const idx = entry.indexOf(':');
              return { app_id: entry.slice(0, idx), permission: entry.slice(idx + 1) };
            }
            return null;
          })
          .filter(Boolean);
      }

      function appIds(user) {
        const fromAccess = Array.isArray(user.app_access) ? user.app_access : [];
        const fromPerms = permissionEntries(user).map((entry) => entry.app_id);
        const merged = [...new Set([...defaultApps, ...fromAccess, ...fromPerms])];
        return merged.filter(Boolean);
      }

      function roleBadge(user) {
        return user.is_admin
          ? '<span class="badge admin">admin</span>'
          : '<span class="badge user">user</span>';
      }

      function userRow(user) {
        return '<tr data-user-id="' + user.id + '">' +
          '<td>' + user.id + '</td>' +
          '<td>' + user.username + '</td>' +
          '<td>' + roleBadge(user) + '</td>' +
          '<td class="split">' +
            '<button class="btn" data-action="configure">Configure</button>' +
            '<button class="btn" data-action="toggle-admin">' + (user.is_admin ? 'Remove admin' : 'Make admin') + '</button>' +
            (currentUserId === user.id ? '' : '<button class="btn" data-action="delete">Delete</button>') +
          '</td>' +
        '</tr>';
      }

      function renderUsers(users) {
        const body = document.getElementById('users-body');
        if (!body) return;
        usersById.clear();
        for (const user of users) usersById.set(Number(user.id), user);
        body.innerHTML = users.map(userRow).join('');
      }

      async function loadUsers() {
        const body = document.getElementById('users-body');
        if (body) body.innerHTML = '<tr><td colspan="4" class="muted">Loading...</td></tr>';
        const { response, body: data } = await api('/api/admin/users', { method: 'GET' });
        if (!response.ok || !data || !Array.isArray(data.users)) {
          if (body) body.innerHTML = '<tr><td colspan="4" class="err">Failed to load users.</td></tr>';
          return;
        }
        renderUsers(data.users);
      }

      async function createUser() {
        const username = (document.getElementById('new-username')?.value || '').trim();
        const password = document.getElementById('new-password')?.value || '';
        const is_admin = Boolean(document.getElementById('new-admin')?.checked);
        if (!username || !password) return showMessage('Username and password are required.', true);
        const { response, body } = await api('/api/admin/users', { method: 'POST', body: JSON.stringify({ username, password, is_admin }) });
        if (!response.ok) return showMessage(body?.error || 'Failed to create user.', true);
        showMessage('User created.');
        document.getElementById('new-username').value = '';
        document.getElementById('new-password').value = '';
        document.getElementById('new-admin').checked = false;
        await loadUsers();
      }

      async function updateAdmin(userId, isAdmin) {
        const { response, body } = await api('/api/admin/users/' + userId, { method: 'PATCH', body: JSON.stringify({ is_admin: !isAdmin }) });
        if (!response.ok) return showMessage(body?.error || 'Role update failed.', true);
        showMessage('Role updated.');
        await loadUsers();
      }

      async function deleteUser(userId) {
        if (!confirm('Delete this user?')) return;
        const { response, body } = await api('/api/admin/users/' + userId, { method: 'DELETE' });
        if (!response.ok) return showMessage(body?.error || 'Delete failed.', true);
        showMessage('User deleted.');
        await loadUsers();
      }

      function permsForApp(user, appId) {
        return permissionEntries(user).filter((entry) => entry.app_id === appId).map((entry) => entry.permission);
      }

      function cfgRow(user, appId) {
        const hasAccess = Array.isArray(user.app_access) && user.app_access.includes(appId);
        const perms = permsForApp(user, appId);
        const badges = perms.length ? perms.map((perm) => '<span class="subperm">' + perm + '</span>').join('') : '<span class="muted">(none)</span>';
        return '<tr>' +
          '<td>' + appId + '</td>' +
          '<td>' + (appId === '*' ? '<span class="muted">global</span>' : '<button class="btn" data-action="cfg-toggle-access" data-app-id="' + appId + '" data-enabled="' + (hasAccess ? '1' : '0') + '">' + (hasAccess ? 'Revoke' : 'Grant') + '</button>') + '</td>' +
          '<td>' + badges + '</td>' +
          '<td class="split">' +
            '<input data-input="cfg-perms" data-app-id="' + appId + '" placeholder="perm1,perm2 or *" value="' + perms.join(',') + '" />' +
            '<button class="btn btn-accent" data-action="cfg-save-perms" data-app-id="' + appId + '">Save</button>' +
          '</td>' +
        '</tr>';
      }

      function openConfig(userId) {
        const user = usersById.get(userId);
        if (!user) return;
        activeUserId = userId;
        const ids = appIds(user);
        if (!ids.includes('*')) ids.unshift('*');
        const title = document.getElementById('cfg-title');
        const body = document.getElementById('cfg-body');
        const modal = document.getElementById('cfg-modal');
        if (title) title.textContent = 'Config for ' + user.username;
        if (body) body.innerHTML = ids.map((appId) => cfgRow(user, appId)).join('');
        modal?.classList.add('show');
      }

      function closeConfig() {
        activeUserId = null;
        document.getElementById('cfg-modal')?.classList.remove('show');
      }

      async function onUsersClick(event) {
        const target = event.target;
        if (!(target instanceof HTMLElement)) return;
        const action = target.getAttribute('data-action');
        const row = target.closest('tr[data-user-id]');
        if (!action || !row) return;
        const userId = Number(row.getAttribute('data-user-id'));
        const user = usersById.get(userId);
        if (!user) return;
        if (action === 'configure') return openConfig(userId);
        if (action === 'toggle-admin') return updateAdmin(userId, Boolean(user.is_admin));
        if (action === 'delete') return deleteUser(userId);
      }

      async function onCfgClick(event) {
        const target = event.target;
        if (!(target instanceof HTMLElement) || !activeUserId) return;
        const action = target.getAttribute('data-action');
        if (action === 'cfg-toggle-access') {
          const appId = String(target.getAttribute('data-app-id') || '').trim();
          const enabled = target.getAttribute('data-enabled') === '1';
          if (!appId) return;
          const { response, body } = await api('/api/admin/users/' + activeUserId + '/apps/' + encodeURIComponent(appId), { method:'PUT', body: JSON.stringify({ enabled: !enabled }) });
          if (!response.ok) return showMessage(body?.error || 'App access update failed.', true);
          showMessage('App access updated.');
          await loadUsers();
          openConfig(activeUserId);
        }
        if (action === 'cfg-save-perms') {
          const appId = String(target.getAttribute('data-app-id') || '').trim();
          if (!appId) return;
          const input = document.querySelector('[data-input="cfg-perms"][data-app-id="' + appId + '"]');
          const raw = input instanceof HTMLInputElement ? input.value.trim() : '';
          const permissions = raw ? raw.split(',').map((p) => p.trim()).filter(Boolean) : [];
          const { response, body } = await api('/api/admin/users/' + activeUserId + '/permissions', { method:'PUT', body: JSON.stringify({ app_id: appId, permissions }) });
          if (!response.ok) return showMessage(body?.error || 'Permission update failed.', true);
          showMessage('Permissions updated.');
          await loadUsers();
          openConfig(activeUserId);
        }
      }

      document.getElementById('create-user')?.addEventListener('click', createUser);
      document.getElementById('users-body')?.addEventListener('click', onUsersClick);
      document.getElementById('cfg-body')?.addEventListener('click', onCfgClick);
      document.getElementById('cfg-close')?.addEventListener('click', closeConfig);
      document.getElementById('cfg-modal')?.addEventListener('click', (event) => {
        if (event.target === event.currentTarget) closeConfig();
      });
      loadUsers();
    </script>
  </body>
</html>`;
  res.type('html').send(adminHtml);
});

app.use('/api', (_req, res) => {
  res.status(404).json({ error: 'Not found' });
});

app.listen(PORT, HOST, () => {
  console.log(`[Auth] Running at http://${HOST}:${PORT}`);
});

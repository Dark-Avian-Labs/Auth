import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const parentName = path.basename(path.resolve(__dirname, '..'));
export const PROJECT_ROOT = path.resolve(
  __dirname,
  parentName === 'dist' ? '../..' : '..',
);

export const DATA_DIR = path.join(PROJECT_ROOT, 'data');
export const CENTRAL_DB_PATH =
  process.env.CENTRAL_DB_PATH || path.join(DATA_DIR, 'central.db');

const _port = parseInt(process.env.PORT || '3000', 10);
export const PORT = Number.isFinite(_port) && _port > 0 ? _port : 3000;
export const HOST = process.env.HOST || '127.0.0.1';
export const APP_NAME = process.env.APP_NAME?.trim() || 'Dark Avian LABS';
export const APP_ID = process.env.APP_ID?.trim() || 'auth';
export const NODE_ENV = process.env.NODE_ENV || 'development';

const DEFAULT_SESSION_SECRET = 'auth-dev-secret-change-me';
export const SESSION_SECRET =
  process.env.SESSION_SECRET || DEFAULT_SESSION_SECRET;
if (NODE_ENV === 'production' && SESSION_SECRET === DEFAULT_SESSION_SECRET) {
  throw new Error('SESSION_SECRET must be set in production.');
}

export const TRUST_PROXY =
  process.env.TRUST_PROXY === '1' || process.env.TRUST_PROXY === 'true';
export const SECURE_COOKIES =
  process.env.SECURE_COOKIES === '1' || process.env.SECURE_COOKIES === 'true';
export const BASE_PROTOCOL =
  process.env.BASE_PROTOCOL ||
  (process.env.NODE_ENV === 'production' ? 'https' : 'http');

export const BASE_DOMAIN = process.env.BASE_DOMAIN?.trim().toLowerCase() || '';
if (!BASE_DOMAIN) {
  throw new Error('BASE_DOMAIN must be set.');
}
const DOMAIN_LABEL_REGEX = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/;
const domainLabels = BASE_DOMAIN.split('.');
const hasValidBaseDomain =
  domainLabels.length >= 2 &&
  domainLabels.every((label) => DOMAIN_LABEL_REGEX.test(label)) &&
  domainLabels[domainLabels.length - 1].length >= 2;
if (!hasValidBaseDomain) {
  throw new Error(
    'BASE_DOMAIN must be a valid dot-separated domain with labels that start/end with alphanumeric characters and may contain internal hyphens.',
  );
}

export const AUTH_SUBDOMAIN =
  process.env.AUTH_SUBDOMAIN?.trim().toLowerCase() || 'auth';
if (!DOMAIN_LABEL_REGEX.test(AUTH_SUBDOMAIN)) {
  throw new Error(
    'AUTH_SUBDOMAIN must start/end with an alphanumeric character and may contain internal hyphens.',
  );
}

function buildSubdomainUrl(subdomain: string): string {
  return `${BASE_PROTOCOL}://${subdomain}.${BASE_DOMAIN}`;
}

export const AUTH_PUBLIC_BASE_URL = buildSubdomainUrl(AUTH_SUBDOMAIN);

export const APP_LIST = (process.env.APP_LIST || 'parametric,corpus')
  .split(',')
  .map((value) => value.trim().toLowerCase())
  .filter((value, idx, arr) => value.length > 0 && arr.indexOf(value) === idx);
if (APP_LIST.length === 0) {
  throw new Error('APP_LIST must include at least one app id.');
}
for (const appId of APP_LIST) {
  if (!/^[a-z0-9-]+$/.test(appId)) {
    throw new Error(`APP_LIST contains invalid app id "${appId}".`);
  }
}

export const APP_URL_BY_ID = Object.fromEntries(
  APP_LIST.map((appId) => [appId, buildSubdomainUrl(appId)]),
) as Record<string, string>;

export const COOKIE_DOMAIN =
  process.env.COOKIE_DOMAIN?.trim() || `.${BASE_DOMAIN}`;

export const AUTH_COOKIE_DOMAIN =
  process.env.AUTH_COOKIE_DOMAIN?.trim() || COOKIE_DOMAIN;
export const AUTH_COOKIE_NAME =
  process.env.AUTH_COOKIE_NAME?.trim() || 'darkavianlabs.auth.sid';
export const SESSION_COOKIE_NAME =
  process.env.SESSION_COOKIE_NAME?.trim() || AUTH_COOKIE_NAME;

export const ALLOWED_APP_ORIGINS = Object.values(APP_URL_BY_ID).map(
  (value) => new URL(value).origin,
);
export const ALLOWED_NEXT_ORIGINS = [
  new URL(AUTH_PUBLIC_BASE_URL).origin,
  ...ALLOWED_APP_ORIGINS,
];

export const SHARED_THEME_COOKIE = 'dal.theme.mode';
export const SHARED_THEME_COOKIE_DOMAIN =
  process.env.SHARED_THEME_COOKIE_DOMAIN?.trim() || AUTH_COOKIE_DOMAIN || '';

export function ensureDataDirs(): void {
  for (const dir of [DATA_DIR]) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

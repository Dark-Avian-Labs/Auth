import argon2 from 'argon2';
import type express from 'express';

import {
  ALLOWED_NEXT_ORIGINS,
  AUTH_COOKIE_DOMAIN,
  AUTH_COOKIE_NAME,
  AUTH_PUBLIC_BASE_URL,
  CORPUS_APP_URL,
  PARAMETRIC_APP_URL,
} from '../config.js';
import {
  db,
  getGamesForUser,
  getUserById,
  type UserRow,
} from '../db/authDb.js';

export const APP_META_BY_ID: Record<
  string,
  { label: string; subtitle: string }
> = {
  parametric: {
    label: 'Parametric',
    subtitle: 'Build planning and management',
  },
  corpus: {
    label: 'Corpus',
    subtitle: 'Collection tracking',
  },
};

export const APP_URL_BY_ID: Record<string, string> = {
  parametric: PARAMETRIC_APP_URL,
  corpus: CORPUS_APP_URL,
};

export function requestIp(req: express.Request): string {
  return req.ip ?? 'unknown';
}

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

export function sanitizeNextUrl(
  input: string | undefined,
  fallbackPath: string,
): string {
  const fallback = new URL(fallbackPath, AUTH_PUBLIC_BASE_URL).toString();
  if (!input || input.length < 1) {
    return fallback;
  }
  const parsed = parseUrlSafe(input);
  if (!parsed) {
    return fallback;
  }
  if (!isAllowedOrigin(parsed, ALLOWED_NEXT_ORIGINS)) {
    return fallback;
  }
  return parsed.toString();
}

export async function verifyPassword(
  password: string,
  hash: string,
): Promise<boolean> {
  try {
    return await argon2.verify(hash, password);
  } catch {
    return false;
  }
}

export async function hashPassword(password: string): Promise<string> {
  return await argon2.hash(password, {
    type: argon2.argon2id,
    memoryCost: 19 * 1024,
    timeCost: 2,
    parallelism: 1,
  });
}

export function revokeSessionsForUser(userId: number): number {
  const sessions = db.prepare('SELECT sid, sess FROM sessions').all() as Array<{
    sid: string;
    sess: string;
  }>;
  const deleteSession = db.prepare('DELETE FROM sessions WHERE sid = ?');
  let revoked = 0;
  for (const row of sessions) {
    try {
      const payload = JSON.parse(row.sess) as { user_id?: unknown };
      if (payload.user_id === userId) {
        revoked += deleteSession.run(row.sid).changes;
      }
    } catch {
      // ignore malformed session rows
    }
  }
  return revoked;
}

export function clearAuthCookies(res: express.Response): void {
  const options: express.CookieOptions = {
    httpOnly: true,
    secure: true,
    sameSite: 'none',
    domain: AUTH_COOKIE_DOMAIN,
  };
  res.clearCookie(AUTH_COOKIE_NAME, options);
}

export function requireAuth(
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

export function requireAdmin(
  req: express.Request,
  res: express.Response,
  next: express.NextFunction,
): void {
  if (typeof req.session.user_id !== 'number' || req.session.user_id <= 0) {
    res.status(401).json({ error: 'Authentication required' });
    return;
  }
  const user = getUserById(req.session.user_id);
  if (!user || !user.is_admin) {
    req.session.is_admin = false;
    res.status(403).json({ error: 'Admin access required' });
    return;
  }
  req.session.is_admin = true;
  next();
}

export function readSessionUser(req: express.Request): UserRow | null {
  if (typeof req.session.user_id !== 'number' || req.session.user_id <= 0) {
    return null;
  }
  return getUserById(req.session.user_id) ?? null;
}

export function buildAppCards(userId: number): Array<{
  id: string;
  label: string;
  subtitle: string;
  url: string;
}> {
  const appAccess = getGamesForUser(userId);
  return appAccess
    .map((appId) => {
      const url = APP_URL_BY_ID[appId];
      if (!url) {
        return null;
      }
      const meta = APP_META_BY_ID[appId] ?? {
        label: appId,
        subtitle: 'Open app',
      };
      return { id: appId, label: meta.label, subtitle: meta.subtitle, url };
    })
    .filter((entry): entry is NonNullable<typeof entry> => entry !== null);
}

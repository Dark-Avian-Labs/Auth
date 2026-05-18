import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../db/authDb.js', () => ({
  db: {
    prepare: () => ({
      run: () => ({ changes: 0 }),
    }),
    transaction: (fn: (userId: number) => number) => fn,
  },
  getGamesForUser: vi.fn(() => []),
  getUserById: vi.fn(() => null),
}));

import type { Request, Response } from 'express';

import { AUTH_PUBLIC_BASE_URL } from '../config.js';
import { getUserById, type UserRow } from '../db/authDb.js';
import { requireAdminPage, requireAuthPage, sanitizeNextUrl } from './service.js';

function stubUser(partial: Pick<UserRow, 'id' | 'username' | 'is_admin'>): UserRow {
  return {
    password_hash: '',
    display_name: '',
    email: '',
    created_at: '',
    ...partial,
  };
}

describe('sanitizeNextUrl', () => {
  let fallback: string;

  beforeAll(() => {
    fallback = new URL('/login', AUTH_PUBLIC_BASE_URL).toString();
  });

  const rejectsOpenRedirectAndGarbage: ReadonlyArray<readonly [string, string | null | undefined]> = [
    ['missing next', undefined],
    ['empty string', ''],
    ['null at runtime', null],
    ['whitespace only', '   '],
    ['invalid absolute URL', 'not-a-url'],
    ['external origin', 'https://evil.example.com/steal'],
    ['protocol-relative URL', '//evil.com'],
    ['javascript URL', 'javascript:alert(1)'],
    ['data URL', 'data:text/html,<script>alert(1)</script>'],
    ['path traversal segment', '../admin'],
  ];

  it.each(rejectsOpenRedirectAndGarbage)('falls back for %s', (_label, input) => {
    expect(sanitizeNextUrl(input as string | undefined, '/login')).toBe(fallback);
  });

  it('falls back for Unicode-only invisible trim bait', () => {
    expect(sanitizeNextUrl('\u200b\uFEFF', '/login')).toBe(fallback);
  });

  it('preserves a full URL on an allowlisted origin', () => {
    const allowed = new URL('/dashboard', AUTH_PUBLIC_BASE_URL).toString();
    expect(sanitizeNextUrl(allowed, '/login')).toBe(allowed);
  });

  it('resolves a root-relative path against AUTH_PUBLIC_BASE_URL', () => {
    const expected = new URL('/dashboard', AUTH_PUBLIC_BASE_URL).toString();
    expect(sanitizeNextUrl('/dashboard', '/login')).toBe(expected);
  });

  it('preserves query and hash on internal paths', () => {
    expect(sanitizeNextUrl('/dashboard?tab=settings', '/login')).toBe(
      new URL('/dashboard?tab=settings', AUTH_PUBLIC_BASE_URL).toString(),
    );
    expect(sanitizeNextUrl('/dashboard#section', '/login')).toBe(
      new URL('/dashboard#section', AUTH_PUBLIC_BASE_URL).toString(),
    );
  });
});

describe('requireAuthPage', () => {
  const next = vi.fn();

  function mockRes(): Response {
    return { redirect: vi.fn() } as unknown as Response;
  }

  beforeEach(() => {
    vi.mocked(getUserById).mockReset();
    next.mockReset();
  });

  it('clears session and redirects when getUserById returns no user', () => {
    vi.mocked(getUserById).mockReturnValue(undefined);
    const res = mockRes();
    const req = {
      session: { user_id: 99, username: 'ghost', is_admin: true, login_time: 1 },
    } as Request;
    requireAuthPage(req, res, next);
    expect(getUserById).toHaveBeenCalledWith(99);
    expect(req.session.user_id).toBeUndefined();
    expect(req.session.username).toBeUndefined();
    expect(req.session.is_admin).toBeUndefined();
    expect(req.session.login_time).toBeUndefined();
    expect(res.redirect).toHaveBeenCalledWith('/login');
    expect(next).not.toHaveBeenCalled();
  });
});

describe('requireAdminPage', () => {
  const next = vi.fn();

  function mockRes(): Response {
    return {
      redirect: vi.fn(),
      status: vi.fn().mockReturnThis(),
      send: vi.fn(),
    } as unknown as Response;
  }

  beforeEach(() => {
    vi.mocked(getUserById).mockReset();
    next.mockReset();
  });

  it('redirects to login when session has no user id', () => {
    const res = mockRes();
    const req = { session: { user_id: undefined, is_admin: true } } as Request;
    requireAdminPage(req, res, next);
    expect(res.redirect).toHaveBeenCalledWith('/login');
    expect(res.status).not.toHaveBeenCalled();
    expect(next).not.toHaveBeenCalled();
  });

  it('redirects to login when getUserById returns no user', () => {
    vi.mocked(getUserById).mockReturnValue(undefined);
    const res = mockRes();
    const req = { session: { user_id: 99, is_admin: true } } as Request;
    requireAdminPage(req, res, next);
    expect(getUserById).toHaveBeenCalledWith(99);
    expect(req.session.user_id).toBeUndefined();
    expect(req.session.is_admin).toBeUndefined();
    expect(res.redirect).toHaveBeenCalledWith('/login');
    expect(res.status).not.toHaveBeenCalled();
    expect(next).not.toHaveBeenCalled();
  });

  it('returns 403 when user exists but is not admin', () => {
    vi.mocked(getUserById).mockReturnValue(stubUser({ id: 1, username: 'user', is_admin: 0 }));
    const res = mockRes();
    const req = { session: { user_id: 1, is_admin: true } } as Request;
    requireAdminPage(req, res, next);
    expect(req.session.is_admin).toBe(false);
    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.send).toHaveBeenCalledWith('Admin access required');
    expect(res.redirect).not.toHaveBeenCalled();
    expect(next).not.toHaveBeenCalled();
  });

  it('calls next for platform admins', () => {
    vi.mocked(getUserById).mockReturnValue(stubUser({ id: 1, username: 'admin', is_admin: 1 }));
    const res = mockRes();
    const req = { session: { user_id: 1, is_admin: false } } as Request;
    requireAdminPage(req, res, next);
    expect(req.session.is_admin).toBe(true);
    expect(next).toHaveBeenCalledOnce();
  });
});

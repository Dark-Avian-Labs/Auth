import { beforeAll, describe, expect, it, vi } from 'vitest';

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

import { AUTH_PUBLIC_BASE_URL } from '../config.js';
import { sanitizeNextUrl } from './service.js';

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

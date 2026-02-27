import { describe, expect, it } from 'vitest';

import { sanitizeNextUrl } from './service.js';

describe('sanitizeNextUrl', () => {
  it('uses fallback when next is missing', () => {
    const value = sanitizeNextUrl(undefined, '/login');
    expect(value.endsWith('/login')).toBe(true);
  });

  it('rejects invalid absolute URLs', () => {
    const value = sanitizeNextUrl('not-a-url', '/login');
    expect(value.endsWith('/login')).toBe(true);
  });

  it('rejects URLs outside the allowlist', () => {
    const value = sanitizeNextUrl('https://evil.example.com/steal', '/login');
    expect(value.endsWith('/login')).toBe(true);
  });
});

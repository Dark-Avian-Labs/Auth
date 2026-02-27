import { describe, expect, it } from 'vitest';

import { AUTH_PUBLIC_BASE_URL } from '../config.js';
import { sanitizeNextUrl } from './service.js';

describe('sanitizeNextUrl', () => {
  const fallback = new URL('/login', AUTH_PUBLIC_BASE_URL).toString();

  it('returns the exact fallback when sanitizeNextUrl receives missing next', () => {
    const value = sanitizeNextUrl(undefined, '/login');
    expect(value).toBe(fallback);
  });

  it('returns the exact fallback when sanitizeNextUrl receives an invalid absolute URL', () => {
    const value = sanitizeNextUrl('not-a-url', '/login');
    expect(value).toBe(fallback);
  });

  it('returns the exact fallback when sanitizeNextUrl receives a URL outside the allowlist', () => {
    const value = sanitizeNextUrl('https://evil.example.com/steal', '/login');
    expect(value).toBe(fallback);
  });

  it('returns the exact fallback when sanitizeNextUrl receives a protocol-relative URL', () => {
    const value = sanitizeNextUrl('//evil.com', '/login');
    expect(value).toBe(fallback);
  });

  it('returns the exact fallback when sanitizeNextUrl receives a javascript URL', () => {
    const value = sanitizeNextUrl('javascript:alert(1)', '/login');
    expect(value).toBe(fallback);
  });

  it('returns the exact fallback when sanitizeNextUrl receives a data URL', () => {
    const value = sanitizeNextUrl(
      'data:text/html,<script>alert(1)</script>',
      '/login',
    );
    expect(value).toBe(fallback);
  });

  it('returns the exact fallback when sanitizeNextUrl receives path traversal input', () => {
    const value = sanitizeNextUrl('../admin', '/login');
    expect(value).toBe(fallback);
  });

  it('preserves a valid internal redirect when sanitizeNextUrl receives an allowed path', () => {
    const allowed = new URL('/dashboard', AUTH_PUBLIC_BASE_URL).toString();
    const value = sanitizeNextUrl(allowed, '/login');
    expect(value).toBe(allowed);
  });
});

import { describe, expect, it } from 'vitest';

import { isSafeRelativePath } from './safeRelativePath';

describe('isSafeRelativePath', () => {
  it('allows simple root-relative paths', () => {
    expect(isSafeRelativePath('/')).toBe(true);
    expect(isSafeRelativePath('/profile')).toBe(true);
  });

  it('rejects protocol-relative and absolute URLs', () => {
    expect(isSafeRelativePath('//evil.com')).toBe(false);
    expect(isSafeRelativePath('https://evil.com')).toBe(false);
    expect(isSafeRelativePath('javascript:alert(1)')).toBe(false);
  });

  it('rejects backslashes and encoded backslashes', () => {
    expect(isSafeRelativePath('/path\\sub')).toBe(false);
    expect(isSafeRelativePath('/path%5csub')).toBe(false);
  });

  it('rejects embedded double slashes after decode', () => {
    expect(isSafeRelativePath('/path//sub')).toBe(false);
  });

  it('rejects decoded unsafe paths', () => {
    expect(isSafeRelativePath('/%2f%2fevil.com')).toBe(false);
  });

  it('rejects double-encoded protocol-relative paths', () => {
    expect(isSafeRelativePath('/%252f%252fevil.com')).toBe(false);
  });

  it('rejects paths without a leading slash', () => {
    expect(isSafeRelativePath('profile')).toBe(false);
    expect(isSafeRelativePath('dashboard')).toBe(false);
  });
});

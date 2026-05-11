import type { Request } from 'express';
import { describe, expect, it } from 'vitest';

import { secFetchSiteIsCrossSite } from './secFetchSite.js';

function mockReq(headers: Record<string, string | string[] | undefined>): Request {
  return { headers } as Request;
}

describe('secFetchSiteIsCrossSite', () => {
  it('returns true for cross-site (case-insensitive)', () => {
    expect(secFetchSiteIsCrossSite(mockReq({ 'sec-fetch-site': 'cross-site' }))).toBe(true);
    expect(secFetchSiteIsCrossSite(mockReq({ 'sec-fetch-site': 'Cross-Site' }))).toBe(true);
  });

  it('returns false for same-origin, none, and missing header', () => {
    expect(secFetchSiteIsCrossSite(mockReq({ 'sec-fetch-site': 'same-origin' }))).toBe(false);
    expect(secFetchSiteIsCrossSite(mockReq({ 'sec-fetch-site': 'none' }))).toBe(false);
    expect(secFetchSiteIsCrossSite(mockReq({}))).toBe(false);
  });

  it('reads first value when header is an array', () => {
    expect(secFetchSiteIsCrossSite(mockReq({ 'sec-fetch-site': ['cross-site'] }))).toBe(true);
  });
});

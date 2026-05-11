import type { Request } from 'express';

export function secFetchSiteIsCrossSite(req: Request): boolean {
  const raw = req.headers['sec-fetch-site'];
  const value = Array.isArray(raw) ? raw[0] : raw;
  return typeof value === 'string' && value.toLowerCase() === 'cross-site';
}

export function sanitizeUsername(raw: string): string {
  const normalized = raw.normalize('NFKC').trim().toLowerCase().replace(/\s+/g, '');
  if (!/^[a-z0-9._-]{3,40}$/.test(normalized)) {
    return '';
  }
  return normalized;
}

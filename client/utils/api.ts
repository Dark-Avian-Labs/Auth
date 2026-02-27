let cachedToken = '';

async function getCsrfToken(): Promise<string> {
  if (cachedToken) {
    return cachedToken;
  }
  try {
    const res = await fetch('/api/auth/csrf');
    if (!res.ok) {
      return '';
    }
    const body = (await res.json()) as { csrfToken?: string };
    cachedToken = body.csrfToken ?? '';
    return cachedToken;
  } catch {
    return '';
  }
}

export function clearCsrfToken(): void {
  cachedToken = '';
}

export async function apiFetch(
  url: string,
  init?: RequestInit,
): Promise<Response> {
  const method = (init?.method ?? 'GET').toUpperCase();
  const needsCsrf =
    method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS';

  const headers = new Headers(init?.headers);
  if (needsCsrf) {
    const csrfToken = await getCsrfToken();
    if (csrfToken) {
      headers.set('X-CSRF-Token', csrfToken);
    }
  }

  if (
    !headers.has('Content-Type') &&
    init?.body &&
    typeof init.body === 'string'
  ) {
    headers.set('Content-Type', 'application/json');
  }

  return fetch(url, { ...init, headers });
}

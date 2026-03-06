const CSRF_TOKEN_TTL_MS = 5 * 60 * 1000;
let cachedToken: { token: string; expiresAt: number } | null = null;
let inFlightPromise: Promise<string | null> | null = null;

async function fetchCsrfTokenWithSingleRetry(): Promise<string | null> {
  let hasRetriedAfter403 = false;

  while (true) {
    try {
      const res = await fetch('/api/auth/csrf');
      if (!res.ok) {
        const responseBody = await res.text().catch(() => '');
        console.warn('Failed to fetch CSRF token: non-OK response', {
          status: res.status,
          statusText: res.statusText,
          body: responseBody,
        });

        if (res.status === 403 && !hasRetriedAfter403) {
          hasRetriedAfter403 = true;
          cachedToken = null;
          continue;
        }

        return null;
      }

      const body = (await res.json()) as { csrfToken?: string };
      if (!body.csrfToken) {
        console.warn('Failed to fetch CSRF token: missing token in response', {
          body,
        });
        return null;
      }

      cachedToken = {
        token: body.csrfToken,
        expiresAt: Date.now() + CSRF_TOKEN_TTL_MS,
      };
      return body.csrfToken;
    } catch (error) {
      console.warn('Failed to fetch CSRF token: request error', { error });
      return null;
    }
  }
}

async function getCsrfToken(): Promise<string | null> {
  const now = Date.now();
  if (cachedToken !== null && cachedToken.expiresAt > now) {
    return cachedToken.token;
  }

  if (inFlightPromise !== null) {
    return await inFlightPromise;
  }

  const request = fetchCsrfTokenWithSingleRetry();
  inFlightPromise = request;
  try {
    return await request;
  } finally {
    if (inFlightPromise === request) {
      inFlightPromise = null;
    }
  }
}

export function clearCsrfToken(): void {
  cachedToken = null;
  inFlightPromise = null;
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
    if (csrfToken === null) {
      throw new Error('Failed to fetch CSRF token');
    }
    headers.set('X-CSRF-Token', csrfToken);
  }

  const response = await fetch(url, { ...init, headers });
  if (!needsCsrf || response.status !== 403) {
    return response;
  }

  clearCsrfToken();
  const freshToken = await getCsrfToken();
  if (freshToken === null) {
    throw new Error('Failed to refresh CSRF token');
  }

  const retryHeaders = new Headers(init?.headers);
  retryHeaders.set('X-CSRF-Token', freshToken);
  return fetch(url, { ...init, headers: retryHeaders });
}

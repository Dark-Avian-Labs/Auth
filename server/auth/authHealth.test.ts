import { afterEach, describe, expect, it, vi } from 'vitest';

import { pingAuthServiceHealth } from './authHealth.js';

describe('pingAuthServiceHealth', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('returns true when auth healthz responds ok', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response(JSON.stringify({ status: 'ok' }), { status: 200 })),
    );
    await expect(pingAuthServiceHealth('https://auth.example.com')).resolves.toBe(true);
    expect(fetch).toHaveBeenCalledWith('https://auth.example.com/healthz', expect.objectContaining({ method: 'GET' }));
  });

  it('returns false when auth healthz is not ok', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response('', { status: 503 })),
    );
    await expect(pingAuthServiceHealth('https://auth.example.com')).resolves.toBe(false);
  });

  it('returns false when fetch fails', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new Error('network');
      }),
    );
    await expect(pingAuthServiceHealth('https://auth.example.com')).resolves.toBe(false);
  });
});

import { afterEach, describe, expect, it, vi } from 'vitest';

import { log } from './logger.js';

describe('log', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('does not let caller fields override ts, level, or msg', () => {
    const infoSpy = vi.spyOn(console, 'log').mockImplementation(() => undefined);
    log('info', 'real message', {
      ts: 'spoofed-ts',
      level: 'error',
      msg: 'spoofed-msg',
      requestId: 'abc',
    });

    const line = JSON.parse(String(infoSpy.mock.calls[0]?.[0])) as {
      ts: string;
      level: string;
      msg: string;
      requestId: string;
    };
    expect(line.msg).toBe('real message');
    expect(line.level).toBe('info');
    expect(line.ts).not.toBe('spoofed-ts');
    expect(line.requestId).toBe('abc');
  });
});

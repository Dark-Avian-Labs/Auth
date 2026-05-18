// @vitest-environment jsdom

import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { createMemoryRouter, RouterProvider } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { APP_PATHS } from '../../app/paths';
import { LoginPage } from './LoginPage';
import {
  applyPostLoginRedirect,
  isSafeRelativePath,
  readNextFromLocation,
  type PostLoginRedirectDeps,
} from './loginRedirect';

vi.mock('../../utils/api', () => ({
  apiFetch: vi.fn(),
}));

vi.mock('./AuthContext', () => ({
  useAuth: vi.fn(),
}));

import { apiFetch } from '../../utils/api';
import { useAuth } from './AuthContext';

let warnSpy: ReturnType<typeof vi.spyOn> | undefined;

beforeEach(() => {
  warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
});

describe('isSafeRelativePath', () => {
  it.each([
    ['/dashboard', true],
    ['/dashboard?tab=settings', true],
    ['/dashboard#section', true],
    ['/path//subpath', false],
    [APP_PATHS.home, true],
    ['//evil.com/phish', false],
    ['https://evil.example.com/steal', false],
    ['javascript:alert(1)', false],
    ['data:text/html,hi', false],
    ['../admin', false],
    ['ftp://x', false],
    ['/x\\y', false],
    ['%5c%5cevil', false],
  ])('%s -> %s', (input, expected) => {
    expect(isSafeRelativePath(input)).toBe(expected);
  });
});

describe('readNextFromLocation', () => {
  it('uses home when next is missing', () => {
    expect(readNextFromLocation('')).toBe(APP_PATHS.home);
  });

  it('accepts safe relative next from query string', () => {
    expect(readNextFromLocation('?next=%2Fprofile')).toBe('/profile');
  });

  it('rejects open-redirect style next (protocol-relative)', () => {
    expect(readNextFromLocation('?next=%2F%2Fevil.com')).toBe(APP_PATHS.home);
  });
});

describe('applyPostLoginRedirect', () => {
  const homePath = APP_PATHS.home;
  const navigateSpy = vi.fn((_: string) => {});
  const assignSpy = vi.fn((_: string) => {});

  beforeEach(() => {
    navigateSpy.mockClear();
    assignSpy.mockClear();
  });

  const deps = (origin = 'https://auth.example.test'): PostLoginRedirectDeps => ({
    windowOrigin: origin,
    assignHref: assignSpy,
    navigate: navigateSpy,
    warn: (...args: unknown[]) => warnSpy!(...args),
    homePath,
  });

  it('navigates home when next is missing', () => {
    applyPostLoginRedirect(undefined, deps());
    expect(navigateSpy).toHaveBeenCalledWith(homePath);
    expect(warnSpy).not.toHaveBeenCalled();
  });

  it('assigns href for same-origin absolute URL', () => {
    applyPostLoginRedirect('https://auth.example.test/profile?x=1', deps());
    expect(assignSpy).toHaveBeenCalledWith('https://auth.example.test/profile?x=1');
    expect(navigateSpy).not.toHaveBeenCalled();
    expect(warnSpy).not.toHaveBeenCalled();
  });

  it('warns and navigates home on cross-origin absolute URL', () => {
    applyPostLoginRedirect('https://evil.example.com/', deps());
    expect(warnSpy).toHaveBeenCalledWith(
      '[auth] Login redirect rejected: absolute URL origin mismatch',
      expect.objectContaining({
        expectedOrigin: 'https://auth.example.test',
        targetOrigin: 'https://evil.example.com',
      }),
    );
    expect(navigateSpy).toHaveBeenCalledWith(homePath);
  });

  it('warns and navigates home on malformed absolute URL', () => {
    applyPostLoginRedirect('https://', deps());
    expect(warnSpy).toHaveBeenCalledWith('[auth] Login redirect rejected: invalid absolute URL from server');
    expect(navigateSpy).toHaveBeenCalledWith(homePath);
  });

  it('navigates to safe relative path', () => {
    applyPostLoginRedirect('/legal', deps());
    expect(navigateSpy).toHaveBeenCalledWith('/legal');
    expect(warnSpy).not.toHaveBeenCalled();
  });

  it('warns and navigates home on unsafe relative path', () => {
    applyPostLoginRedirect('//evil.com', deps());
    expect(warnSpy).toHaveBeenCalledWith('[auth] Login redirect rejected: unsafe or invalid next path from server');
    expect(navigateSpy).toHaveBeenCalledWith(homePath);
  });
});

describe('LoginPage (integration)', () => {
  beforeEach(() => {
    vi.mocked(useAuth).mockReturnValue({
      auth: { status: 'unauthenticated', user: null, apps: [] },
      refresh: vi.fn().mockResolvedValue(undefined),
      logout: vi.fn(),
      updateProfile: vi.fn(),
    });
  });

  function mockLoginResponse(body: unknown) {
    vi.mocked(apiFetch).mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(body),
    } as Response);
  }

  it('navigates to safe relative next after successful login', async () => {
    mockLoginResponse({ next: '/profile' });
    const router = createMemoryRouter(
      [
        { path: '/login', element: <LoginPage /> },
        { path: '/profile', element: <div>Profile</div> },
      ],
      { initialEntries: ['/login'] },
    );
    const user = userEvent.setup();
    render(<RouterProvider router={router} />);

    await user.type(screen.getByLabelText('Username'), 'u');
    await user.type(screen.getByLabelText('Password'), 'p');
    await user.click(screen.getByRole('button', { name: 'Login' }));

    await waitFor(() => {
      expect(router.state.location.pathname).toBe('/profile');
    });
    expect(warnSpy).not.toHaveBeenCalled();
  });

  it('falls back to home and warns when server returns unsafe relative next', async () => {
    mockLoginResponse({ next: '//evil.com' });
    const router = createMemoryRouter(
      [
        { path: '/login', element: <LoginPage /> },
        { path: '/', element: <div>Home</div> },
      ],
      { initialEntries: ['/login'] },
    );
    const user = userEvent.setup();
    render(<RouterProvider router={router} />);

    await user.type(screen.getByLabelText('Username'), 'u');
    await user.type(screen.getByLabelText('Password'), 'p');
    await user.click(screen.getByRole('button', { name: 'Login' }));

    await waitFor(() => {
      expect(router.state.location.pathname).toBe('/');
    });
    expect(warnSpy).toHaveBeenCalledWith('[auth] Login redirect rejected: unsafe or invalid next path from server');
  });

  it('assigns window.location for same-origin absolute next', async () => {
    const origin = 'http://localhost:3000';
    let href = `${origin}/login`;
    const locationSnapshot = window.location;
    vi.stubGlobal(
      'location',
      new Proxy(locationSnapshot, {
        get(target, prop) {
          if (prop === 'origin') return origin;
          if (prop === 'href') return href;
          return Reflect.get(target, prop);
        },
        set(target, prop, value) {
          if (prop === 'href') {
            href = String(value);
            return true;
          }
          return Reflect.set(target, prop, value);
        },
      }),
    );

    mockLoginResponse({ next: `${origin}/admin` });
    const router = createMemoryRouter([{ path: '/login', element: <LoginPage /> }], {
      initialEntries: ['/login'],
    });
    const user = userEvent.setup();
    render(<RouterProvider router={router} />);

    await user.type(screen.getByLabelText('Username'), 'u');
    await user.type(screen.getByLabelText('Password'), 'p');
    await user.click(screen.getByRole('button', { name: 'Login' }));

    await waitFor(() => {
      expect(href).toBe(`${origin}/admin`);
    });
    vi.unstubAllGlobals();
  });
});

afterEach(() => {
  warnSpy?.mockRestore();
  warnSpy = undefined;
  vi.unstubAllGlobals();
});

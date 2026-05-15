import { useState, useEffect, useRef, useCallback } from 'react';
import { Link, Outlet } from 'react-router-dom';

import feathers from '../../../feathers.png';
import {
  APP_DISPLAY_NAME,
  APP_DISPLAY_NAME_2,
  APP_VERSION,
  LEGAL_ENTITY_NAME,
  LEGAL_PAGE_URL,
} from '../../app/config';
import { APP_PATHS } from '../../app/paths';
import { MaterialSymbol } from '../../components/ui/MaterialSymbol';
import { Menu } from '../../components/ui/Menu';
import { useTheme } from '../../context/ThemeContext';
import { useAuth } from '../../features/auth/AuthContext';
import { AsciiWaveBackground } from './AsciiWaveBackground';
import { SearchBar } from './SearchBar';
import { StaleClientUpdateBanner } from './StaleClientUpdateBanner';

export function Layout() {
  const { mode, toggleMode } = useTheme();
  const { auth, logout } = useAuth();
  const [menuOpen, setMenuOpen] = useState(false);
  const [logoutError, setLogoutError] = useState<string | null>(null);
  const menuRef = useRef<HTMLDivElement | null>(null);
  const triggerRef = useRef<HTMLButtonElement | null>(null);
  const firstMenuItemRef = useRef<HTMLElement | null>(null);
  const prevMenuOpenRef = useRef(menuOpen);
  const currentYear = new Date().getFullYear();

  const handleLogout = useCallback(async () => {
    setLogoutError(null);
    try {
      await logout(APP_PATHS.login);
    } catch (error) {
      console.error('Logout failed:', error);
      setLogoutError('Logout failed. Please try again.');
    }
  }, [logout]);

  useEffect(() => {
    if (!menuOpen) {
      return undefined;
    }
    const onMouseDown = (event: globalThis.MouseEvent) => {
      if (!menuRef.current?.contains(event.target as Node)) {
        setMenuOpen(false);
      }
    };
    document.addEventListener('mousedown', onMouseDown);
    return () => {
      document.removeEventListener('mousedown', onMouseDown);
    };
  }, [menuOpen]);

  useEffect(() => {
    if (menuOpen) {
      firstMenuItemRef.current?.focus();
    } else if (prevMenuOpenRef.current) {
      triggerRef.current?.focus();
    }
    prevMenuOpenRef.current = menuOpen;
  }, [menuOpen]);

  useEffect(() => {
    if (!menuOpen) {
      return undefined;
    }
    const onEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setMenuOpen(false);
      }
    };
    document.addEventListener('keydown', onEscape);
    return () => {
      document.removeEventListener('keydown', onEscape);
    };
  }, [menuOpen]);

  const isLoggedIn = auth.status === 'ok' && auth.user !== null;
  const isAdmin = auth.user?.is_admin === true;
  return (
    <div className="flex min-h-screen flex-col">
      <a href="#main-content" className="skip-link">
        Skip to main content
      </a>
      <AsciiWaveBackground />
      <header className="relative z-30 h-[100px] px-6">
        <div className="mx-auto grid h-full w-full max-w-[1900px] grid-cols-[1fr_auto_1fr] items-center gap-4">
          <div className="flex w-fit max-w-full min-w-0 flex-col gap-0.5 justify-self-start">
            <Link to={APP_PATHS.home} className="brand-lockup w-fit">
              <img
                src={feathers}
                alt="Dark Avian Labs feather mark"
                className="brand-lockup__icon"
              />
              <span
                className={`brand-lockup__title brand-lockup--fx ${mode === 'light' ? 'brand-lockup--light' : ''}`}
              >
                {APP_DISPLAY_NAME}
              </span>
              <span
                className={`brand-lockup__title brand-lockup__title_small brand-lockup--fx ${mode === 'light' ? 'brand-lockup--light' : ''}`}
              >
                {' '}
                {APP_DISPLAY_NAME_2}
              </span>
            </Link>
            <div className="flex flex-wrap items-center justify-end gap-x-2 gap-y-0.5">
              <span
                className="text-muted font-mono text-[10px] leading-none tracking-wide opacity-70"
                title={`Client ${APP_VERSION}`}
              >
                v{APP_VERSION}
              </span>
            </div>
          </div>

          <div className="justify-self-center">{isLoggedIn ? <SearchBar /> : null}</div>

          <div className="flex flex-wrap items-center justify-end gap-3">
            <button
              type="button"
              className="icon-toggle-btn"
              onClick={toggleMode}
              aria-label={`Switch to ${mode === 'dark' ? 'light' : 'dark'} mode`}
              title={`Switch to ${mode === 'dark' ? 'light' : 'dark'} mode`}
            >
              {mode === 'dark' ? (
                <MaterialSymbol name="light_mode" filled />
              ) : (
                <MaterialSymbol name="dark_mode" filled />
              )}
            </button>

            <div ref={menuRef} className="relative">
              <button
                ref={triggerRef}
                type="button"
                className="icon-toggle-btn"
                aria-haspopup="menu"
                aria-expanded={menuOpen}
                aria-label="Open user menu"
                onClick={() => setMenuOpen((prev) => !prev)}
              >
                <MaterialSymbol name="person" filled />
              </button>
              {menuOpen && (
                <Menu>
                  {!isLoggedIn ? (
                    <>
                      <Link
                        ref={(node) => {
                          firstMenuItemRef.current = node;
                        }}
                        to={APP_PATHS.login}
                        className="user-menu-item"
                        role="menuitem"
                        onClick={() => setMenuOpen(false)}
                      >
                        Login
                      </Link>
                    </>
                  ) : (
                    <>
                      {isAdmin && (
                        <Link
                          ref={(node) => {
                            firstMenuItemRef.current = node;
                          }}
                          to={APP_PATHS.admin}
                          className="user-menu-item"
                          role="menuitem"
                          onClick={() => setMenuOpen(false)}
                        >
                          Admin
                        </Link>
                      )}
                      <Link
                        ref={
                          isAdmin
                            ? undefined
                            : (node) => {
                                firstMenuItemRef.current = node;
                              }
                        }
                        to={APP_PATHS.profile}
                        className="user-menu-item"
                        role="menuitem"
                        onClick={() => setMenuOpen(false)}
                      >
                        Profile
                      </Link>
                      <button
                        type="button"
                        className="user-menu-item text-left"
                        role="menuitem"
                        onClick={() => {
                          setMenuOpen(false);
                          handleLogout();
                        }}
                      >
                        Logout
                      </button>
                    </>
                  )}
                </Menu>
              )}
            </div>
          </div>
        </div>
        {logoutError ? (
          <p className="text-danger mt-1 text-right text-sm" role="alert">
            {logoutError}
          </p>
        ) : null}
      </header>

      <main id="main-content" className="relative z-0 flex-1 px-6 pb-6">
        <div className="mx-auto w-full max-w-[1900px]">
          <Outlet />
        </div>
      </main>

      <footer className="relative z-10 flex h-[50px] items-center justify-center px-6">
        <div className="mx-auto w-full max-w-[1900px] text-center">
          <a
            href={LEGAL_PAGE_URL}
            className="text-muted hover:text-foreground text-sm"
            target={LEGAL_PAGE_URL.startsWith('http') ? '_blank' : undefined}
            rel={LEGAL_PAGE_URL.startsWith('http') ? 'noreferrer' : undefined}
          >
            ©{currentYear} {LEGAL_ENTITY_NAME}
          </a>
        </div>
      </footer>

      <StaleClientUpdateBanner appVersion={APP_VERSION} />
    </div>
  );
}

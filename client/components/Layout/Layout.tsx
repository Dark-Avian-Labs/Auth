import { useState, useEffect, useRef, useCallback } from 'react';
import { Link, Outlet } from 'react-router-dom';

import { SearchBar } from './SearchBar';
import bgArt from '../../../background.txt?raw';
import feathers from '../../../feathers.png';
import {
  APP_DISPLAY_NAME,
  APP_DISPLAY_NAME_2,
  LEGAL_ENTITY_NAME,
  LEGAL_PAGE_URL,
} from '../../app/config';
import { APP_PATHS } from '../../app/paths';
import { Menu } from '../../components/ui/Menu';
import { useTheme } from '../../context/ThemeContext';
import { useAuth } from '../../features/auth/AuthContext';

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
    const onMouseDown = (event: MouseEvent) => {
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
  const avatarId = Number(auth.user?.avatar ?? 1);

  return (
    <div className="flex min-h-screen flex-col">
      <div className="bg-art" aria-hidden="true">
        {bgArt}
      </div>
      <header className="relative z-30 h-[100px] px-6">
        <div className="mx-auto grid h-full w-full max-w-[1900px] grid-cols-[1fr_auto_1fr] items-center gap-4">
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

          <div className="justify-self-center">
            {isLoggedIn ? <SearchBar /> : null}
          </div>

          <div className="flex flex-wrap items-center justify-end gap-3">
            <button
              type="button"
              className="icon-toggle-btn"
              onClick={toggleMode}
              aria-label={`Switch to ${mode === 'dark' ? 'light' : 'dark'} mode`}
              title={`Switch to ${mode === 'dark' ? 'light' : 'dark'} mode`}
            >
              <span aria-hidden="true">{mode === 'dark' ? '☀' : '☾'}</span>
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
                <span aria-hidden="true" className="text-xs font-semibold">
                  {isLoggedIn
                    ? `#${Number.isInteger(avatarId) ? avatarId : 1}`
                    : '🔐'}
                </span>
              </button>
              {menuOpen && (
                <Menu>
                  {!isLoggedIn ? (
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
          <p className="mt-1 text-right text-sm text-red-400" role="alert">
            {logoutError}
          </p>
        ) : null}
      </header>

      <main className="relative z-0 flex-1 px-6 pb-6">
        <div className="mx-auto w-full max-w-[1900px]">
          <Outlet />
        </div>
      </main>

      <footer className="relative z-10 flex h-[50px] items-center justify-center px-6">
        <div className="mx-auto w-full max-w-[1900px] text-center">
          <a
            href={LEGAL_PAGE_URL}
            className="text-sm text-muted hover:text-foreground"
            target={LEGAL_PAGE_URL.startsWith('http') ? '_blank' : undefined}
            rel={LEGAL_PAGE_URL.startsWith('http') ? 'noreferrer' : undefined}
          >
            ©{currentYear} {LEGAL_ENTITY_NAME}
          </a>
        </div>
      </footer>
    </div>
  );
}

import {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react';

type ThemeMode = 'light' | 'dark';

interface ThemeContextValue {
  mode: ThemeMode;
  setMode: (mode: ThemeMode) => void;
  toggleMode: () => void;
}

const THEME_STORAGE_KEY = 'dal.theme.mode';
const THEME_COOKIE = 'dal.theme.mode';
const THEME_COOKIE_DOMAIN =
  (import.meta.env.VITE_SHARED_THEME_COOKIE_DOMAIN as string | undefined) ?? '';
const ONE_YEAR_SECONDS = 60 * 60 * 24 * 365;

const ThemeContext = createContext<ThemeContextValue | undefined>(undefined);

function resolveInitialMode(): ThemeMode {
  if (typeof window === 'undefined') return 'dark';
  const stored = window.localStorage.getItem(THEME_STORAGE_KEY);
  if (stored === 'light' || stored === 'dark') {
    return stored;
  }
  const cookieTheme = document.cookie
    .split(';')
    .map((part) => part.trim())
    .find((part) => part.startsWith(`${THEME_COOKIE}=`))
    ?.split('=')
    .slice(1)
    .join('=');
  return cookieTheme === 'light' ? 'light' : 'dark';
}

function writeThemeCookie(mode: ThemeMode): void {
  const secure = window.location.protocol === 'https:' ? '; Secure' : '';
  const base = `${THEME_COOKIE}=${mode}; Max-Age=${ONE_YEAR_SECONDS}; Path=/; SameSite=Lax${secure}`;
  document.cookie = base;
  if (THEME_COOKIE_DOMAIN) {
    document.cookie = `${base}; Domain=${THEME_COOKIE_DOMAIN}`;
  }
}

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [mode, setMode] = useState<ThemeMode>(resolveInitialMode);

  useEffect(() => {
    const root = document.documentElement;
    root.classList.remove('theme-light', 'theme-dark');
    root.classList.add(`theme-${mode}`);
    window.localStorage.setItem(THEME_STORAGE_KEY, mode);
    writeThemeCookie(mode);
  }, [mode]);

  const value = useMemo<ThemeContextValue>(
    () => ({
      mode,
      setMode,
      toggleMode: () => setMode((prev) => (prev === 'dark' ? 'light' : 'dark')),
    }),
    [mode],
  );

  return (
    <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>
  );
}

export function useTheme() {
  const context = useContext(ThemeContext);
  if (!context) {
    throw new Error('useTheme must be used within ThemeProvider');
  }
  return context;
}

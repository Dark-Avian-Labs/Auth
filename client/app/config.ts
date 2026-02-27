function readTrimmedEnv(value: string | undefined, fallback: string): string {
  if (typeof value !== 'string') {
    return fallback;
  }
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : fallback;
}

function readCsvEnv(value: string | undefined): string[] {
  if (typeof value !== 'string') {
    return [];
  }
  return value
    .split(',')
    .map((item) => item.trim())
    .filter((item) => item.length > 0);
}

export const APP_DISPLAY_NAME = readTrimmedEnv(
  import.meta.env.VITE_APP_NAME as string | undefined,
  'Dark Avian',
);

export const APP_DISPLAY_NAME_2 = readTrimmedEnv(
  import.meta.env.VITE_APP_NAME_2 as string | undefined,
  'LABS',
);

export const LEGAL_ENTITY_NAME = readTrimmedEnv(
  import.meta.env.VITE_LEGAL_ENTITY_NAME as string | undefined,
  'Dark Avian Labs',
);

export const LEGAL_PAGE_URL = readTrimmedEnv(
  import.meta.env.VITE_LEGAL_PAGE_URL as string | undefined,
  '/legal',
);

export const SEARCH_PLACEHOLDER = readTrimmedEnv(
  import.meta.env.VITE_SEARCH_PLACEHOLDER as string | undefined,
  'Search users...',
);

export const AUTH_ADMIN_URL = readTrimmedEnv(
  import.meta.env.VITE_AUTH_ADMIN_URL as string | undefined,
  'http://localhost:3000/admin',
);

export const ALLOWED_NEXT_ORIGINS = readCsvEnv(
  import.meta.env.VITE_ALLOWED_NEXT_ORIGINS as string | undefined,
);

export const AVAILABLE_APPS = readCsvEnv(
  import.meta.env.VITE_AVAILABLE_APPS as string | undefined,
);

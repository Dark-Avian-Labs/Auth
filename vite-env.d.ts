/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_APP_NAME?: string;
  readonly VITE_APP_NAME_2?: string;
  readonly VITE_LEGAL_ENTITY_NAME?: string;
  readonly VITE_LEGAL_PAGE_URL?: string;
  readonly VITE_SEARCH_PLACEHOLDER?: string;
  readonly VITE_ALLOWED_NEXT_ORIGINS?: string;
  readonly VITE_AVAILABLE_APPS?: string;
  readonly VITE_SHARED_THEME_COOKIE_DOMAIN?: string;
  readonly VITE_BASE_PATH?: string;
  readonly VITE_DEV_API_TARGET?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}

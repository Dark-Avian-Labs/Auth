export type AuthStatus = 'loading' | 'unauthenticated' | 'ok' | 'error';

export interface RemoteAuthUser {
  id: number;
  username: string;
  is_admin: boolean;
  display_name?: string;
  email?: string;
  avatar?: number | string;
}

export interface AppSummary {
  id: string;
  label: string;
  subtitle: string;
  url: string;
}

export interface RemoteAuthState {
  authenticated?: boolean;
  has_game_access?: boolean;
  user?: RemoteAuthUser;
  app_access?: string[];
  apps?: AppSummary[];
}

export interface AuthState {
  status: AuthStatus;
  user: RemoteAuthUser | null;
  apps: AppSummary[];
}

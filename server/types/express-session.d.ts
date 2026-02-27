import 'express-session';

declare module 'express-session' {
  interface SessionData {
    user_id?: number;
    username?: string;
    is_admin?: boolean;
    csrf_token?: string;
    login_time?: number;
  }
}

import { APP_PATHS } from '../../app/paths';
import { isSafeRelativePath } from './safeRelativePath';

export { isSafeRelativePath } from './safeRelativePath';

export function isAbsoluteHttpUrl(next: string): boolean {
  return /^https?:\/\//i.test(next);
}

export function readNextFromLocation(search: string): string {
  const params = new URLSearchParams(search);
  const rawNext = params.get('next');
  if (!rawNext) {
    return APP_PATHS.home;
  }
  const next = rawNext.trim();
  return isSafeRelativePath(next) ? next : APP_PATHS.home;
}

export interface PostLoginRedirectDeps {
  windowOrigin: string;
  assignHref: (href: string) => void;
  navigate: (to: string) => void;
  warn: (...args: unknown[]) => void;
  homePath: string;
}

export function applyPostLoginRedirect(bodyNext: unknown, deps: PostLoginRedirectDeps): void {
  if (typeof bodyNext !== 'string') {
    deps.navigate(deps.homePath);
    return;
  }

  if (isAbsoluteHttpUrl(bodyNext)) {
    try {
      const targetUrl = new URL(bodyNext);
      if (targetUrl.origin === deps.windowOrigin) {
        deps.assignHref(targetUrl.href);
        return;
      }
      deps.warn('[auth] Login redirect rejected: absolute URL origin mismatch', {
        expectedOrigin: deps.windowOrigin,
        targetOrigin: targetUrl.origin,
      });
    } catch {
      deps.warn('[auth] Login redirect rejected: invalid absolute URL from server');
    }
    deps.navigate(deps.homePath);
    return;
  }

  if (isSafeRelativePath(bodyNext)) {
    deps.navigate(bodyNext);
    return;
  }

  deps.warn('[auth] Login redirect rejected: unsafe or invalid next path from server');
  deps.navigate(deps.homePath);
}

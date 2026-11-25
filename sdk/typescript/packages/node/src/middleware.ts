/**
 * Framework-agnostic (req, res, next) middleware for web apps / BFFs:
 * login, callback, logout and back-channel logout routes, an opaque
 * session cookie, `req.moonSso` helpers and HTMX-aware login redirects.
 * Works with Express, Connect and plain node:http.
 */

import type { IncomingMessage, ServerResponse } from 'node:http';
import type { AccountApi } from './shared/account.js';
import { MoonSsoError } from './shared/errors.js';
import type { IdTokenClaims } from './shared/jose.js';
import { type BackchannelLogoutVerifier, createBackchannelLogoutHandler, type LogoutTokenClaims } from './backchannel.js';
import type { MoonSsoClient } from './client.js';
import {
  appendSetCookie,
  type CookieOptions,
  header,
  isHtmx,
  type NextFunction,
  originalUrl,
  parseCookies,
  redirect,
  safeReturnTo,
  sendJson,
  serializeCookie,
} from './http-util.js';
import { MemorySessionStore, SessionManager, type SessionStore } from './session.js';

export interface MoonSsoRequestContext {
  /** Session id (undefined before any login attempt). */
  sessionId: string | undefined;
  isAuthenticated: boolean;
  /** Validated ID token claims of the signed-in user. */
  user: IdTokenClaims | undefined;
  /** A valid access token (refreshed when < 120 s remain). Throws login_required when signed out. */
  getAccessToken(opts?: { force?: boolean }): Promise<string>;
  /** Account API on behalf of the user. */
  account(): AccountApi;
  /** URL of the login route with returnTo. */
  loginUrl(returnTo?: string): string;
  /** Sends the user to the login route (HTMX-aware). */
  requireLogin(returnTo?: string): void;
}

export type RequestWithMoonSso = IncomingMessage & { moonSso: MoonSsoRequestContext };

export interface MoonSsoMiddlewareOptions {
  client: MoonSsoClient;
  /** Session manager or a store (default: new MemorySessionStore()). */
  sessions?: SessionManager | SessionStore;
  cookieName?: string;
  /** Cookie attributes; `secure` defaults to true when the redirect URI is https. */
  cookie?: Omit<CookieOptions, 'maxAge' | 'httpOnly'> & { maxAgeSeconds?: number };
  /** Route paths. callback defaults to the path of client.options.redirectUri. */
  routes?: { login?: string; callback?: string; logout?: string; backchannel?: string };
  /** Where to go after login when no returnTo was given (default "/"). */
  afterLoginPath?: string;
  /** Where to go after logout if the SSO session is not ended (default "/"). */
  afterLogoutPath?: string;
  /** Redirect to end_session_endpoint on logout (default true). */
  endSessionOnLogout?: boolean;
  /** Paths that require a signed-in user (true = all except the SDK routes). */
  requireAuth?: boolean | ((req: IncomingMessage) => boolean);
  /** Enables the back-channel logout route. */
  backchannel?: {
    verifier: BackchannelLogoutVerifier;
    onLogout?: (sub: string | undefined, sid: string | undefined, claims: LogoutTokenClaims) => void | Promise<void>;
  };
  /** Login / callback failures; default answers 400 with a short message. Errors never include tokens. */
  onError?: (err: unknown, req: IncomingMessage, res: ServerResponse) => void;
  /** Scope / prompt etc. for every login. */
  authorizationParams?: Parameters<MoonSsoClient['createAuthorizationUrl']>[0];
}

function pathOf(req: IncomingMessage): string {
  const url = originalUrl(req);
  const q = url.indexOf('?');
  return q >= 0 ? url.slice(0, q) : url;
}

function queryOf(req: IncomingMessage): URLSearchParams {
  const url = originalUrl(req);
  const q = url.indexOf('?');
  return new URLSearchParams(q >= 0 ? url.slice(q + 1) : '');
}

function wantsHtml(req: IncomingMessage): boolean {
  const accept = header(req, 'accept') ?? '';
  return accept === '' || accept.includes('text/html') || accept.includes('*/*');
}

export function moonSsoMiddleware(opts: MoonSsoMiddlewareOptions): (req: IncomingMessage, res: ServerResponse, next: NextFunction) => void {
  const client = opts.client;
  const sessions =
    opts.sessions instanceof SessionManager
      ? opts.sessions
      : new SessionManager({ client, store: opts.sessions ?? new MemorySessionStore() });
  const cookieName = opts.cookieName ?? 'moon_sso';
  const redirectUri = client.options.redirectUri;
  const routes = {
    login: opts.routes?.login ?? '/auth/login',
    callback: opts.routes?.callback ?? (redirectUri ? new URL(redirectUri).pathname : '/auth/callback'),
    logout: opts.routes?.logout ?? '/auth/logout',
    backchannel: opts.routes?.backchannel ?? '/auth/backchannel-logout',
  };
  const cookieBase: CookieOptions = {
    path: opts.cookie?.path ?? '/',
    secure: opts.cookie?.secure ?? (redirectUri ? redirectUri.startsWith('https:') : false),
    sameSite: opts.cookie?.sameSite ?? 'Lax',
    httpOnly: true,
  };
  if (opts.cookie?.domain) {
    cookieBase.domain = opts.cookie.domain;
  }
  const maxAge = opts.cookie?.maxAgeSeconds;
  const setSessionCookie = (res: ServerResponse, id: string) =>
    appendSetCookie(res, serializeCookie(cookieName, id, maxAge === undefined ? cookieBase : { ...cookieBase, maxAge }));
  const clearSessionCookie = (res: ServerResponse) => appendSetCookie(res, serializeCookie(cookieName, '', { ...cookieBase, maxAge: 0 }));

  const store = sessions.store;
  const bcHandler = opts.backchannel
    ? createBackchannelLogoutHandler({
        verifier: opts.backchannel.verifier,
        onLogout: async (sub, sid, claims) => {
          if (sid && store.deleteBySid) {
            await store.deleteBySid(sid);
          } else if (sub && store.deleteBySub) {
            await store.deleteBySub(sub);
          }
          await opts.backchannel?.onLogout?.(sub, sid, claims);
        },
      })
    : undefined;

  const fail = (err: unknown, req: IncomingMessage, res: ServerResponse) => {
    if (opts.onError) {
      opts.onError(err, req, res);
      return;
    }
    const code = err instanceof MoonSsoError ? err.error : 'server_error';
    res.statusCode = err instanceof MoonSsoError && err.error === 'network' ? 502 : 400;
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    res.end(`Sign-in failed (${code}). Please try again.`);
  };

  const loginUrl = (returnTo?: string) => `${routes.login}?returnTo=${encodeURIComponent(safeReturnTo(returnTo, opts.afterLoginPath ?? '/'))}`;

  const requireLogin = (req: IncomingMessage, res: ServerResponse, returnTo?: string) => {
    let target = returnTo;
    if (target === undefined) {
      const hx = header(req, 'hx-current-url');
      if (isHtmx(req) && hx) {
        try {
          const u = new URL(hx);
          target = u.pathname + u.search;
        } catch {
          target = undefined;
        }
      }
      target ??= req.method === 'GET' ? originalUrl(req) : undefined;
    }
    if (!isHtmx(req) && !wantsHtml(req)) {
      sendJson(res, 401, { error: 'login_required', login_url: loginUrl(target) });
      return;
    }
    redirect(req, res, loginUrl(target));
  };

  return (req, res, next) => {
    const path = pathOf(req);
    const sessionId = parseCookies(req)[cookieName] || undefined;

    const run = async () => {
      if (path === routes.login && (req.method === 'GET' || req.method === 'POST')) {
        const returnTo = safeReturnTo(queryOf(req).get('returnTo'), opts.afterLoginPath ?? '/');
        const r = await sessions.beginLogin(sessionId, { ...opts.authorizationParams, returnTo });
        if (r.sessionId !== sessionId) {
          setSessionCookie(res, r.sessionId);
        }
        redirect(req, res, r.url);
        return;
      }
      if (path === routes.callback && req.method === 'GET') {
        if (!sessionId) {
          throw new MoonSsoError({ error: 'invalid_state', error_description: 'session cookie missing' });
        }
        const done = await sessions.completeLogin(sessionId, queryOf(req));
        setSessionCookie(res, done.sessionId);
        redirect(req, res, safeReturnTo(done.returnTo, opts.afterLoginPath ?? '/'));
        return;
      }
      if (path === routes.logout && (req.method === 'POST' || req.method === 'GET')) {
        let target: string | undefined;
        if (sessionId) {
          target = await sessions.logout(sessionId);
        }
        clearSessionCookie(res);
        redirect(req, res, (opts.endSessionOnLogout ?? true) && target ? target : (opts.afterLogoutPath ?? '/'));
        return;
      }
      if (bcHandler && path === routes.backchannel) {
        await bcHandler(req, res);
        return;
      }

      const data = sessionId ? await sessions.get(sessionId) : undefined;
      const authed = data?.tokens !== undefined;
      const ctx: MoonSsoRequestContext = {
        sessionId,
        isAuthenticated: authed,
        user: data?.user,
        getAccessToken: async (o = {}) => {
          if (!sessionId) {
            throw new MoonSsoError({ error: 'login_required', error_description: 'not signed in' });
          }
          return sessions.getAccessToken(sessionId, o);
        },
        account: () => {
          if (!sessionId) {
            throw new MoonSsoError({ error: 'login_required', error_description: 'not signed in' });
          }
          return sessions.account(sessionId);
        },
        loginUrl,
        requireLogin: (returnTo) => requireLogin(req, res, returnTo),
      };
      (req as RequestWithMoonSso).moonSso = ctx;
      const mustAuth = typeof opts.requireAuth === 'function' ? opts.requireAuth(req) : opts.requireAuth === true;
      if (mustAuth && !authed) {
        requireLogin(req, res);
        return;
      }
      if (authed && sessionId) {
        // Keep the access token fresh; a dead refresh token ends the local session.
        try {
          await sessions.getTokens(sessionId);
        } catch (e) {
          if (e instanceof MoonSsoError && (e.error === 'invalid_grant' || e.error === 'login_required')) {
            clearSessionCookie(res);
            ctx.isAuthenticated = false;
            ctx.user = undefined;
            if (mustAuth) {
              requireLogin(req, res);
              return;
            }
          }
          // Transient errors (network, 5xx) keep the session; the next request retries.
        }
      }
      next();
    };

    run().catch((e: unknown) => {
      if (path === routes.login || path === routes.callback || path === routes.logout) {
        fail(e, req, res);
        return;
      }
      next(e);
    });
  };
}

/** Express-style guard: answers with a login redirect (HTMX-aware) unless signed in. Use after moonSsoMiddleware. */
export function requireLogin(): (req: IncomingMessage, res: ServerResponse, next: NextFunction) => void {
  return (req, res, next) => {
    const ctx = (req as Partial<RequestWithMoonSso>).moonSso;
    if (!ctx) {
      next(new MoonSsoError({ error: 'invalid_configuration', error_description: 'moonSsoMiddleware must run before requireLogin' }));
      return;
    }
    if (ctx.isAuthenticated) {
      next();
      return;
    }
    ctx.requireLogin();
  };
}

// Minimal Express BFF: tokens stay on the server, the browser only holds an
// HttpOnly session cookie. Includes HTMX-friendly redirects, profile editing,
// webhooks and back-channel logout.
//
//   MOON_SSO_ISSUER=https://sso.moonl.cloud \
//   MOON_SSO_CLIENT_ID=... MOON_SSO_CLIENT_SECRET=... \
//   MOON_SSO_REDIRECT_URI=http://127.0.0.1:3000/auth/callback \
//   MOON_SSO_WEBHOOK_SECRET=whsec_... npm start

import express, { type NextFunction, type Request, type Response } from 'express';
import {
  BackchannelLogoutVerifier,
  createWebhookHandler,
  MemorySessionStore,
  MoonSsoClient,
  MoonSsoError,
  moonSsoMiddleware,
  type RequestWithMoonSso,
  requireLogin,
  SessionManager,
} from '@moon-sso/node';

function env(name: string, fallback?: string): string {
  const v = process.env[name] ?? fallback;
  if (v === undefined || v === '') {
    throw new Error(`environment variable ${name} is required`);
  }
  return v;
}

const issuer = env('MOON_SSO_ISSUER', 'https://sso.moonl.cloud');
const clientId = env('MOON_SSO_CLIENT_ID');
const port = Number(process.env['PORT'] ?? 3000);

const client = new MoonSsoClient({
  issuer,
  clientId,
  clientSecret: env('MOON_SSO_CLIENT_SECRET'),
  redirectUri: env('MOON_SSO_REDIRECT_URI', `http://127.0.0.1:${port}/auth/callback`),
  postLogoutRedirectUri: process.env['MOON_SSO_POST_LOGOUT_URI'] ?? `http://127.0.0.1:${port}/`,
  scope: 'openid profile offline_access profile:write',
  userAgentSuffix: 'example-bff/1.0',
});

// Replace MemorySessionStore with a Redis/DB implementation of SessionStore in production.
const sessions = new SessionManager({ client, store: new MemorySessionStore() });

const app = express();
app.disable('x-powered-by');

// Webhooks need the raw body for signature verification: mount before other body parsers.
const webhookSecret = process.env['MOON_SSO_WEBHOOK_SECRET'];
if (webhookSecret) {
  const lastVersion = new Map<string, number>();
  app.post(
    '/webhooks/moon-sso',
    express.raw({ type: '*/*', limit: '1mb' }),
    createWebhookHandler({
      secret: webhookSecret,
      onEvent: (event) => {
        // Drop stale events by profile_version (deliveries may be retried).
        const prev = lastVersion.get(event.data.sub) ?? -1;
        if (event.data.profile_version < prev) {
          return;
        }
        lastVersion.set(event.data.sub, event.data.profile_version);
        console.log(`webhook ${event.type} for ${event.data.sub} (v${event.data.profile_version})`);
      },
      onError: (e) => console.warn('webhook rejected:', e instanceof MoonSsoError ? e.error : 'error'),
    }),
  );
}

// Login, callback, logout and back-channel logout routes + req.moonSso.
app.use(
  moonSsoMiddleware({
    client,
    sessions,
    routes: { login: '/auth/login', logout: '/auth/logout', backchannel: '/auth/backchannel-logout' },
    backchannel: {
      verifier: new BackchannelLogoutVerifier({ issuer, clientId, jwks: client.jwks }),
      onLogout: (sub, sid) => console.log(`back-channel logout sub=${sub ?? '-'} sid=${sid ?? '-'}`),
    },
  }),
);

const ctx = (req: Request) => (req as unknown as RequestWithMoonSso).moonSso;

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] ?? c);
}

app.get('/', (req, res) => {
  const c = ctx(req);
  const body = c.isAuthenticated
    ? `<p>Hello ${escapeHtml(String(c.user?.name ?? c.user?.preferred_username ?? ''))}</p>
       <p><a href="/app/profile">Profile (JSON)</a></p>
       <form hx-post="/app/nickname" hx-target="#msg"><input name="nickname"><button>Save nickname</button></form>
       <div id="msg"></div>
       <form method="post" action="/auth/logout"><button>Sign out</button></form>`
    : `<a href="/auth/login?returnTo=%2F">Sign in with Moon SSO</a>`;
  res.type('html').send(`<!doctype html><meta charset="utf-8"><script src="https://unpkg.com/htmx.org@2.0.4"></script>${body}`);
});

app.get('/app/profile', requireLogin(), async (req, res, next) => {
  try {
    res.json(await ctx(req).account().getMe());
  } catch (e) {
    next(e);
  }
});

app.post('/app/nickname', requireLogin(), express.urlencoded({ extended: false }), async (req, res, next) => {
  try {
    const nickname = String((req.body as Record<string, unknown>)['nickname'] ?? '').trim();
    const p = await ctx(req).account().updateProfile({ displayName: nickname });
    res.type('html').send(`Saved: ${escapeHtml(p.nickname)}`);
  } catch (e) {
    if (e instanceof MoonSsoError && e.status === 422) {
      res.status(422).type('html').send(escapeHtml(e.error_description ?? 'invalid'));
      return;
    }
    next(e);
  }
});

app.use((err: unknown, req: Request, res: Response, _next: NextFunction) => {
  if (err instanceof MoonSsoError && (err.error === 'login_required' || err.error === 'invalid_grant')) {
    ctx(req).requireLogin();
    return;
  }
  console.error('request failed:', err instanceof MoonSsoError ? `${err.error} ${err.status ?? ''}` : err);
  res.status(500).send('Internal error');
});

app.listen(port, '127.0.0.1', () => {
  console.log(`BFF example on http://127.0.0.1:${port}`);
});

// Confidential web login (test-web) against the testbed: authorization URL,
// /__test/authorize, callback exchange, userinfo, getMe, resource-server
// verification, refresh rotation (incl. concurrent convergence), revocation,
// the (req,res,next) middleware with HTMX and server-side registration.

import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { after, before, test } from 'node:test';
import {
  AccessTokenVerifier,
  MemorySessionStore,
  MoonSsoClient,
  MoonSsoError,
  moonSsoMiddleware,
  type RequestWithMoonSso,
  SessionManager,
  USER_AGENT,
} from '../../dist/index.js';
import { ALICE, randomName, recordingFetch, TEST_WEB, TESTBED, testAuthorize, testbedReachable } from '../../../../test-support/testbed.ts';

const rec = recordingFetch();
const client = new MoonSsoClient({
  issuer: TESTBED,
  clientId: TEST_WEB.clientId,
  clientSecret: TEST_WEB.clientSecret,
  redirectUri: TEST_WEB.redirectUri,
  postLogoutRedirectUri: 'http://127.0.0.1:18700/',
  scope: 'openid profile offline_access',
  fetch: rec.fetch,
});

before(async () => {
  assert.ok(await testbedReachable(), `testbed not reachable at ${TESTBED}`);
});

async function login(username = ALICE.username, password = ALICE.password, scope?: string) {
  const { url, pending } = await client.createAuthorizationUrl(scope ? { scope } : {});
  const { redirect, sessionToken } = await testAuthorize(url, username, password);
  return { tokens: await client.handleCallback(redirect, pending), sessionToken, redirect, pending };
}

test('login, userinfo, getMe and resource-server verification', async () => {
  const { tokens, redirect, pending } = await login();
  assert.ok(tokens.accessToken && tokens.refreshToken && tokens.idToken);
  assert.equal(tokens.claims?.preferred_username, 'alice');
  assert.equal(tokens.claims?.nonce, pending.nonce);
  assert.ok(tokens.expiresAt > Date.now() / 1000);
  const sent = rec.log.find((l) => l.url.endsWith('/oauth/token'));
  assert.equal(sent?.requestHeaders.get('User-Agent'), USER_AGENT);
  assert.match(sent?.requestHeaders.get('Authorization') ?? '', /^Basic /);

  const ui = await client.userinfo(tokens.accessToken);
  assert.equal(ui['sub'], tokens.claims?.sub);
  const me = await client.account(async () => tokens.accessToken).getMe();
  assert.equal(me.preferred_username, 'alice');
  assert.equal(me.sub, tokens.claims?.sub);

  const verifier = new AccessTokenVerifier({ issuer: TESTBED, audience: TEST_WEB.clientId, jwks: client.jwks });
  const claims = await verifier.verify(tokens.accessToken);
  assert.equal(claims.client_id, TEST_WEB.clientId);
  assert.equal(claims.sub, tokens.claims?.sub);
  await assert.rejects(new AccessTokenVerifier({ issuer: TESTBED, audience: 'someone-else', jwks: client.jwks }).verify(tokens.accessToken), /audience/);
  // ID tokens are not access tokens
  await assert.rejects(verifier.verify(tokens.idToken!), /type/);

  // a replayed callback (same code) fails
  await assert.rejects(client.handleCallback(redirect, pending), (e: unknown) => e instanceof MoonSsoError && e.error === 'invalid_grant');
  // state / iss checks
  const forged = new URL(redirect);
  forged.searchParams.set('iss', 'https://evil.example');
  await assert.rejects(client.handleCallback(forged.toString(), pending), (e: unknown) => e instanceof MoonSsoError && e.error === 'invalid_issuer');
  forged.searchParams.set('state', 'x');
  await assert.rejects(client.handleCallback(forged.toString(), pending), (e: unknown) => e instanceof MoonSsoError && e.error === 'invalid_state');
});

test('refresh rotation, grace-window convergence, single-flight and revocation', async () => {
  const { tokens } = await login();
  const r1 = await client.refresh(tokens.refreshToken!, { previous: tokens });
  assert.notEqual(r1.refreshToken, tokens.refreshToken, 'rotated');
  assert.notEqual(r1.accessToken, tokens.accessToken);
  assert.equal(r1.claims?.sub, tokens.claims?.sub);

  // Re-presenting the predecessor inside the 60 s grace window yields the same successor.
  const again = await client.refresh(tokens.refreshToken!, { previous: tokens });
  assert.equal(again.refreshToken, r1.refreshToken);

  // Concurrent raw refreshes of one token (e.g. several processes) converge.
  const many = await Promise.all(Array.from({ length: 5 }, () => client.refresh(r1.refreshToken!, { previous: r1 })));
  assert.equal(new Set(many.map((m) => m.refreshToken)).size, 1, 'all callers got the same successor');

  // SessionManager: 10 concurrent forced refreshes → one token request.
  const sessions = new SessionManager({ client, store: new MemorySessionStore() });
  await sessions.save('s1', { tokens: many[0]!, ...(many[0]!.claims ? { user: many[0]!.claims } : {}), createdAt: Date.now(), updatedAt: Date.now() });
  const before = rec.log.filter((l) => l.url.endsWith('/oauth/token')).length;
  const ats = await Promise.all(Array.from({ length: 10 }, () => sessions.getAccessToken('s1', { force: true })));
  assert.equal(new Set(ats).size, 1);
  assert.equal(rec.log.filter((l) => l.url.endsWith('/oauth/token')).length - before, 1);
  const me = await sessions.account('s1').getMe();
  assert.equal(me.preferred_username, 'alice');

  // Revocation kills the family: refresh → invalid_grant, session removed.
  const current = (await sessions.get('s1'))!.tokens!;
  assert.equal(await client.revoke(current.refreshToken!), true);
  await assert.rejects(sessions.getAccessToken('s1', { force: true }), (e: unknown) => e instanceof MoonSsoError && e.error === 'invalid_grant' && e.isSessionExpired);
  assert.equal(await sessions.get('s1'), undefined);
});

test('middleware: login → callback → protected route → HTMX → logout', async () => {
  const store = new MemorySessionStore();
  const mw = moonSsoMiddleware({ client, sessions: store, requireAuth: (req) => (req.url ?? '').startsWith('/private') });
  const server: Server = createServer((req, res) => {
    mw(req, res, async (err?: unknown) => {
      if (err) {
        res.statusCode = 500;
        res.end(String(err));
        return;
      }
      const ctx = (req as RequestWithMoonSso).moonSso;
      if (req.url === '/private/me') {
        const me = await ctx.account().getMe();
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ username: me.preferred_username, sub: ctx.user?.sub }));
        return;
      }
      res.end(ctx.isAuthenticated ? 'in' : 'out');
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  try {
    // unauthenticated: browser → 302 to login route; HTMX → 200 + HX-Redirect; API → 401 JSON
    const r302 = await fetch(`${base}/private/me`, { redirect: 'manual', headers: { Accept: 'text/html' } });
    assert.equal(r302.status, 302);
    assert.equal(r302.headers.get('location'), '/auth/login?returnTo=%2Fprivate%2Fme');
    const hx = await fetch(`${base}/private/me`, { redirect: 'manual', headers: { 'HX-Request': 'true', 'HX-Current-URL': `${base}/private/page?x=1` } });
    assert.equal(hx.status, 200);
    assert.equal(hx.headers.get('hx-redirect'), '/auth/login?returnTo=%2Fprivate%2Fpage%3Fx%3D1');
    const api = await fetch(`${base}/private/me`, { headers: { Accept: 'application/json' } });
    assert.equal(api.status, 401);

    // login route → authorization URL + pre-auth session cookie
    const start = await fetch(`${base}/auth/login?returnTo=%2Fprivate%2Fme`, { redirect: 'manual' });
    assert.equal(start.status, 302);
    const cookie1 = (start.headers.getSetCookie()[0] ?? '').split(';')[0]!;
    assert.match(cookie1, /^moon_sso=/);
    assert.match(start.headers.getSetCookie()[0] ?? '', /HttpOnly/);
    const authorizeUrl = start.headers.get('location')!;
    assert.ok(authorizeUrl.startsWith(`${TESTBED}/oauth/authorize?`));

    // the IdP sends the browser to the registered callback; replay it on our test server
    const { redirect } = await testAuthorize(authorizeUrl, ALICE.username, ALICE.password);
    const cb = new URL(redirect);
    const done = await fetch(`${base}${cb.pathname}${cb.search}`, { redirect: 'manual', headers: { Cookie: cookie1 } });
    assert.equal(done.status, 302, await done.clone().text());
    assert.equal(done.headers.get('location'), '/private/me');
    const cookie2 = (done.headers.getSetCookie()[0] ?? '').split(';')[0]!;
    assert.notEqual(cookie2, cookie1, 'session id rotated after login');

    const me = await fetch(`${base}/private/me`, { headers: { Cookie: cookie2 } });
    assert.equal(me.status, 200);
    assert.equal(((await me.json()) as { username: string }).username, 'alice');
    assert.equal(await (await fetch(`${base}/`, { headers: { Cookie: cookie1 } })).text(), 'out', 'old session id is dead');

    // logout → end_session redirect with id_token_hint, cookie cleared, session gone
    const out = await fetch(`${base}/auth/logout`, { method: 'POST', redirect: 'manual', headers: { Cookie: cookie2 } });
    assert.equal(out.status, 302);
    const end = new URL(out.headers.get('location')!);
    assert.equal(end.pathname, '/oauth/end_session');
    assert.ok(end.searchParams.get('id_token_hint'));
    assert.match(out.headers.getSetCookie()[0] ?? '', /Max-Age=0/);
    assert.equal(await (await fetch(`${base}/`, { headers: { Cookie: cookie2 } })).text(), 'out');
  } finally {
    server.closeAllConnections();
    server.close();
  }
});

test('server-side registration API and registration info', async () => {
  const info = await client.registrationInfo();
  assert.equal(typeof info.registration_open, 'boolean');
  const username = randomName();
  const password = `Ts-Api-Reg-${Date.now()}`;
  const r = await client.registerUser({ username, password, displayName: 'API Reg' });
  assert.equal(r.created, true);
  assert.equal(r.username, username);
  const { tokens } = await login(username, password);
  assert.equal(tokens.claims?.preferred_username, username);
  await assert.rejects(client.registerUser({ username, password }), (e: unknown) => e instanceof MoonSsoError && e.status === 422 && e.field === 'username');
});

after(() => undefined);

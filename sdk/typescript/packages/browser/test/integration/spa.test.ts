// Browser SDK against the testbed (run in Node with in-memory storage):
// PKCE + DPoP redirect login with test-spa, use_dpop_nonce, refresh rotation,
// multi-tab single-flight, DPoP binding and logout.

import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { DPoP, InProcessLockProvider, MemoryStore, MoonSso, MoonSsoError, type TabChannel } from '../../dist/index.js';
import { ALICE, recordingFetch, TEST_SPA, TESTBED, testAuthorize, testbedReachable } from '../../../../test-support/testbed.ts';

class Hub {
  private readonly subs = new Set<(m: unknown) => void>();
  channel(): TabChannel {
    const mine = new Set<(m: unknown) => void>();
    return {
      post: (m) => {
        for (const fn of this.subs) {
          if (!mine.has(fn)) {
            fn(structuredClone(m));
          }
        }
      },
      subscribe: (fn) => {
        mine.add(fn);
        this.subs.add(fn);
        return () => {
          mine.delete(fn);
          this.subs.delete(fn);
        };
      },
      close: () => {
        for (const fn of mine) {
          this.subs.delete(fn);
        }
      },
    };
  }
}

const rec = recordingFetch();
const store = new MemoryStore();
const locks = new InProcessLockProvider();
const hub = new Hub();
let navigated = '';
const clients: MoonSso[] = [];

function newTab(): MoonSso {
  const c = new MoonSso({
    issuer: TESTBED,
    clientId: TEST_SPA.clientId,
    redirectUri: TEST_SPA.redirectUri,
    postLogoutRedirectUri: TEST_SPA.redirectUri,
    scope: 'openid profile offline_access',
    storage: store,
    locks,
    channel: hub.channel(),
    fetch: rec.fetch,
    navigate: (u) => {
      navigated = u;
    },
  });
  clients.push(c);
  return c;
}

before(async () => {
  assert.ok(await testbedReachable(), `testbed not reachable at ${TESTBED}`);
});

after(async () => {
  for (const c of clients) {
    await c.close();
  }
});

const tokenPosts = () => rec.log.filter((l) => l.method === 'POST' && l.url.endsWith('/oauth/token'));

test('redirect login with PKCE + DPoP (test-spa), use_dpop_nonce, getMe, rotation, multi-tab, binding, logout', async (t) => {
  const tabA = newTab();
  await tabA.init();

  await t.test('login', async () => {
    await tabA.login({ returnTo: '/dashboard' });
    const authUrl = new URL(navigated);
    assert.equal(authUrl.origin + authUrl.pathname, `${TESTBED}/oauth/authorize`);
    for (const p of ['state', 'nonce', 'code_challenge', 'dpop_jkt']) {
      assert.ok(authUrl.searchParams.get(p), `authorization request has ${p}`);
    }
    assert.equal(authUrl.searchParams.get('code_challenge_method'), 'S256');
    const { redirect } = await testAuthorize(navigated, ALICE.username, ALICE.password);
    assert.ok(tabA.isRedirectCallback(redirect));
    assert.ok(new URL(redirect).searchParams.get('iss'), 'RFC 9207 iss in the response');

    const result = await tabA.handleRedirectCallback(redirect);
    assert.equal(result.returnTo, '/dashboard');
    assert.equal(result.user?.aud, TEST_SPA.clientId);
    assert.equal(result.user?.preferred_username, 'alice');
    assert.equal(tabA.isAuthenticated, true);

    const tp = tokenPosts();
    assert.ok(tp.every((l) => l.requestHeaders.get('DPoP')), 'every token request carries a DPoP proof');
    assert.ok(tp.some((l) => l.status === 400 && l.error === 'use_dpop_nonce'), 'server demanded a nonce');
    assert.equal(tp.at(-1)?.status, 200);
    // the code cannot be replayed
    await assert.rejects(tabA.handleRedirectCallback(redirect), (e: unknown) => e instanceof MoonSsoError && e.error === 'invalid_state');
  });

  await t.test('account API and userinfo', async () => {
    const me = await tabA.getMe();
    assert.equal(me.preferred_username, 'alice');
    assert.equal(me.sub, tabA.user?.sub);
    assert.equal(typeof me.profile_version, 'number');
    const ui = await tabA.userinfo();
    assert.equal(ui['sub'], me.sub);
  });

  await t.test('refresh rotation with DPoP', async () => {
    const rt0 = tabA.tokens.currentSession!.refreshToken;
    const at0 = await tabA.getAccessToken();
    const at1 = await tabA.getAccessToken({ force: true });
    assert.notEqual(at1, at0);
    const rt1 = tabA.tokens.currentSession!.refreshToken;
    assert.notEqual(rt1, rt0, 'refresh token rotated and persisted');
    assert.equal((await store.get<{ refreshToken: string }>(`moon-sso:${TEST_SPA.clientId}:session`))?.refreshToken, rt1);
  });

  await t.test('two tabs refreshing at once make one token request', async () => {
    const tabB = newTab();
    await tabB.init();
    assert.equal(tabB.isAuthenticated, true, 'tab B restored the persisted session');
    const before = tokenPosts().filter((l) => l.status === 200).length;
    const [a, b] = await Promise.all([tabA.getAccessToken({ force: true }), tabB.getAccessToken()]);
    assert.equal(a, b);
    assert.equal(tokenPosts().filter((l) => l.status === 200).length - before, 1);
    const me = await tabB.getMe();
    assert.equal(me.preferred_username, 'alice');
  });

  await t.test('stolen refresh token is useless without the DPoP key', async () => {
    const rt = tabA.tokens.currentSession!.refreshToken;
    const thief = await DPoP.generate();
    const tokenUrl = `${TESTBED}/oauth/token`;
    let res: Response | undefined;
    for (let i = 0; i < 2; i++) {
      res = await fetch(tokenUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', DPoP: await thief.proof('POST', tokenUrl) },
        body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: rt, client_id: TEST_SPA.clientId }).toString(),
      });
      thief.captureNonce(tokenUrl, res);
      const body = (await res.clone().json()) as { error?: string };
      if (body.error !== 'use_dpop_nonce') {
        break;
      }
    }
    assert.equal(res?.status, 400);
    assert.equal(((await res!.json()) as { error: string }).error, 'invalid_dpop_proof');
    // the legitimate holder still works
    assert.ok(await tabA.getAccessToken({ force: true }));
  });

  await t.test('logout revokes the refresh token and builds the end-session URL', async () => {
    const rt = tabA.tokens.currentSession!.refreshToken;
    const loggedOut: string[] = [];
    clients[1]?.on('logout', () => loggedOut.push('B'));
    await tabA.logout({ endSession: true, state: 'bye' });
    assert.equal(tabA.isAuthenticated, false);
    assert.deepEqual(loggedOut, ['B'], 'other tab notified');
    const end = new URL(navigated);
    assert.equal(end.pathname, '/oauth/end_session');
    assert.ok(end.searchParams.get('id_token_hint'));
    assert.equal(end.searchParams.get('post_logout_redirect_uri'), TEST_SPA.redirectUri);
    assert.equal(end.searchParams.get('state'), 'bye');
    // a revoked token is dead even for the right key
    const dpop = await tabA.tokens.getDPoP();
    const tokenUrl = `${TESTBED}/oauth/token`;
    let body: { error?: string } = {};
    for (let i = 0; i < 2; i++) {
      const res = await fetch(tokenUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', DPoP: await dpop.proof('POST', tokenUrl) },
        body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: rt, client_id: TEST_SPA.clientId }).toString(),
      });
      dpop.captureNonce(tokenUrl, res);
      body = (await res.json()) as { error?: string };
      if (body.error !== 'use_dpop_nonce') {
        break;
      }
    }
    assert.equal(body.error, 'invalid_grant');
    await assert.rejects(tabA.getAccessToken(), (e: unknown) => e instanceof MoonSsoError && e.error === 'login_required');
  });
});

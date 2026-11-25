// Changes feed with client_credentials on test-web, Standard Webhooks
// delivery and back-channel logout to our own DCR-registered client.

import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import {
  BackchannelLogoutVerifier,
  createBackchannelLogoutHandler,
  createWebhookHandler,
  type LogoutTokenClaims,
  MemorySessionStore,
  type MoonEvent,
  MoonSsoClient,
  registerClient,
  SessionManager,
  WebhookVerifier,
} from '../../dist/index.js';
import {
  createUser,
  endSsoSession,
  initialAccessToken,
  type Receiver,
  setBackchannel,
  setDisplayNameServerSide,
  setWebhook,
  startReceiver,
  TEST_WEB,
  TESTBED,
  testAuthorize,
  testbedReachable,
  trustClient,
  until,
} from '../../../../test-support/testbed.ts';

const receivers: Receiver[] = [];

before(async () => {
  assert.ok(await testbedReachable(), `testbed not reachable at ${TESTBED}`);
});

after(async () => {
  for (const r of receivers) {
    await r.close();
  }
});

const testWeb = new MoonSsoClient({
  issuer: TESTBED,
  clientId: TEST_WEB.clientId,
  clientSecret: TEST_WEB.clientSecret,
  redirectUri: TEST_WEB.redirectUri,
});

async function loginWith(client: MoonSsoClient, username: string, password: string) {
  const { url, pending } = await client.createAuthorizationUrl();
  const { redirect, sessionToken } = await testAuthorize(url, username, password);
  return { tokens: await client.handleCallback(redirect, pending), sessionToken };
}

test('changes feed (client_credentials, users:sync): snapshot watermark, then the event of a fresh user', { timeout: 120_000 }, async () => {
  const feed = testWeb.changesFeed();
  // snapshot: first page's watermark is where we continue
  const snap = feed.fullSync({ limit: 50 });
  const first = await snap.next();
  assert.equal(first.done, false);
  const watermark = first.done ? '' : first.value.watermark;
  assert.match(watermark, /^\d+$/);
  await snap.return('');

  const user = await createUser();
  const { tokens } = await loginWith(testWeb, user.username, user.password);
  const sub = tokens.claims!.sub;
  await setDisplayNameServerSide(user.username, 'Feed Name');

  let cursor = watermark;
  let found: MoonEvent | undefined;
  const deadline = Date.now() + 30_000;
  while (!found && Date.now() < deadline) {
    for await (const item of feed.changes(cursor, { limit: 200 })) {
      if (item.kind === 'events') {
        found ??= item.events.find((e) => e.data.sub === sub && e.type === 'user.updated' && e.data.nickname === 'Feed Name');
        cursor = item.cursor;
      } else {
        cursor = item.watermark;
      }
    }
    if (!found) {
      await new Promise((r) => setTimeout(r, 500));
    }
  }
  assert.ok(found, 'event for the fresh user arrived in the feed');
  assert.equal(found.data.preferred_username, user.username);
  assert.ok(Number(cursor) >= found.seq);
  assert.equal(testWeb.clientCredentials().requestCount, 1, 'client_credentials token reused');

  // the user also shows up in the snapshot
  let inSnapshot = false;
  for await (const page of feed.fullSync({ limit: 500 })) {
    inSnapshot ||= page.users.some((u) => u.sub === sub);
  }
  assert.ok(inSnapshot);
});

test('webhooks and back-channel logout to an own DCR client', { timeout: 120_000 }, async (t) => {
  const reg = await registerClient({
    issuer: TESTBED,
    initialAccessToken: await initialAccessToken(),
    metadata: {
      client_name: `ts-sdk-test-${Date.now()}`,
      redirect_uris: ['http://127.0.0.1:18799/callback'],
      token_endpoint_auth_method: 'client_secret_basic',
      application_type: 'web',
      grant_types: ['authorization_code', 'refresh_token'],
      scope: 'openid profile offline_access',
    },
  });
  assert.equal(reg.status, 'active');
  assert.ok(reg.client_secret && reg.registration_access_token);
  await trustClient(reg.client_id);
  const client = new MoonSsoClient({ issuer: TESTBED, clientId: reg.client_id, clientSecret: reg.client_secret!, redirectUri: 'http://127.0.0.1:18799/callback' });

  await t.test('webhook delivery verified with the Standard Webhooks verifier', async () => {
    const events: MoonEvent[] = [];
    let secret = '';
    let verifier: WebhookVerifier | undefined;
    const hook = await startReceiver(async (req, res, rec) => {
      if (!verifier) {
        res.statusCode = 503;
        res.end();
        return;
      }
      const handler = createWebhookHandler({ verifier, onEvent: (ev) => void events.push(ev) });
      // the receiver already consumed the stream; hand the raw bytes over
      (req as unknown as { rawBody: Buffer }).rawBody = rec.body;
      await handler(req, res);
    });
    receivers.push(hook);
    secret = await setWebhook(reg.client_id, `${hook.url}/webhook`);
    assert.match(secret, /^whsec_/);
    verifier = new WebhookVerifier(secret);

    const user = await createUser();
    const { tokens } = await loginWith(client, user.username, user.password);
    await setDisplayNameServerSide(user.username, 'Hooked Name');
    const ev = await until(() => events.find((e) => e.data.sub === tokens.claims!.sub && e.data.nickname === 'Hooked Name'), 40_000);
    assert.equal(ev.type, 'user.updated');
    assert.equal(ev.data.preferred_username, user.username);
    // independently re-verify the recorded raw delivery
    const raw = hook.requests.find((r) => r.body.toString().includes('Hooked Name'))!;
    const msg = await new WebhookVerifier(secret).verify(raw.headers, raw.body);
    assert.equal(msg.id, raw.headers['webhook-id']);
    await assert.rejects(new WebhookVerifier(secret).verify(raw.headers, Buffer.concat([raw.body, Buffer.from(' ')])), /no matching signature/);
  });

  await t.test('back-channel logout token verified; session store cleared by sid', async () => {
    const verifier = new BackchannelLogoutVerifier({ issuer: TESTBED, clientId: reg.client_id, jwks: client.jwks });
    const logouts: { sub: string | undefined; sid: string | undefined; claims: LogoutTokenClaims }[] = [];
    const store = new MemorySessionStore();
    const handler = createBackchannelLogoutHandler({
      verifier,
      onLogout: async (sub, sid, claims) => {
        logouts.push({ sub, sid, claims });
        if (sid) {
          await store.deleteBySid(sid);
        }
      },
    });
    const bc = await startReceiver(async (req, res, rec) => {
      (req as unknown as { rawBody: Buffer }).rawBody = rec.body;
      await handler(req, res);
    });
    receivers.push(bc);
    await setBackchannel(reg.client_id, `${bc.url}/backchannel`);

    const user = await createUser();
    const { tokens, sessionToken } = await loginWith(client, user.username, user.password);
    const sid = tokens.claims?.sid;
    assert.ok(sid, 'ID token carries sid');
    const sessions = new SessionManager({ client, store });
    await sessions.save('app-session', { tokens, user: tokens.claims!, createdAt: Date.now(), updatedAt: Date.now() });

    await endSsoSession(sessionToken);
    const got = await until(() => logouts.find((l) => l.sid === sid), 40_000);
    assert.equal(got.sub, tokens.claims!.sub);
    assert.equal(got.claims.iss, TESTBED);
    assert.equal(await store.get('app-session'), undefined, 'application session destroyed');
    const delivery = bc.requests.find((r) => r.body.toString().startsWith('logout_token='))!;
    // replaying the same token is rejected (jti cache)
    const token = new URLSearchParams(delivery.body.toString()).get('logout_token')!;
    await assert.rejects(verifier.verify(token), /replayed/);
  });
});

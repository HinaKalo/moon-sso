// First-party in-app login (authorize-challenge) with TOTP (bob, test-native-dpop),
// in-app registration, profile writes and live SSE events.

import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { InProcessLockProvider, MemoryStore, MoonSso, MoonSsoError, OtpRequiredError, type Profile } from '../../dist/index.js';
import {
  BOB,
  createUser,
  makePng,
  randomName,
  recordingFetch,
  setDisplayNameServerSide,
  TESTBED,
  testbedReachable,
  totp,
  until,
} from '../../../../test-support/testbed.ts';

const clients: MoonSso[] = [];

function app(clientId: string, scope = 'openid profile offline_access', fetchImpl?: typeof fetch): MoonSso {
  const c = new MoonSso({
    issuer: TESTBED,
    clientId,
    scope,
    storage: new MemoryStore(),
    locks: new InProcessLockProvider(),
    channel: null,
    ...(fetchImpl ? { fetch: fetchImpl } : {}),
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

/** Submits the current TOTP; bob is shared with other suites, so a code may already be spent in this 30 s window. */
async function submitTotp(c: MoonSso, authSession: string): Promise<void> {
  const deadline = Date.now() + 100_000;
  let session = authSession;
  for (;;) {
    try {
      await c.verifyOtp(session, await totp(BOB.totpSecret));
      return;
    } catch (e) {
      if (Date.now() > deadline) {
        throw e;
      }
      if (e instanceof OtpRequiredError) {
        session = e.authSession;
        await new Promise((r) => setTimeout(r, 31_000 - (Date.now() % 30_000)));
        continue;
      }
      if (e instanceof MoonSsoError && e.status === 429) {
        await new Promise((r) => setTimeout(r, 2_000));
        continue;
      }
      throw e;
    }
  }
}

test('in-app login with OTP (bob, test-native-dpop)', { timeout: 150_000 }, async () => {
  const rec = recordingFetch();
  const c = app('test-native-dpop', 'openid profile offline_access', rec.fetch);
  await c.init();
  let otpErr: OtpRequiredError | undefined;
  try {
    await c.signIn(BOB.username, BOB.password);
    assert.fail('expected OtpRequiredError');
  } catch (e) {
    assert.ok(e instanceof OtpRequiredError, `got ${String(e)}`);
    otpErr = e;
  }
  assert.equal(otpErr.required, 'otp');
  assert.equal(otpErr.error, 'insufficient_authorization');
  assert.equal(otpErr.status, 400);
  const challengeCalls = rec.log.filter((l) => l.url.endsWith('/oauth/authorize-challenge'));
  assert.ok(challengeCalls.every((l) => l.requestHeaders.get('DPoP')), 'challenge requests carry DPoP proofs');

  // a wrong code keeps the challenge alive
  await assert.rejects(c.verifyOtp(otpErr.authSession, '000000'), (e: unknown) => (e instanceof OtpRequiredError) || (e instanceof MoonSsoError && e.status === 429));
  await submitTotp(c, otpErr.authSession);
  assert.equal(c.isAuthenticated, true);
  assert.equal(c.user?.preferred_username, 'bob');
  assert.ok(c.user?.amr?.includes('otp'), 'amr includes otp');
  const me = await c.getMe();
  assert.equal(me.preferred_username, 'bob');
  assert.equal(me.totp_enabled, true);
  // the redeemed code was exchanged without redirect_uri and with DPoP
  const tokenCalls = rec.log.filter((l) => l.url.endsWith('/oauth/token'));
  assert.ok(tokenCalls.every((l) => l.requestHeaders.get('DPoP')));
  await c.logout();
});

test('wrong password and unknown auth_session errors', async () => {
  const c = app('test-native-dpop');
  await assert.rejects(c.signIn(BOB.username, 'not-the-password'), (e: unknown) => e instanceof MoonSsoError && e.error === 'access_denied' && e.status === 403);
  await assert.rejects(c.verifyOtp('nope', '123456'), (e: unknown) => e instanceof MoonSsoError && e.error === 'invalid_request');
});

test('in-app registration (test-spa), profile writes, avatar and live SSE events', { timeout: 120_000 }, async () => {
  const c = app('test-spa', 'openid profile offline_access profile:write password:write');
  const username = randomName();
  const password = `Ts-Reg-${Date.now()}-x`;
  const reg = await c.register({ username, password, displayName: 'Reg User' });
  assert.equal(reg.user?.preferred_username, username);

  // validation errors carry the field (422)
  await assert.rejects(
    app('test-spa').register({ username: '!', password: 'x' }),
    (e: unknown) => e instanceof MoonSsoError && e.status === 422 && typeof e.field === 'string',
  );

  const changes: Profile[] = [];
  c.on('profileChanged', (p) => changes.push(p));
  const connected = new Promise<void>((resolve) => c.on('eventsConnected', () => resolve()));
  await c.startEvents();
  await connected;

  // server-side change arrives over SSE
  await setDisplayNameServerSide(username, 'Live Name 1');
  const live = await until(() => changes.find((p) => p.nickname === 'Live Name 1'), 20_000);
  assert.equal(live.preferred_username, username);
  assert.ok(c.lastEventId, 'Last-Event-ID tracked');

  // SDK write: local cache updated immediately and the event echoes back
  const before = c.profile?.profile_version ?? 0;
  const p = await c.updateProfile({ displayName: 'Written By SDK' });
  assert.equal(p.nickname, 'Written By SDK');
  assert.ok(p.profile_version > before);
  await until(() => changes.find((x) => x.nickname === 'Written By SDK' && x.profile_version === p.profile_version), 20_000);

  const withAvatar = await c.uploadAvatar(makePng(32, 32), 'image/png');
  assert.ok(withAvatar.picture, 'avatar URL set');
  const noAvatar = await c.deleteAvatar();
  assert.equal(noAvatar.picture, null);

  // password change keeps this device signed in
  await c.changePassword({ currentPassword: password, newPassword: `${password}-new` });
  await new Promise((r) => setTimeout(r, 500));
  assert.ok(await c.getAccessToken({ force: true }), 'refresh still works after own password change');
  assert.equal(c.isAuthenticated, true);
  await c.stopEvents();
});

test('another device changing the password expires this session (sessionExpired)', { timeout: 60_000 }, async () => {
  const user = await createUser();
  const victim = app('test-native', 'openid profile offline_access');
  await victim.signIn(user.username, user.password);
  const other = app('test-native', 'openid profile offline_access password:write');
  await other.signIn(user.username, user.password);
  const expired: MoonSsoError[] = [];
  victim.on('sessionExpired', (e) => expired.push(e));
  const connected = new Promise<void>((resolve) => victim.on('eventsConnected', () => resolve()));
  await victim.startEvents();
  await connected;
  await other.changePassword({ currentPassword: user.password, newPassword: `${user.password}-2` });
  await until(() => (expired.length > 0 ? true : undefined), 20_000);
  assert.equal(victim.isAuthenticated, false);
  assert.equal(other.isAuthenticated, true);
});

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { BACKCHANNEL_LOGOUT_EVENT, BackchannelLogoutVerifier, MoonSsoError } from '../../dist/index.js';
import { ISSUER, makeKey, nowS, scriptedFetch, signJwt } from '../../../../test-support/keys.ts';

async function setup() {
  const key = await makeKey('RS256', 'bcl');
  const sf = scriptedFetch(() => [key]);
  const verifier = new BackchannelLogoutVerifier({ issuer: ISSUER, clientId: 'app', fetch: sf.fetch });
  const now = nowS();
  const base = {
    iss: ISSUER,
    aud: 'app',
    iat: now,
    exp: now + 120,
    jti: `j-${Math.random()}`,
    sub: 'user-1',
    sid: 'sid-1',
    events: { [BACKCHANNEL_LOGOUT_EVENT]: {} },
  };
  const sign = (claims: Record<string, unknown>, typ = 'logout+jwt') => signJwt(key, claims, { typ });
  return { verifier, base, sign, key };
}

test('accepts a valid logout token and returns sub and sid', async () => {
  const { verifier, base, sign } = await setup();
  const c = await verifier.verify(await sign(base));
  assert.equal(c.sub, 'user-1');
  assert.equal(c.sid, 'sid-1');
  // sid alone or sub alone is enough
  await verifier.verify(await sign({ ...base, jti: 'a1', sub: undefined }));
  await verifier.verify(await sign({ ...base, jti: 'a2', sid: undefined }));
  // aud as array
  await verifier.verify(await sign({ ...base, jti: 'a3', aud: ['other', 'app'] }));
});

test('enforces every check of sdk-spec §5.3', async () => {
  const { verifier, base, sign } = await setup();
  const now = nowS();
  const cases: [string, Promise<string>, RegExp][] = [
    ['typ', sign({ ...base, jti: 'c1' }, 'JWT'), /unexpected token type/],
    ['iss', sign({ ...base, jti: 'c2', iss: 'https://evil' }), /iss/],
    ['aud', sign({ ...base, jti: 'c3', aud: 'other' }), /aud/],
    ['iat future', sign({ ...base, jti: 'c4', iat: now + 300 }), /iat/],
    ['iat missing', sign({ ...base, jti: 'c5', iat: undefined }), /iat/],
    ['exp', sign({ ...base, jti: 'c6', exp: now - 120 }), /expired/],
    ['events', sign({ ...base, jti: 'c7', events: { 'http://other': {} } }), /events/],
    ['events missing', sign({ ...base, jti: 'c8', events: undefined }), /events/],
    ['sub/sid', sign({ ...base, jti: 'c9', sub: undefined, sid: undefined }), /sub nor sid/],
    ['nonce', sign({ ...base, jti: 'c10', nonce: 'n' }), /nonce/],
    ['jti missing', sign({ ...base, jti: undefined }), /jti/],
  ];
  for (const [name, tok, re] of cases) {
    await assert.rejects(verifier.verify(await tok), (e: unknown) => e instanceof MoonSsoError && re.test(e.message), name);
  }
});

test('jti replay is rejected within the window', async () => {
  const { verifier, base, sign } = await setup();
  const tok = await sign({ ...base, jti: 'replay-1' });
  await verifier.verify(tok);
  await assert.rejects(verifier.verify(tok), /replayed/);
  // a token that failed validation must not poison the jti cache
  await assert.rejects(verifier.verify(await sign({ ...base, jti: 'later-ok', nonce: 'x' })), /nonce/);
  await verifier.verify(await sign({ ...base, jti: 'later-ok' }));
});

test('signature by an unknown key is rejected', async () => {
  const { verifier, base } = await setup();
  const rogue = await makeKey('RS256', 'bcl');
  await assert.rejects(verifier.verify(await signJwt(rogue, base, { typ: 'logout+jwt' })), /signature/);
});

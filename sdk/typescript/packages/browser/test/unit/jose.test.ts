import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { HttpClient, JwksCache, MoonSsoError, validateIdToken, verifyJwt } from '../../dist/index.js';
import { ISSUER, makeKey, nowS, scriptedFetch, signJwt, type TestKey } from '../../../../test-support/keys.ts';

function cacheFor(keys: () => TestKey[], now?: () => number) {
  const sf = scriptedFetch(keys);
  const http = new HttpClient({ fetch: sf.fetch });
  const jwks = new JwksCache({ http, jwksUri: async () => `${ISSUER}/.well-known/jwks.json`, ...(now ? { now } : {}) });
  return { sf, jwks };
}

test('verifies RS256 and ES256 signatures', async () => {
  const rsa = await makeKey('RS256', 'r1');
  const ec = await makeKey('ES256', 'e1');
  const { jwks } = cacheFor(() => [rsa, ec]);
  for (const k of [rsa, ec]) {
    const tok = await signJwt(k, { iss: ISSUER, sub: 'u' }, { typ: 'JWT' });
    const out = await verifyJwt(tok, jwks);
    assert.equal(out.payload['sub'], 'u');
    assert.equal(out.header.alg, k.alg);
  }
});

test('rejects tampered payloads, alg none and wrong typ', async () => {
  const ec = await makeKey('ES256', 'e1');
  const { jwks } = cacheFor(() => [ec]);
  const tok = await signJwt(ec, { sub: 'u' }, { typ: 'at+jwt' });
  const [h, , s] = tok.split('.');
  const forged = `${h}.${Buffer.from(JSON.stringify({ sub: 'admin' })).toString('base64url')}.${s}`;
  await assert.rejects(verifyJwt(forged, jwks), (e: unknown) => e instanceof MoonSsoError && e.error === 'invalid_token');
  const none = `${Buffer.from(JSON.stringify({ alg: 'none' })).toString('base64url')}.${Buffer.from('{}').toString('base64url')}.AAAA`;
  await assert.rejects(verifyJwt(none, jwks), /unsupported token algorithm/);
  await assert.rejects(verifyJwt(tok, jwks, { typ: 'logout+jwt' }), /unexpected token type/);
  assert.ok(await verifyJwt(tok, jwks, { typ: 'at+jwt' }));
  // an ES256 token must not be accepted with an RS256 key under the same kid
  const rsa = await makeKey('RS256', 'e1');
  const { jwks: j2 } = cacheFor(() => [rsa]);
  await assert.rejects(verifyJwt(tok, j2), /no signing key/);
});

test('JWKS is cached and refetched on unknown kid at most every 30 s', async () => {
  let clock = 1_000_000;
  const k1 = await makeKey('ES256', 'k1');
  const k2 = await makeKey('ES256', 'k2');
  let published = [k1];
  const { sf, jwks } = cacheFor(() => published, () => clock);
  const t1 = await signJwt(k1, { a: 1 });
  const t2 = await signJwt(k2, { a: 2 });
  await verifyJwt(t1, jwks);
  await verifyJwt(t1, jwks);
  assert.equal(sf.count('/.well-known/jwks.json'), 1);
  // unknown kid within 30 s of the last fetch: no refetch
  clock += 10_000;
  await assert.rejects(verifyJwt(t2, jwks), /no signing key with kid k2/);
  assert.equal(sf.count('/.well-known/jwks.json'), 1);
  // after 30 s an unknown kid triggers one refetch (key rotation)
  published = [k1, k2];
  clock += 25_000;
  await verifyJwt(t2, jwks);
  assert.equal(sf.count('/.well-known/jwks.json'), 2);
  // TTL expiry (1 h) refetches
  clock += 3_600_001;
  await verifyJwt(t1, jwks);
  assert.equal(sf.count('/.well-known/jwks.json'), 3);
});

test('stale JWKS is used when refetch fails', async () => {
  let clock = 0;
  let fail = false;
  const k1 = await makeKey('RS256', 'k1');
  const http = new HttpClient({
    fetch: async (input) => {
      if (fail) {
        throw new TypeError('offline');
      }
      return Response.json({ keys: [k1.jwk] }, { headers: { 'X-Url': String(input) } });
    },
  });
  const jwks = new JwksCache({ http, jwksUri: async () => 'https://x/jwks', now: () => clock });
  const tok = await signJwt(k1, {});
  await verifyJwt(tok, jwks);
  fail = true;
  clock += 7_200_000;
  await verifyJwt(tok, jwks);
});

function atHash(at: string): string {
  return createHash('sha256').update(at).digest().subarray(0, 16).toString('base64url');
}

test('ID token claim validation', async () => {
  const rsa = await makeKey('RS256', 'r1');
  const { jwks } = cacheFor(() => [rsa]);
  const now = nowS();
  const base = { iss: ISSUER, sub: 'user-1', aud: 'app', azp: 'app', iat: now, exp: now + 300, nonce: 'n1', at_hash: atHash('AT') };
  const check = { issuer: ISSUER, clientId: 'app', nonce: 'n1', accessToken: 'AT' };
  const ok = await validateIdToken(await signJwt(rsa, base, { typ: 'JWT' }), jwks, check);
  assert.equal(ok.sub, 'user-1');

  const bad: [Record<string, unknown>, RegExp][] = [
    [{ ...base, iss: 'https://evil' }, /issuer/],
    [{ ...base, aud: 'other', azp: 'other' }, /audience/],
    [{ ...base, aud: ['app', 'other'], azp: 'other' }, /azp/],
    [{ ...base, exp: now - 120 }, /expired/],
    [{ ...base, iat: now + 600 }, /future/],
    [{ ...base, nonce: 'n2' }, /nonce/],
    [{ ...base, at_hash: atHash('OTHER') }, /at_hash/],
    [{ ...base, sub: undefined }, /sub/],
  ];
  for (const [claims, re] of bad) {
    await assert.rejects(validateIdToken(await signJwt(rsa, claims), jwks, check), re);
  }
  // 60 s clock skew is tolerated
  await validateIdToken(await signJwt(rsa, { ...base, exp: now - 30 }), jwks, check);
  // refresh: sub must not change, nonce not required
  await assert.rejects(validateIdToken(await signJwt(rsa, { ...base, nonce: undefined }), jwks, { issuer: ISSUER, clientId: 'app', expectedSub: 'someone-else' }), /sub changed/);
});

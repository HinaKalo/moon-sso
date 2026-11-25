import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { test } from 'node:test';
import { AccessTokenVerifier, MoonSsoError, type RequestWithAuth } from '../../dist/index.js';
import { ISSUER, makeKey, nowS, scriptedFetch, signJwt } from '../../../../test-support/keys.ts';

async function setup() {
  const key = await makeKey('ES256', 'at1');
  const sf = scriptedFetch(() => [key]);
  const verifier = new AccessTokenVerifier({ issuer: ISSUER, audience: ['my-api', 'other-api'], fetch: sf.fetch });
  const now = nowS();
  const base = { iss: ISSUER, sub: 'u1', aud: ['web', 'my-api'], exp: now + 300, iat: now, nbf: now - 5, jti: 'j', client_id: 'web', scope: 'openid profile api:read' };
  const sign = (c: Record<string, unknown>, typ = 'at+jwt') => signJwt(key, c, { typ });
  return { verifier, base, sign, sf };
}

test('accepts a valid access token', async () => {
  const { verifier, base, sign } = await setup();
  const c = await verifier.verify(await sign(base), { scopes: ['api:read'] });
  assert.equal(c.sub, 'u1');
  assert.equal(c.client_id, 'web');
});

test('rejects wrong typ, iss, audience, expiry, nbf and missing scope', async () => {
  const { verifier, base, sign } = await setup();
  const now = nowS();
  const cases: [Promise<string>, string, RegExp][] = [
    [sign(base, 'JWT'), 'invalid_token', /type/],
    [sign({ ...base, iss: 'https://x' }), 'invalid_token', /issuer/],
    [sign({ ...base, aud: ['web'] }), 'invalid_token', /audience/],
    [sign({ ...base, exp: now - 61 }), 'invalid_token', /expired/],
    [sign({ ...base, nbf: now + 120 }), 'invalid_token', /not valid yet/],
  ];
  for (const [tok, code, re] of cases) {
    await assert.rejects(verifier.verify(await tok), (e: unknown) => e instanceof MoonSsoError && e.error === code && re.test(e.message));
  }
  await assert.rejects(verifier.verify(await sign(base), { scopes: ['api:write'] }), (e: unknown) => e instanceof MoonSsoError && e.error === 'insufficient_scope' && e.status === 403);
});

test('middleware: 401 with WWW-Authenticate, 403 on scope, req.auth on success', async () => {
  const { verifier, base, sign } = await setup();
  const mw = verifier.middleware({ scopes: ['api:read'] });
  const server = createServer((req, res) => {
    mw(req, res, (err?: unknown) => {
      if (err) {
        res.statusCode = 500;
        res.end();
        return;
      }
      res.end(JSON.stringify({ sub: (req as RequestWithAuth).auth?.sub }));
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/`;
  try {
    const none = await fetch(url);
    assert.equal(none.status, 401);
    assert.match(none.headers.get('www-authenticate') ?? '', /^Bearer/);
    const bad = await fetch(url, { headers: { Authorization: `Bearer ${await sign({ ...base, aud: 'x' })}` } });
    assert.equal(bad.status, 401);
    assert.match(bad.headers.get('www-authenticate') ?? '', /invalid_token/);
    const scope = await fetch(url, { headers: { Authorization: `Bearer ${await sign({ ...base, scope: 'openid' })}` } });
    assert.equal(scope.status, 403);
    const ok = await fetch(url, { headers: { Authorization: `Bearer ${await sign(base)}` } });
    assert.equal(ok.status, 200);
    assert.deepEqual(await ok.json(), { sub: 'u1' });
  } finally {
    server.close();
  }
});

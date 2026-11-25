import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createPkce, pkceChallenge, randomState } from '../../dist/index.js';

test('RFC 7636 appendix B vector', async () => {
  assert.equal(await pkceChallenge('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'), 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
});

test('createPkce yields a 43-char base64url verifier and its S256 challenge', async () => {
  const p = await createPkce();
  assert.match(p.verifier, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(p.method, 'S256');
  assert.equal(p.challenge, await pkceChallenge(p.verifier));
  const q = await createPkce();
  assert.notEqual(p.verifier, q.verifier);
});

test('verifier length and charset are enforced', async () => {
  await assert.rejects(pkceChallenge('short'), RangeError);
  await assert.rejects(pkceChallenge('a'.repeat(129)), RangeError);
  await assert.rejects(pkceChallenge(`${'a'.repeat(42)}!`), RangeError);
});

test('state and nonce carry at least 128 bits', () => {
  const s = randomState();
  assert.ok(Buffer.from(s, 'base64url').length >= 16);
  assert.notEqual(s, randomState());
});

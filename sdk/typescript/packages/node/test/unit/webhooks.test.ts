import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { test } from 'node:test';
import { createWebhookHandler, type MoonEvent, WebhookVerificationError, WebhookVerifier } from '../../dist/index.js';

const SECRET = 'whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw';
const ID = 'msg_p5jXN8AQM9LWM0D4loKWxJek';
const TS = 1614265330;
const BODY = '{"test": 2432232314}';
const SIG = 'v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=';

const atVectorTime = { now: () => TS * 1000 };

test('Standard Webhooks test vector (sdk-spec §5.2)', async () => {
  const v = new WebhookVerifier(SECRET, atVectorTime);
  assert.equal(await v.sign(ID, TS, BODY), SIG);
  const msg = await v.verify({ 'webhook-id': ID, 'webhook-timestamp': String(TS), 'webhook-signature': SIG }, BODY);
  assert.deepEqual(msg.payload, { test: 2432232314 });
  assert.equal(msg.id, ID);
  // Headers object and byte body work too
  await v.verify(new Headers({ 'Webhook-Id': ID, 'Webhook-Timestamp': String(TS), 'Webhook-Signature': SIG }), new TextEncoder().encode(BODY));
});

test('any of several space-separated signatures may match; other versions are ignored', async () => {
  const v = new WebhookVerifier(SECRET, atVectorTime);
  const headers = { 'webhook-id': ID, 'webhook-timestamp': String(TS), 'webhook-signature': `v1a,abc v1,${Buffer.alloc(32).toString('base64')} ${SIG}` };
  await v.verify(headers, BODY);
});

test('rejects tampered body, wrong secret, stale or future timestamps and missing headers', async () => {
  const v = new WebhookVerifier(SECRET, atVectorTime);
  const h = { 'webhook-id': ID, 'webhook-timestamp': String(TS), 'webhook-signature': SIG };
  await assert.rejects(v.verify(h, '{"test": 2432232315}'), WebhookVerificationError);
  await assert.rejects(v.verify({ ...h, 'webhook-id': 'msg_other' }, BODY), /no matching signature/);
  await assert.rejects(new WebhookVerifier('whsec_' + Buffer.alloc(24, 1).toString('base64'), atVectorTime).verify(h, BODY), /no matching signature/);
  await assert.rejects(new WebhookVerifier(SECRET, { now: () => (TS + 301) * 1000 }).verify(h, BODY), /tolerance/);
  await assert.rejects(new WebhookVerifier(SECRET, { now: () => (TS - 301) * 1000 }).verify(h, BODY), /tolerance/);
  await new WebhookVerifier(SECRET, { now: () => (TS + 299) * 1000 }).verify(h, BODY);
  await assert.rejects(v.verify({ 'webhook-id': ID, 'webhook-timestamp': String(TS) }, BODY), /missing/);
  await assert.rejects(v.verify({ ...h, 'webhook-signature': 'v1,not-base64!!' }, BODY), /no matching signature/);
});

test('webhook handler verifies raw bytes, de-duplicates by webhook-id and answers 204', async () => {
  const secret = `whsec_${Buffer.alloc(32, 7).toString('base64')}`;
  const v = new WebhookVerifier(secret);
  const got: MoonEvent[] = [];
  const handler = createWebhookHandler({ verifier: v, onEvent: (ev) => void got.push(ev) });
  const server = createServer((req, res) => void handler(req, res));
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/hook`;
  try {
    const event = { id: 'evt_9', seq: 9, type: 'user.updated', occurred_at: new Date().toISOString(), data: { sub: 's', status: 'active', profile_version: 3, updated_at: 1 } };
    const body = JSON.stringify(event);
    const ts = Math.floor(Date.now() / 1000);
    const headers = { 'Content-Type': 'application/json', 'webhook-id': 'evt_9', 'webhook-timestamp': String(ts), 'webhook-signature': await v.sign('evt_9', ts, body) };
    assert.equal((await fetch(url, { method: 'POST', headers, body })).status, 204);
    assert.equal((await fetch(url, { method: 'POST', headers, body })).status, 204);
    assert.equal(got.length, 1, 'duplicate delivery ignored');
    assert.equal(got[0]?.data.profile_version, 3);
    const bad = await fetch(url, { method: 'POST', headers, body: body.replace('"s"', '"x"') });
    assert.equal(bad.status, 400);
  } finally {
    server.close();
  }
});

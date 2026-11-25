import assert from 'node:assert/strict';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { test } from 'node:test';
import { parseCookies, redirect, safeReturnTo, serializeCookie } from '../../dist/index.js';

async function serve(handler: (req: IncomingMessage, res: ServerResponse) => void): Promise<{ url: string; close: () => void }> {
  const s = createServer(handler);
  await new Promise<void>((r) => s.listen(0, '127.0.0.1', r));
  return { url: `http://127.0.0.1:${(s.address() as AddressInfo).port}`, close: () => s.close() };
}

test('HTMX-aware redirect: 200 + HX-Redirect for HTMX, 302 otherwise', async () => {
  const s = await serve((req, res) => redirect(req, res, '/auth/login?returnTo=%2Fx'));
  try {
    const plain = await fetch(s.url, { redirect: 'manual' });
    assert.equal(plain.status, 302);
    assert.equal(plain.headers.get('location'), '/auth/login?returnTo=%2Fx');
    const hx = await fetch(s.url, { redirect: 'manual', headers: { 'HX-Request': 'true' } });
    assert.equal(hx.status, 200);
    assert.equal(hx.headers.get('hx-redirect'), '/auth/login?returnTo=%2Fx');
    assert.equal(hx.headers.get('location'), null);
  } finally {
    s.close();
  }
});

test('safeReturnTo blocks open redirects', () => {
  assert.equal(safeReturnTo('/a?b=1'), '/a?b=1');
  for (const bad of ['//evil.com', 'https://evil.com', '/\\evil.com', 'javascript:alert(1)', '/a\r\nSet-Cookie: x', '', null, undefined]) {
    assert.equal(safeReturnTo(bad, '/home'), '/home', String(bad));
  }
});

test('cookie serialization and parsing', () => {
  const c = serializeCookie('moon_sso', 'a b', { secure: true, sameSite: 'Lax', maxAge: 60 });
  assert.match(c, /^moon_sso=a%20b; Path=\/; Max-Age=60; HttpOnly; Secure; SameSite=Lax$/);
  const req = { headers: { cookie: 'x=1; moon_sso=a%20b; moon_sso=dup' } } as IncomingMessage;
  assert.deepEqual(parseCookies(req), { x: '1', moon_sso: 'a b' });
});

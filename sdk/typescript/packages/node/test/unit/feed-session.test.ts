import assert from 'node:assert/strict';
import { test } from 'node:test';
import { CursorExpiredError, MemorySessionStore, MoonSsoClient, MoonSsoError, SessionManager, type SyncItem } from '../../dist/index.js';
import { ISSUER, scriptedFetch } from '../../../../test-support/keys.ts';

function ev(seq: number) {
  return { id: `evt_${seq}`, seq, type: 'user.updated', occurred_at: '2026-01-01T00:00:00Z', data: { sub: `s${seq}`, status: 'active', profile_version: seq, updated_at: 1 } };
}

test('changes feed: pages until has_more=false; 410 → full sync → continue from first-page watermark', async () => {
  let ccCalls = 0;
  const changeCursors: string[] = [];
  const sf = scriptedFetch(
    () => [],
    (req) => {
      const u = new URL(req.url);
      if (u.pathname === '/oauth/token') {
        ccCalls++;
        assert.match(req.headers.get('Authorization') ?? '', /^Basic /);
        return Response.json({ access_token: `cc${ccCalls}`, token_type: 'Bearer', expires_in: 3600, scope: 'users:sync' });
      }
      if (u.pathname === '/api/v1/users/changes') {
        const cursor = u.searchParams.get('cursor') ?? '';
        changeCursors.push(cursor);
        if (cursor === '5') {
          return Response.json({ error: 'cursor_expired' }, { status: 410 });
        }
        if (cursor === '100') {
          return Response.json({ events: [ev(101), ev(102)], next_cursor: '102', has_more: true });
        }
        if (cursor === '102') {
          return Response.json({ events: [ev(103)], next_cursor: '103', has_more: false });
        }
        return Response.json({ events: [], next_cursor: cursor || '0', has_more: false });
      }
      if (u.pathname === '/api/v1/users') {
        const c = u.searchParams.get('cursor');
        if (!c) {
          return Response.json({ users: [{ sub: 'a' }], has_more: true, next_cursor: 'aa', watermark: '100' });
        }
        return Response.json({ users: [{ sub: 'b' }], has_more: false, watermark: '107' });
      }
      return undefined;
    },
  );
  const client = new MoonSsoClient({ issuer: ISSUER, clientId: 'web', clientSecret: 's3cret', fetch: sf.fetch });
  const feed = client.changesFeed();
  const items: SyncItem[] = [];
  const gen = feed.changes('5');
  let r = await gen.next();
  while (!r.done) {
    items.push(r.value);
    r = await gen.next();
  }
  assert.equal(r.value, '103');
  assert.deepEqual(
    items.map((i) => (i.kind === 'snapshot' ? `snap:${i.users.map((u) => u.sub).join(',')}@${i.watermark}` : `ev:${i.events.map((e) => e.seq).join(',')}→${i.cursor}`)),
    ['snap:a@100', 'snap:b@100', 'ev:101,102→102', 'ev:103→103'],
  );
  assert.deepEqual(changeCursors, ['5', '100', '102']);
  assert.equal(ccCalls, 1, 'client_credentials token cached');
  await assert.rejects(feed.syncChanges('5'), CursorExpiredError);
});

test('client_credentials: 401 from the API forces exactly one new token', async () => {
  let ccCalls = 0;
  const sf = scriptedFetch(
    () => [],
    (req) => {
      const u = new URL(req.url);
      if (u.pathname === '/oauth/token') {
        ccCalls++;
        return Response.json({ access_token: `cc${ccCalls}`, token_type: 'Bearer', expires_in: 3600 });
      }
      if (u.pathname === '/api/v1/users/changes') {
        return req.headers.get('Authorization') === 'Bearer cc2'
          ? Response.json({ events: [], next_cursor: '0', has_more: false })
          : Response.json({ error: 'invalid_token' }, { status: 401 });
      }
      return undefined;
    },
  );
  const client = new MoonSsoClient({ issuer: ISSUER, clientId: 'web', clientSecret: 's', fetch: sf.fetch });
  const page = await client.changesFeed().syncChanges('');
  assert.equal(page.hasMore, false);
  assert.equal(ccCalls, 2);
});

test('SessionManager: concurrent refreshes per session are single-flight; invalid_grant ends the session', async () => {
  let refreshes = 0;
  let mode: 'ok' | 'dead' = 'ok';
  const sf = scriptedFetch(
    () => [],
    async (req) => {
      const u = new URL(req.url);
      if (u.pathname === '/oauth/token') {
        const body = new URLSearchParams(await req.text());
        assert.equal(body.get('grant_type'), 'refresh_token');
        if (mode === 'dead') {
          return Response.json({ error: 'invalid_grant' }, { status: 400 });
        }
        refreshes++;
        await new Promise((r) => setTimeout(r, 20));
        return Response.json({ access_token: `at${refreshes}`, token_type: 'Bearer', expires_in: 600, refresh_token: `rt${refreshes}` });
      }
      return undefined;
    },
  );
  const client = new MoonSsoClient({ issuer: ISSUER, clientId: 'web', clientSecret: 's', fetch: sf.fetch });
  const store = new MemorySessionStore();
  const sessions = new SessionManager({ client, store });
  const now = Math.floor(Date.now() / 1000);
  await sessions.save('sid1', { tokens: { accessToken: 'at0', tokenType: 'Bearer', expiresAt: now + 60, refreshToken: 'rt0' }, createdAt: Date.now(), updatedAt: Date.now() });
  // < 120 s left → refresh; 10 concurrent callers → 1 request
  const all = await Promise.all(Array.from({ length: 10 }, () => sessions.getAccessToken('sid1')));
  assert.deepEqual(new Set(all), new Set(['at1']));
  assert.equal(refreshes, 1);
  assert.equal((await store.get('sid1'))?.tokens?.refreshToken, 'rt1');
  // fresh token: no refresh
  assert.equal(await sessions.getAccessToken('sid1'), 'at1');
  assert.equal(refreshes, 1);
  mode = 'dead';
  await assert.rejects(sessions.getAccessToken('sid1', { force: true }), (e: unknown) => e instanceof MoonSsoError && e.error === 'invalid_grant');
  assert.equal(await store.get('sid1'), undefined);
});

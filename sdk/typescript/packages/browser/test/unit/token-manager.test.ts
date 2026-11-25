import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  InProcessLockProvider,
  MemoryStore,
  MoonSso,
  MoonSsoError,
  SingleFlight,
  type MoonSsoOptions,
  type TabChannel,
} from '../../dist/index.js';
import { ISSUER, scriptedFetch } from '../../../../test-support/keys.ts';

/** Synchronous in-memory channel hub (deterministic multi-tab tests). */
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

interface TokenServer {
  calls: Request[];
  dpopProofs: string[];
  /** queue of scripted responses for /oauth/token; when empty, a fresh token is issued */
  queue: (() => Response | Promise<Response>)[];
  issued: number;
}

function tokenServer(): { server: TokenServer; fetch: typeof fetch; apiHandler: { fn: (req: Request) => Response | undefined } } {
  const server: TokenServer = { calls: [], dpopProofs: [], queue: [], issued: 0 };
  const apiHandler = { fn: (_req: Request): Response | undefined => undefined };
  const sf = scriptedFetch(
    () => [],
    async (req) => {
      const url = new URL(req.url);
      if (url.pathname === '/oauth/token') {
        server.calls.push(req.clone());
        server.dpopProofs.push(req.headers.get('DPoP') ?? '');
        const next = server.queue.shift();
        if (next) {
          return next();
        }
        await new Promise((r) => setTimeout(r, 20));
        server.issued++;
        return Response.json({ access_token: `at-${server.issued}`, token_type: 'Bearer', expires_in: 300, refresh_token: `rt-${server.issued}`, scope: 'openid profile offline_access' }, { headers: { 'DPoP-Nonce': 'nonce-ok' } });
      }
      if (url.pathname === '/oauth/revoke') {
        return new Response(null, { status: 200 });
      }
      return apiHandler.fn(req);
    },
  );
  return { server, fetch: sf.fetch, apiHandler };
}

function client(f: typeof fetch, extra: Partial<MoonSsoOptions> = {}): MoonSso {
  return new MoonSso({ issuer: ISSUER, clientId: 'spa', fetch: f, storage: new MemoryStore(), locks: new InProcessLockProvider(), channel: null, ...extra });
}

async function seed(c: MoonSso): Promise<void> {
  await c.init();
  await c.tokens.commit({ access_token: 'at-0', token_type: 'Bearer', expires_in: 300, refresh_token: 'rt-0' }, 'user-1', undefined);
}

test('single-flight: concurrent forced refreshes share one token request', async () => {
  const { server, fetch } = tokenServer();
  const c = client(fetch);
  await seed(c);
  const results = await Promise.all(Array.from({ length: 8 }, () => c.getAccessToken({ force: true })));
  assert.equal(server.calls.length, 1);
  assert.deepEqual(new Set(results), new Set(['at-1']));
  const body = new URLSearchParams(await server.calls[0]!.text());
  assert.equal(body.get('grant_type'), 'refresh_token');
  assert.equal(body.get('refresh_token'), 'rt-0');
  assert.equal(body.get('client_id'), 'spa');
  assert.ok(server.dpopProofs[0], 'refresh carries a DPoP proof');
  assert.equal(c.tokens.currentSession?.refreshToken, 'rt-1', 'rotated refresh token persisted');
  await c.close();
});

test('two tabs sharing storage, lock and channel converge on one refresh', async () => {
  const { server, fetch } = tokenServer();
  const store = new MemoryStore();
  const locks = new InProcessLockProvider();
  const hub = new Hub();
  const a = client(fetch, { storage: store, locks, channel: hub.channel() });
  const b = client(fetch, { storage: store, locks, channel: hub.channel() });
  await seed(a);
  await b.init();
  assert.equal(b.isAuthenticated, true);
  const [ta, tb] = await Promise.all([a.getAccessToken({ force: true }), b.getAccessToken()]);
  assert.equal(server.calls.length, 1, 'second tab reused the broadcast token');
  assert.equal(ta, 'at-1');
  assert.equal(tb, 'at-1');
  assert.equal(b.tokens.currentAccess?.accessToken, 'at-1');
  await a.close();
  await b.close();
});

test('proactive refresh after 75 % of the lifetime (checked before each request)', async () => {
  let clock = 1_000_000_000_000;
  const { server, fetch } = tokenServer();
  const c = client(fetch, { now: () => clock });
  await seed(c);
  clock += 200_000; // 66 % of 300 s
  assert.equal(await c.getAccessToken(), 'at-0');
  assert.equal(server.calls.length, 0);
  clock += 30_000; // 76 %
  assert.equal(await c.getAccessToken(), 'at-1');
  assert.equal(server.calls.length, 1);
  await c.close();
});

test('retries once on 503 and on network errors with a fresh DPoP proof', async () => {
  const { server, fetch } = tokenServer();
  const c = client(fetch);
  await seed(c);
  server.queue.push(() => new Response('{"error":"temporarily_unavailable"}', { status: 503 }));
  assert.equal(await c.getAccessToken({ force: true }), 'at-1');
  assert.equal(server.calls.length, 2);
  assert.notEqual(server.dpopProofs[0], server.dpopProofs[1], 'new proof (new jti) per attempt');
  server.queue.push(() => {
    throw new TypeError('socket hang up');
  });
  assert.equal(await c.getAccessToken({ force: true }), 'at-2');
  assert.equal(server.calls.length, 4);
  await c.close();
});

test('502 twice: error surfaces, session is kept, still-valid token is returned for proactive refresh', async () => {
  let clock = 2_000_000_000_000;
  const { server, fetch } = tokenServer();
  const c = client(fetch, { now: () => clock });
  await seed(c);
  server.queue.push(
    () => new Response('bad gateway', { status: 502 }),
    () => new Response('bad gateway', { status: 502 }),
  );
  await assert.rejects(c.getAccessToken({ force: true }), (e: unknown) => e instanceof MoonSsoError && e.status === 502);
  assert.equal(c.isAuthenticated, true);
  clock += 240_000;
  server.queue.push(
    () => new Response('bad gateway', { status: 502 }),
    () => new Response('bad gateway', { status: 502 }),
  );
  assert.equal(await c.getAccessToken(), 'at-0', 'falls back to the unexpired token');
  await c.close();
});

test('use_dpop_nonce: retried immediately with the server nonce', async () => {
  const { server, fetch } = tokenServer();
  const c = client(fetch);
  await seed(c);
  server.queue.push(() =>
    Response.json({ error: 'use_dpop_nonce', error_description: 'nonce required' }, { status: 400, headers: { 'DPoP-Nonce': 'srv-nonce-1' } }),
  );
  assert.equal(await c.getAccessToken({ force: true }), 'at-1');
  assert.equal(server.calls.length, 2);
  const claims = (p: string) => JSON.parse(Buffer.from(p.split('.')[1]!, 'base64url').toString()) as Record<string, unknown>;
  assert.equal(claims(server.dpopProofs[0]!)['nonce'], undefined);
  const second = claims(server.dpopProofs[1]!);
  assert.equal(second['nonce'], 'srv-nonce-1');
  assert.equal(second['htm'], 'POST');
  assert.equal(second['htu'], `${ISSUER}/oauth/token`);
  const header = JSON.parse(Buffer.from(server.dpopProofs[1]!.split('.')[0]!, 'base64url').toString()) as Record<string, unknown>;
  assert.equal(header['typ'], 'dpop+jwt');
  assert.deepEqual(Object.keys(header['jwk'] as object).sort(), ['crv', 'kty', 'x', 'y']);
  await c.close();
});

test('invalid_grant clears the session and emits sessionExpired; invalid_client does not', async () => {
  const { server, fetch } = tokenServer();
  const c = client(fetch);
  await seed(c);
  server.queue.push(() => Response.json({ error: 'invalid_client' }, { status: 401 }));
  await assert.rejects(c.getAccessToken({ force: true }), (e: unknown) => e instanceof MoonSsoError && e.error === 'invalid_client');
  assert.equal(server.calls.length, 1, 'invalid_client is not retried');
  assert.equal(c.isAuthenticated, true);
  const expired: MoonSsoError[] = [];
  c.on('sessionExpired', (e) => expired.push(e));
  server.queue.push(() => Response.json({ error: 'invalid_grant', error_description: 'revoked' }, { status: 400 }));
  await assert.rejects(c.getAccessToken({ force: true }), (e: unknown) => e instanceof MoonSsoError && e.isSessionExpired);
  assert.equal(expired.length, 1);
  assert.equal(c.isAuthenticated, false);
  await assert.rejects(c.getAccessToken(), (e: unknown) => e instanceof MoonSsoError && e.error === 'login_required');
  await c.close();
});

test('authorized fetch: 401 → one refresh → one replay; second 401 is returned', async () => {
  const { server, fetch, apiHandler } = tokenServer();
  const c = client(fetch);
  await seed(c);
  const seen: string[] = [];
  apiHandler.fn = (req) => {
    const auth = req.headers.get('Authorization') ?? '';
    seen.push(auth);
    return auth === 'Bearer at-1' ? Response.json({ ok: true }) : Response.json({ error: 'invalid_token' }, { status: 401 });
  };
  const r = await c.fetch(`${ISSUER}/api/v1/thing`, { method: 'POST', body: '{"x":1}' });
  assert.equal(r.status, 200);
  assert.deepEqual(seen, ['Bearer at-0', 'Bearer at-1']);
  assert.equal(server.calls.length, 1);
  apiHandler.fn = () => Response.json({ error: 'invalid_token' }, { status: 401 });
  const r2 = await c.fetch(`${ISSUER}/api/v1/thing`);
  assert.equal(r2.status, 401);
  assert.equal(server.calls.length, 2, 'exactly one more refresh');
  assert.equal(c.isAuthenticated, true, '401 alone never clears the session');
  await c.close();
});

test('SingleFlight coalesces concurrent calls per key', async () => {
  const sf = new SingleFlight<string, number>();
  let runs = 0;
  const work = () =>
    new Promise<number>((r) => {
      runs++;
      setTimeout(() => r(runs), 10);
    });
  const out = await Promise.all([sf.run('a', work), sf.run('a', work), sf.run('b', work)]);
  assert.equal(runs, 2);
  assert.equal(out[0], out[1]);
  assert.equal(sf.size, 0);
  assert.equal(await sf.run('a', work), 3);
});

// Helpers for integration tests against the local Moon SSO testbed
// (docs/sdk-spec.md §8). Every mutating test uses fresh random users and
// its own DCR-registered clients; shared fixtures are never modified.

import { randomBytes } from 'node:crypto';
import { createServer, type IncomingHttpHeaders, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { deflateSync, crc32 } from 'node:zlib';

export const TESTBED = (process.env['MOON_SSO_TESTBED'] ?? 'http://127.0.0.1:18601').replace(/\/+$/, '');

export const ALICE = { username: 'alice', password: 'Wonderland-Pass-1' };
export const BOB = { username: 'bob', password: 'Builder-Pass-22', totpSecret: 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP' };
export const TEST_WEB = {
  clientId: 'test-web',
  clientSecret: 'test-web-secret-0123456789abcdef',
  redirectUri: 'http://127.0.0.1:18700/callback',
};
export const TEST_SPA = { clientId: 'test-spa', redirectUri: 'http://127.0.0.1:18700/' };

let reachable: boolean | undefined;

/** True when the testbed answers discovery. */
export async function testbedReachable(): Promise<boolean> {
  if (reachable === undefined) {
    try {
      const r = await fetch(`${TESTBED}/.well-known/openid-configuration`, { signal: AbortSignal.timeout(3000) });
      reachable = r.ok;
    } catch {
      reachable = false;
    }
  }
  return reachable;
}

async function post(path: string, body?: unknown, form?: URLSearchParams): Promise<Response> {
  const init: RequestInit = { method: 'POST' };
  if (form) {
    init.headers = { 'Content-Type': 'application/x-www-form-urlencoded' };
    init.body = form.toString();
  } else if (body !== undefined) {
    init.headers = { 'Content-Type': 'application/json' };
    init.body = JSON.stringify(body);
  }
  return fetch(`${TESTBED}${path}`, init);
}

async function okJson<T>(r: Response, what: string): Promise<T> {
  const text = await r.text();
  if (!r.ok) {
    throw new Error(`${what} failed: HTTP ${r.status} ${text.slice(0, 300)}`);
  }
  return JSON.parse(text) as T;
}

export function randomName(prefix = 't_ts'): string {
  const alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789';
  const b = randomBytes(8);
  let s = '';
  for (const x of b) {
    s += alphabet[x % alphabet.length];
  }
  return `${prefix}${s}`;
}

export interface TestUser {
  username: string;
  password: string;
  publicSub: string;
}

/** Creates a fresh random user (POST /__test/users). */
export async function createUser(): Promise<TestUser> {
  const username = randomName();
  const password = `Ts-Sdk-${randomBytes(9).toString('base64url')}-9`;
  const r = await okJson<{ public_sub: string; username: string }>(await post('/__test/users', { username, password }), 'create user');
  return { username: r.username, password, publicSub: r.public_sub };
}

/** Completes an authorization request as a browser would (POST /__test/authorize). */
export async function testAuthorize(authorizeUrl: string, username: string, password: string): Promise<{ redirect: string; sessionToken: string }> {
  const u = new URL(authorizeUrl);
  const form = new URLSearchParams(u.searchParams);
  form.set('username', username);
  form.set('password', password);
  const r = await okJson<{ redirect: string; session_token: string }>(await post('/__test/authorize', undefined, form), 'test authorize');
  return { redirect: r.redirect, sessionToken: r.session_token };
}

export async function totp(secret: string): Promise<string> {
  const r = await okJson<{ code: string }>(await post(`/__test/totp?secret=${encodeURIComponent(secret)}`), 'totp');
  return r.code;
}

export async function initialAccessToken(): Promise<string> {
  return (await okJson<{ token: string }>(await post('/__test/iat'), 'iat')).token;
}

export async function trustClient(clientId: string): Promise<void> {
  await okJson(await post(`/__test/clients/${encodeURIComponent(clientId)}/trust`), 'trust client');
}

export async function setWebhook(clientId: string, url: string): Promise<string> {
  return (await okJson<{ secret: string }>(await post(`/__test/clients/${encodeURIComponent(clientId)}/webhook`, { url }), 'set webhook')).secret;
}

export async function setBackchannel(clientId: string, url: string): Promise<void> {
  await okJson(await post(`/__test/clients/${encodeURIComponent(clientId)}/backchannel`, { url }), 'set backchannel');
}

export async function endSsoSession(sessionToken: string): Promise<void> {
  await okJson(await post(`/__test/logout?session_token=${encodeURIComponent(sessionToken)}`), 'test logout');
}

export async function setDisplayNameServerSide(username: string, displayName: string): Promise<void> {
  await okJson(await post(`/__test/users/${encodeURIComponent(username)}/profile`, { display_name: displayName }), 'server-side profile update');
}

// ---------------------------------------------------------------------------

export interface RecordedRequest {
  method: string;
  url: string;
  headers: IncomingHttpHeaders;
  body: Buffer;
}

export interface Receiver {
  url: string;
  port: number;
  requests: RecordedRequest[];
  /** Resolves with the first (past or future) request matching `pred`. */
  waitFor(pred: (r: RecordedRequest) => boolean, timeoutMs?: number): Promise<RecordedRequest>;
  close(): Promise<void>;
}

/** Local HTTP receiver on 127.0.0.1 with a random port. `handler` may answer; default 204. */
export async function startReceiver(handler?: (req: IncomingMessage, res: ServerResponse, rec: RecordedRequest) => void | Promise<void>): Promise<Receiver> {
  const requests: RecordedRequest[] = [];
  const waiters: { pred: (r: RecordedRequest) => boolean; resolve: (r: RecordedRequest) => void }[] = [];
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      const rec: RecordedRequest = { method: req.method ?? '', url: req.url ?? '', headers: req.headers, body: Buffer.concat(chunks) };
      requests.push(rec);
      const done = () => {
        for (const w of [...waiters]) {
          if (w.pred(rec)) {
            waiters.splice(waiters.indexOf(w), 1);
            w.resolve(rec);
          }
        }
      };
      if (handler) {
        Promise.resolve(handler(req, res, rec))
          .catch(() => {
            if (!res.headersSent) {
              res.statusCode = 500;
            }
            res.end();
          })
          .finally(done);
      } else {
        res.statusCode = 204;
        res.end();
        done();
      }
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as AddressInfo).port;
  return {
    url: `http://127.0.0.1:${port}`,
    port,
    requests,
    waitFor(pred, timeoutMs = 20_000) {
      const hit = requests.find(pred);
      if (hit) {
        return Promise.resolve(hit);
      }
      return new Promise((resolve, reject) => {
        const w = { pred, resolve: (r: RecordedRequest) => {
          clearTimeout(t);
          resolve(r);
        } };
        const t = setTimeout(() => {
          waiters.splice(waiters.indexOf(w), 1);
          reject(new Error(`timed out after ${timeoutMs} ms waiting for a request`));
        }, timeoutMs);
        waiters.push(w);
      });
    },
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}

export interface FetchLog {
  method: string;
  url: string;
  status: number;
  error?: string;
  requestHeaders: Headers;
  responseHeaders: Headers;
}

/** fetch wrapper that records every exchange (bodies of OAuth errors are peeked without consuming). */
export function recordingFetch(): { fetch: typeof fetch; log: FetchLog[] } {
  const log: FetchLog[] = [];
  const f: typeof fetch = async (input, init) => {
    const req = new Request(input, init);
    const res = await fetch(req);
    const entry: FetchLog = { method: req.method, url: req.url, status: res.status, requestHeaders: req.headers, responseHeaders: res.headers };
    if (!res.ok && (res.headers.get('Content-Type') ?? '').includes('json')) {
      try {
        const j = (await res.clone().json()) as { error?: string };
        if (typeof j.error === 'string') {
          entry.error = j.error;
        }
      } catch {
        // ignore
      }
    }
    log.push(entry);
    return res;
  };
  return { fetch: f, log };
}

/** A valid w×h RGB PNG (the avatar endpoint needs at least 16×16). */
export function makePng(w = 32, h = 32): Uint8Array {
  const chunk = (type: string, data: Buffer) => {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(data.length);
    const td = Buffer.concat([Buffer.from(type, 'ascii'), data]);
    const crc = Buffer.alloc(4);
    crc.writeUInt32BE(crc32(td) >>> 0);
    return Buffer.concat([len, td, crc]);
  };
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(w, 0);
  ihdr.writeUInt32BE(h, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 2; // RGB
  const raw = Buffer.alloc((w * 3 + 1) * h);
  for (let y = 0; y < h; y++) {
    raw[y * (w * 3 + 1)] = 0;
    for (let x = 0; x < w; x++) {
      const o = y * (w * 3 + 1) + 1 + x * 3;
      raw[o] = (x * 8) & 255;
      raw[o + 1] = (y * 8) & 255;
      raw[o + 2] = 128;
    }
  }
  return new Uint8Array(
    Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk('IHDR', ihdr), chunk('IDAT', deflateSync(raw)), chunk('IEND', Buffer.alloc(0))]),
  );
}

export function until<T>(fn: () => T | undefined, timeoutMs = 20_000, intervalMs = 100): Promise<T> {
  const start = Date.now();
  return new Promise((resolve, reject) => {
    const tick = () => {
      let v: T | undefined;
      try {
        v = fn();
      } catch (e) {
        reject(e);
        return;
      }
      if (v !== undefined) {
        resolve(v);
        return;
      }
      if (Date.now() - start > timeoutMs) {
        reject(new Error(`condition not met within ${timeoutMs} ms`));
        return;
      }
      setTimeout(tick, intervalMs);
    };
    tick();
  });
}

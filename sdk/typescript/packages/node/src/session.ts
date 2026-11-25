/**
 * Server-side sessions for the BFF pattern: tokens live only on the server,
 * the browser holds an opaque session id. Access tokens are renewed when
 * less than 120 s remain (sdk-spec §1.2), single-flight per session.
 */

import type { AccountApi } from './shared/account.js';
import { MoonSsoError } from './shared/errors.js';
import type { IdTokenClaims } from './shared/jose.js';
import { randomToken } from './shared/encoding.js';
import { SingleFlight } from './shared/util.js';
import type { MoonSsoClient, PendingAuthorization, TokenSet } from './client.js';

export interface SessionData {
  /** Tokens of the signed-in user (absent while a login is pending). */
  tokens?: TokenSet;
  /** Validated ID token claims. */
  user?: IdTokenClaims;
  /** Pending authorization requests keyed by state (several tabs may log in at once). */
  pending?: Record<string, PendingAuthorization>;
  createdAt: number;
  updatedAt: number;
  /** Free-form application data. */
  app?: Record<string, unknown>;
}

/** Persistence for sessions. Implement it on Redis, a database, etc. */
export interface SessionStore {
  get(id: string): Promise<SessionData | undefined>;
  /** Stores the session; `ttlSeconds` is the idle lifetime. */
  set(id: string, data: SessionData, ttlSeconds: number): Promise<void>;
  delete(id: string): Promise<void>;
  /** Back-channel logout support: delete sessions whose ID token carried this sid. Returns the count. */
  deleteBySid?(sid: string): Promise<number>;
  /** Back-channel logout support: delete all sessions of this subject. Returns the count. */
  deleteBySub?(sub: string): Promise<number>;
}

/** In-memory session store (single process). Expired entries are swept lazily. */
export class MemorySessionStore implements SessionStore {
  private readonly map = new Map<string, { data: SessionData; exp: number }>();
  private readonly now: () => number;
  private lastSweep = 0;

  constructor(opts: { now?: () => number } = {}) {
    this.now = opts.now ?? Date.now;
  }

  private sweep(): void {
    const now = this.now();
    if (now - this.lastSweep < 60_000) {
      return;
    }
    this.lastSweep = now;
    for (const [k, v] of this.map) {
      if (v.exp <= now) {
        this.map.delete(k);
      }
    }
  }

  async get(id: string): Promise<SessionData | undefined> {
    this.sweep();
    const e = this.map.get(id);
    if (!e) {
      return undefined;
    }
    if (e.exp <= this.now()) {
      this.map.delete(id);
      return undefined;
    }
    return structuredClone(e.data);
  }

  async set(id: string, data: SessionData, ttlSeconds: number): Promise<void> {
    this.map.set(id, { data: structuredClone(data), exp: this.now() + ttlSeconds * 1000 });
  }

  async delete(id: string): Promise<void> {
    this.map.delete(id);
  }

  async deleteBySid(sid: string): Promise<number> {
    let n = 0;
    for (const [k, v] of this.map) {
      if (v.data.user?.sid === sid) {
        this.map.delete(k);
        n++;
      }
    }
    return n;
  }

  async deleteBySub(sub: string): Promise<number> {
    let n = 0;
    for (const [k, v] of this.map) {
      if (v.data.user?.sub === sub) {
        this.map.delete(k);
        n++;
      }
    }
    return n;
  }

  get size(): number {
    return this.map.size;
  }
}

export interface SessionManagerOptions {
  client: MoonSsoClient;
  store: SessionStore;
  /** Idle lifetime of a session (default 30 days; refreshed on every write). */
  ttlSeconds?: number;
  /** Refresh when fewer seconds than this remain (default 120). */
  refreshBeforeSeconds?: number;
  /** Lifetime of pending logins (default 10 minutes). */
  pendingTtlSeconds?: number;
}

const MAX_PENDING = 5;

export class SessionManager {
  readonly client: MoonSsoClient;
  readonly store: SessionStore;
  private readonly ttl: number;
  private readonly skew: number;
  private readonly pendingTtl: number;
  private readonly flight = new SingleFlight<string, TokenSet>();
  /** Refresh requests sent to the server (diagnostics). */
  refreshCount = 0;

  constructor(opts: SessionManagerOptions) {
    this.client = opts.client;
    this.store = opts.store;
    this.ttl = opts.ttlSeconds ?? 30 * 24 * 3600;
    this.skew = opts.refreshBeforeSeconds ?? 120;
    this.pendingTtl = opts.pendingTtlSeconds ?? 600;
  }

  static newSessionId(): string {
    return randomToken(32);
  }

  private nowS(): number {
    return Math.floor(this.client.nowMs() / 1000);
  }

  async get(sessionId: string): Promise<SessionData | undefined> {
    return this.store.get(sessionId);
  }

  async save(sessionId: string, data: SessionData): Promise<void> {
    data.updatedAt = this.client.nowMs();
    await this.store.set(sessionId, data, this.ttl);
  }

  async destroy(sessionId: string): Promise<void> {
    await this.store.delete(sessionId);
  }

  /** Starts a login: returns the authorization URL and remembers its state in the session. */
  async beginLogin(sessionId: string | undefined, opts: Parameters<MoonSsoClient['createAuthorizationUrl']>[0] = {}): Promise<{ sessionId: string; url: string }> {
    const id = sessionId ?? SessionManager.newSessionId();
    const now = this.client.nowMs();
    const data: SessionData = (sessionId ? await this.store.get(sessionId) : undefined) ?? { createdAt: now, updatedAt: now };
    const { url, pending } = await this.client.createAuthorizationUrl(opts);
    const entries = Object.entries(data.pending ?? {}).filter(([, p]) => now - p.createdAt < this.pendingTtl * 1000);
    entries.push([pending.state, pending]);
    data.pending = Object.fromEntries(entries.slice(-MAX_PENDING));
    await this.save(id, data);
    return { sessionId: id, url };
  }

  /**
   * Completes a login. The session id is rotated (session fixation defense):
   * use the returned id from now on; the old one is deleted.
   */
  async completeLogin(sessionId: string, callback: string | URL | URLSearchParams): Promise<{ sessionId: string; tokens: TokenSet; returnTo: string | undefined }> {
    const data = await this.store.get(sessionId);
    const params =
      callback instanceof URLSearchParams ? callback : callback instanceof URL ? callback.searchParams : new URL(callback, 'http://localhost').searchParams;
    const state = params.get('state') ?? '';
    const pending = data?.pending?.[state];
    if (!data || !pending) {
      throw new MoonSsoError({ error: 'invalid_state', error_description: 'unknown login state (cookie missing or login expired)' });
    }
    delete data.pending![state];
    await this.save(sessionId, data);
    const tokens = await this.client.handleCallback(params, pending, { maxAgeMs: this.pendingTtl * 1000 });
    const now = this.client.nowMs();
    const fresh: SessionData = { tokens, createdAt: now, updatedAt: now };
    if (tokens.claims) {
      fresh.user = tokens.claims;
    }
    if (data.app) {
      fresh.app = data.app;
    }
    const newId = SessionManager.newSessionId();
    await this.save(newId, fresh);
    await this.store.delete(sessionId);
    return { sessionId: newId, tokens, returnTo: pending.returnTo };
  }

  /**
   * Returns valid tokens, refreshing when fewer than 120 s remain or when
   * `force` is set. Concurrent calls for one session share one refresh.
   * On invalid_grant the tokens are removed and the error is rethrown.
   */
  async getTokens(sessionId: string, opts: { force?: boolean; rejected?: string } = {}): Promise<TokenSet | undefined> {
    const data = await this.store.get(sessionId);
    const t = data?.tokens;
    if (!t) {
      return undefined;
    }
    if (!opts.force && t.expiresAt - this.nowS() > this.skew) {
      return t;
    }
    return this.flight.run(sessionId, () => this.refreshLocked(sessionId, opts.rejected ?? (opts.force ? t.accessToken : undefined)));
  }

  private async refreshLocked(sessionId: string, rejected: string | undefined): Promise<TokenSet> {
    // Re-read: another process may have refreshed already.
    const data = await this.store.get(sessionId);
    const t = data?.tokens;
    if (!data || !t) {
      throw new MoonSsoError({ error: 'login_required', error_description: 'session has no tokens' });
    }
    if (t.accessToken !== rejected && t.expiresAt - this.nowS() > this.skew) {
      return t;
    }
    if (!t.refreshToken) {
      throw new MoonSsoError({ error: 'login_required', error_description: 'access token expired and no refresh token is available' });
    }
    let next: TokenSet;
    this.refreshCount++;
    try {
      next = await this.client.refresh(t.refreshToken, { previous: t });
    } catch (e) {
      if (e instanceof MoonSsoError && e.error === 'invalid_grant') {
        await this.store.delete(sessionId);
      }
      throw e;
    }
    // Persist the rotated refresh token immediately.
    data.tokens = next;
    if (next.claims) {
      data.user = next.claims;
    }
    await this.save(sessionId, data);
    return next;
  }

  /** Access token for API calls on behalf of the session's user. */
  async getAccessToken(sessionId: string, opts: { force?: boolean; rejected?: string } = {}): Promise<string> {
    const t = await this.getTokens(sessionId, opts);
    if (!t) {
      throw new MoonSsoError({ error: 'login_required', error_description: 'not signed in' });
    }
    return t.accessToken;
  }

  /** Account API bound to this session (401 → refresh → replay). */
  account(sessionId: string): AccountApi {
    return this.client.account((o) => this.getAccessToken(sessionId, o));
  }

  /** Revokes the refresh token, deletes the session, and returns the end-session URL (if an ID token exists). */
  async logout(sessionId: string, opts: { postLogoutRedirectUri?: string; state?: string } = {}): Promise<string | undefined> {
    const data = await this.store.get(sessionId);
    await this.store.delete(sessionId);
    if (data?.tokens?.refreshToken) {
      await this.client.revoke(data.tokens.refreshToken, 'refresh_token');
    }
    if (!data?.tokens?.idToken) {
      return undefined;
    }
    try {
      const o: { idTokenHint: string; postLogoutRedirectUri?: string; state?: string } = { idTokenHint: data.tokens.idToken };
      if (opts.postLogoutRedirectUri !== undefined) {
        o.postLogoutRedirectUri = opts.postLogoutRedirectUri;
      }
      if (opts.state !== undefined) {
        o.state = opts.state;
      }
      return await this.client.endSessionUrl(o);
    } catch {
      return undefined;
    }
  }
}

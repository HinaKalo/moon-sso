/**
 * Browser token manager (sdk-spec §1, §7): access token in memory only,
 * refresh token and DPoP key in the persistent store, proactive refresh at
 * 75 % of the lifetime, single-flight refresh across tabs via a named lock
 * with re-read of the store, and BroadcastChannel sync of new tokens.
 */

import type { Discovery } from './shared/discovery.js';
import { DPoP } from './shared/dpop.js';
import type { WebCryptoKeyPair } from './shared/encoding.js';
import { MoonSsoError } from './shared/errors.js';
import type { HttpClient } from './shared/http.js';
import { type IdTokenClaims, type JwksCache, validateIdToken } from './shared/jose.js';
import { requestToken, type TokenResponse } from './shared/oauth.js';
import { Emitter, SingleFlight } from './shared/util.js';
import type { KeyValueStore, LockProvider, TabChannel } from './storage.js';

/** What is persisted between page loads. The access token never is. */
export interface StoredSession {
  v: 1;
  refreshToken: string;
  /** Incremented on every rotation; lets tabs detect that another tab already refreshed. */
  gen: number;
  idToken?: string;
  claims?: IdTokenClaims;
  scope?: string;
  sub: string;
  updatedAt: number;
}

export interface AccessTokenState {
  accessToken: string;
  /** epoch ms */
  issuedAt: number;
  /** epoch ms */
  expiresAt: number;
  scope?: string;
  gen: number;
}

export interface TokenManagerEvents {
  tokens: AccessTokenState;
  sessionExpired: MoonSsoError;
  /** Another tab signed out. */
  remoteLogout: undefined;
  error: unknown;
}

type ChannelMessage =
  | { t: 'tokens'; clientId: string; state: AccessTokenState; idToken?: string; claims?: IdTokenClaims }
  | { t: 'expired'; clientId: string }
  | { t: 'logout'; clientId: string }
  | { t: 'login'; clientId: string };

export interface TokenManagerOptions {
  issuer: string;
  clientId: string;
  http: HttpClient;
  discovery: Discovery;
  jwks: JwksCache;
  store: KeyValueStore;
  locks: LockProvider;
  channel: TabChannel;
  /** Use DPoP-bound refresh tokens (default true; required by clients with require_dpop). */
  dpop: boolean;
  keyPrefix: string;
  refreshRatio?: number;
  clockSkewSeconds?: number;
  now?: () => number;
}

const MIN_REFRESH_DELAY_MS = 5_000;

export class TokenManager {
  readonly events = new Emitter<TokenManagerEvents>();
  private readonly o: TokenManagerOptions;
  private readonly now: () => number;
  private readonly ratio: number;
  private readonly flight = new SingleFlight<string, AccessTokenState>();
  private access: AccessTokenState | undefined;
  private session: StoredSession | undefined;
  private dpopInstance: Promise<DPoP> | undefined;
  private timer: ReturnType<typeof setTimeout> | undefined;
  private unsubscribe: (() => void) | undefined;
  private initialized: Promise<void> | undefined;
  /** Network calls made to the token endpoint for refresh (diagnostics and tests). */
  refreshCount = 0;

  constructor(opts: TokenManagerOptions) {
    this.o = opts;
    this.now = opts.now ?? Date.now;
    this.ratio = Math.min(Math.max(opts.refreshRatio ?? 0.75, 0.1), 0.95);
  }

  private get sessionKey(): string {
    return `${this.o.keyPrefix}:session`;
  }

  private get dpopKey(): string {
    return `${this.o.keyPrefix}:dpop`;
  }

  private get lockName(): string {
    return `${this.o.keyPrefix}:refresh`;
  }

  /** Loads the persisted session and subscribes to other tabs. Idempotent. */
  init(): Promise<void> {
    if (!this.initialized) {
      this.initialized = (async () => {
        this.unsubscribe = this.o.channel.subscribe((m) => this.onChannel(m));
        const s = await this.o.store.get<StoredSession>(this.sessionKey);
        if (s && s.v === 1 && typeof s.refreshToken === 'string') {
          if (this.o.dpop && !(await this.o.store.get<WebCryptoKeyPair>(this.dpopKey))) {
            // The refresh token is bound to a key that no longer exists: unusable.
            await this.o.store.delete(this.sessionKey);
            return;
          }
          this.session = s;
        }
      })();
    }
    return this.initialized;
  }

  close(): void {
    this.clearTimer();
    this.unsubscribe?.();
    this.unsubscribe = undefined;
  }

  get hasSession(): boolean {
    return this.session !== undefined;
  }

  get currentSession(): StoredSession | undefined {
    return this.session;
  }

  get currentAccess(): AccessTokenState | undefined {
    return this.access;
  }

  /** The per-installation DPoP key (created and persisted on first use). */
  getDPoP(): Promise<DPoP> {
    if (!this.dpopInstance) {
      this.dpopInstance = this.o.locks
        .withLock(`${this.o.keyPrefix}:dpop-init`, async () => {
          let pair = await this.o.store.get<WebCryptoKeyPair>(this.dpopKey);
          if (!pair || !pair.privateKey || !pair.publicKey) {
            const fresh = await DPoP.generate({ extractable: false, now: this.now });
            await this.o.store.set(this.dpopKey, fresh.keyPair);
            pair = fresh.keyPair;
            return fresh;
          }
          return DPoP.fromKeyPair(pair, { now: this.now });
        })
        .catch((e: unknown) => {
          this.dpopInstance = undefined;
          throw e;
        });
    }
    return this.dpopInstance;
  }

  /** DPoP instance when enabled, undefined otherwise. */
  async dpopIfEnabled(): Promise<DPoP | undefined> {
    return this.o.dpop ? this.getDPoP() : undefined;
  }

  private needsRefresh(a: AccessTokenState): boolean {
    const lifetime = a.expiresAt - a.issuedAt;
    return this.now() >= a.issuedAt + lifetime * this.ratio;
  }

  private isExpired(a: AccessTokenState): boolean {
    return this.now() >= a.expiresAt - 5_000;
  }

  /**
   * Returns a valid access token, refreshing when 75 % of its lifetime has
   * passed (checked on every call, so waking from sleep is covered). When a
   * proactive refresh fails transiently, the still-valid token is returned.
   */
  async getAccessToken(opts: { force?: boolean; rejected?: string } = {}): Promise<string> {
    await this.init();
    const a = this.access;
    if (!opts.force && a && !this.needsRefresh(a)) {
      return a.accessToken;
    }
    try {
      return (await this.refresh(opts.rejected ?? (opts.force ? a?.accessToken : undefined))).accessToken;
    } catch (e) {
      if (!opts.force && a && !this.isExpired(a) && e instanceof MoonSsoError && e.error !== 'invalid_grant' && e.error !== 'login_required') {
        return a.accessToken;
      }
      throw e;
    }
  }

  /** Single-flight refresh: one per tab, serialized across tabs by the named lock. */
  refresh(rejected?: string): Promise<AccessTokenState> {
    return this.flight.run('refresh', () => this.o.locks.withLock(this.lockName, () => this.refreshLocked(rejected)));
  }

  private async refreshLocked(rejected: string | undefined): Promise<AccessTokenState> {
    // Re-read: another tab may have rotated the token or signed out while we waited.
    const stored = await this.o.store.get<StoredSession>(this.sessionKey);
    if (!stored) {
      const hadSession = this.session !== undefined;
      this.session = undefined;
      this.access = undefined;
      this.clearTimer();
      const err = new MoonSsoError({ error: 'login_required', error_description: 'no active session' });
      if (hadSession) {
        this.events.emit('sessionExpired', err);
      }
      throw err;
    }
    this.session = stored;
    const a = this.access;
    if (a && a.gen === stored.gen && a.accessToken !== rejected && !this.needsRefresh(a)) {
      return a; // another tab refreshed and broadcast the result
    }
    const disc = await this.o.discovery.get();
    const dpop = await this.dpopIfEnabled();
    let resp: TokenResponse;
    this.refreshCount++;
    try {
      resp = await requestToken(
        this.o.http,
        disc.token_endpoint,
        { grant_type: 'refresh_token', refresh_token: stored.refreshToken },
        { auth: { clientId: this.o.clientId, method: 'none' }, dpop },
      );
    } catch (e) {
      if (e instanceof MoonSsoError && e.error === 'invalid_grant') {
        await this.expire(e);
      }
      throw e;
    }
    let claims = stored.claims;
    if (resp.id_token) {
      claims = await validateIdToken(resp.id_token, this.o.jwks, {
        issuer: this.o.issuer,
        clientId: this.o.clientId,
        accessToken: resp.access_token,
        expectedSub: stored.sub,
        clockSkewSeconds: this.o.clockSkewSeconds,
        now: this.now,
      });
    }
    return this.commit(resp, stored.sub, claims, stored);
  }

  /** Persists a token response (login or refresh), updates memory and notifies other tabs. */
  async commit(resp: TokenResponse, sub: string, claims: IdTokenClaims | undefined, prev?: StoredSession): Promise<AccessTokenState> {
    const refreshToken = resp.refresh_token ?? prev?.refreshToken;
    if (!refreshToken) {
      throw new MoonSsoError({
        error: 'invalid_response',
        error_description: 'no refresh token issued; request the offline_access scope or enable refresh_token for this client',
      });
    }
    if (this.o.dpop) {
      // The refresh token is bound to this key; make sure it is persisted too.
      await this.getDPoP();
    }
    const now = this.now();
    const next: StoredSession = {
      v: 1,
      refreshToken,
      gen: (prev?.gen ?? 0) + 1,
      sub,
      updatedAt: now,
    };
    const idToken = resp.id_token ?? prev?.idToken;
    if (idToken) {
      next.idToken = idToken;
    }
    if (claims) {
      next.claims = claims;
    }
    const scope = resp.scope ?? prev?.scope;
    if (scope !== undefined) {
      next.scope = scope;
    }
    // Rotation: persist the new refresh token before anything else uses it.
    await this.o.store.set(this.sessionKey, next);
    this.session = next;
    const state: AccessTokenState = {
      accessToken: resp.access_token,
      issuedAt: now,
      expiresAt: now + resp.expires_in * 1000,
      gen: next.gen,
    };
    if (scope !== undefined) {
      state.scope = scope;
    }
    this.access = state;
    this.schedule();
    const msg: ChannelMessage = { t: 'tokens', clientId: this.o.clientId, state };
    if (idToken) {
      msg.idToken = idToken;
    }
    if (claims) {
      msg.claims = claims;
    }
    this.o.channel.post(msg);
    this.events.emit('tokens', state);
    return state;
  }

  /** Called after a successful login in this tab. */
  announceLogin(): void {
    this.o.channel.post({ t: 'login', clientId: this.o.clientId } satisfies ChannelMessage);
  }

  private async expire(err: MoonSsoError): Promise<void> {
    await this.clearLocal();
    this.o.channel.post({ t: 'expired', clientId: this.o.clientId } satisfies ChannelMessage);
    this.events.emit('sessionExpired', err);
  }

  /** Removes the session from storage and memory (keeps the DPoP key). */
  async clearLocal(): Promise<void> {
    this.clearTimer();
    this.access = undefined;
    this.session = undefined;
    try {
      await this.o.store.delete(this.sessionKey);
    } catch (e) {
      this.events.emit('error', e);
    }
  }

  /** Signs this tab out and tells the other tabs. */
  async logoutLocal(): Promise<void> {
    await this.clearLocal();
    this.o.channel.post({ t: 'logout', clientId: this.o.clientId } satisfies ChannelMessage);
  }

  private onChannel(raw: unknown): void {
    if (!raw || typeof raw !== 'object') {
      return;
    }
    const m = raw as ChannelMessage;
    if (m.clientId !== this.o.clientId) {
      return;
    }
    switch (m.t) {
      case 'tokens': {
        if (!this.access || m.state.gen >= this.access.gen || m.state.issuedAt > this.access.issuedAt) {
          this.access = m.state;
          if (this.session) {
            this.session = { ...this.session, gen: m.state.gen };
            if (m.idToken) {
              this.session.idToken = m.idToken;
            }
            if (m.claims) {
              this.session.claims = m.claims;
            }
          }
          this.schedule();
          this.events.emit('tokens', m.state);
        }
        break;
      }
      case 'login':
        void this.o.store.get<StoredSession>(this.sessionKey).then((s) => {
          if (s) {
            this.session = s;
          }
        });
        break;
      case 'expired':
        if (this.session || this.access) {
          this.clearTimer();
          this.session = undefined;
          this.access = undefined;
          this.events.emit('sessionExpired', new MoonSsoError({ error: 'invalid_grant', error_description: 'session expired in another tab' }));
        }
        break;
      case 'logout':
        if (this.session || this.access) {
          this.clearTimer();
          this.session = undefined;
          this.access = undefined;
          this.events.emit('remoteLogout', undefined);
        }
        break;
      default:
        break;
    }
  }

  private clearTimer(): void {
    if (this.timer !== undefined) {
      clearTimeout(this.timer);
      this.timer = undefined;
    }
  }

  /** Proactive refresh at `refreshRatio` of the lifetime. */
  private schedule(): void {
    this.clearTimer();
    const a = this.access;
    if (!a) {
      return;
    }
    const at = a.issuedAt + (a.expiresAt - a.issuedAt) * this.ratio;
    const delay = Math.max(at - this.now(), MIN_REFRESH_DELAY_MS);
    this.timer = setTimeout(() => {
      this.timer = undefined;
      this.refresh().catch((e: unknown) => {
        this.events.emit('error', e);
        // Transient failure: try again later while the token is still valid.
        if (e instanceof MoonSsoError && e.error !== 'invalid_grant' && e.error !== 'login_required' && this.access && !this.isExpired(this.access)) {
          this.timer = setTimeout(() => {
            this.timer = undefined;
            this.schedule();
          }, Math.min(30_000, Math.max(MIN_REFRESH_DELAY_MS, (this.access.expiresAt - this.now()) / 4)));
          unref(this.timer);
        }
      });
    }, delay);
    unref(this.timer);
  }
}

/** Lets Node.js exit while a refresh timer is pending (no-op in browsers). */
function unref(t: unknown): void {
  if (t && typeof t === 'object' && 'unref' in t && typeof (t as { unref: unknown }).unref === 'function') {
    (t as { unref: () => void }).unref();
  }
}

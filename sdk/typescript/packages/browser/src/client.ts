/**
 * MoonSso: the browser SDK facade.
 */

import {
  AccountApi,
  type AuthorizedFetch,
  type AvatarInput,
  type ChangePasswordInput,
  createAuthorizedFetch,
  type MoonEvent,
  parseEvent,
  type Profile,
  profileFromEvent,
  type ProfileUpdate,
  type UpdateOptions,
} from './shared/account.js';
import { Discovery, type DiscoveryDocument } from './shared/discovery.js';
import { errorFromBody, invalidResponse, MoonSsoError, OtpRequiredError } from './shared/errors.js';
import { type FetchLike, HttpClient, trimSlash } from './shared/http.js';
import { type IdTokenClaims, isObject, JwksCache, validateIdToken } from './shared/jose.js';
import {
  buildEndSessionUrl,
  oauthPost,
  parseAuthorizationResponse,
  requestToken,
  revokeToken,
  type TokenResponse,
} from './shared/oauth.js';
import { createPkce, randomState } from './shared/pkce.js';
import { EventStream, type SseMessage } from './shared/sse.js';
import { Emitter } from './shared/util.js';
import {
  BroadcastTabChannel,
  IndexedDBStore,
  InProcessLockProvider,
  type KeyValueStore,
  type LockProvider,
  MemoryStore,
  NoopTabChannel,
  type TabChannel,
  WebLocksProvider,
} from './storage.js';
import { type AccessTokenState, TokenManager } from './token-manager.js';

export const DEFAULT_SCOPE = 'openid profile offline_access';

export interface MoonSsoOptions {
  /** e.g. https://sso.moonl.cloud — everything else is discovered. */
  issuer: string;
  clientId: string;
  /** Registered redirect URI for the redirect flow. */
  redirectUri?: string;
  /** Registered post-logout redirect URI. */
  postLogoutRedirectUri?: string;
  /** Default scope (default "openid profile offline_access"). */
  scope?: string;
  /** DPoP-bound refresh tokens (default true; sdk-spec §3). */
  dpop?: boolean;
  /** Persistent store (default IndexedDB, in-memory when unavailable). */
  storage?: KeyValueStore;
  /** Cross-tab lock (default Web Locks, in-process when unavailable). */
  locks?: LockProvider;
  /** Tab sync channel (default BroadcastChannel; pass null to disable). */
  channel?: TabChannel | null;
  fetch?: FetchLike;
  /** Navigation used for login / end-session redirects (default location.assign). */
  navigate?: (url: string) => void;
  /** Fraction of the access-token lifetime after which it is refreshed (default 0.75). */
  refreshRatio?: number;
  clockSkewSeconds?: number;
  /** Prefix for storage keys, lock and channel names (default "moon-sso:<clientId>"). */
  storageKeyPrefix?: string;
  /** Pending redirect logins older than this are discarded (default 10 minutes). */
  pendingLoginTtlMs?: number;
  /** Request timeout for non-streaming calls (default 30 s). */
  timeoutMs?: number;
  now?: () => number;
}

export interface LoginOptions {
  scope?: string;
  prompt?: 'none' | 'login' | 'consent' | 'select_account';
  loginHint?: string;
  maxAge?: number;
  /** Where the app wants to go after the callback (returned by handleRedirectCallback). */
  returnTo?: string;
  redirectUri?: string;
  /** Additional authorization parameters (cannot override PKCE/state/nonce). */
  extraParams?: Record<string, string>;
}

export interface CallbackResult {
  user: IdTokenClaims | undefined;
  returnTo: string | undefined;
}

export interface SignInResult {
  user: IdTokenClaims | undefined;
}

export interface RegisterInput {
  username: string;
  password: string;
  displayName?: string;
  scope?: string;
}

export interface LogoutOptions {
  /** Redirect to end_session_endpoint afterwards (ends the SSO session). */
  endSession?: boolean;
  postLogoutRedirectUri?: string;
  state?: string;
}

export interface MoonSsoEvents {
  /** New tokens (login, refresh, or another tab). */
  tokens: AccessTokenState;
  login: IdTokenClaims | undefined;
  logout: undefined;
  /** The refresh token is dead (invalid_grant); sign in again. */
  sessionExpired: MoonSsoError;
  profileChanged: Profile;
  /** Any live event received over SSE. */
  event: MoonEvent;
  /** Live event stream connected. */
  eventsConnected: undefined;
  error: unknown;
}

interface PendingLogin {
  verifier: string;
  nonce: string;
  redirectUri: string;
  returnTo?: string;
  createdAt: number;
}

interface PendingChallenge {
  verifier: string;
  challenge: string;
  scope: string;
  createdAt: number;
}

const SESSION_EVENTS = new Set(['user.password_changed', 'user.disabled', 'user.deleted', 'consent.revoked']);

export class MoonSso {
  readonly issuer: string;
  readonly clientId: string;
  readonly events: Emitter<MoonSsoEvents>;
  /** Low-level token manager (exposed for advanced use and tests). */
  readonly tokens: TokenManager;
  readonly http: HttpClient;
  private readonly o: MoonSsoOptions;
  private readonly discovery: Discovery;
  private readonly jwks: JwksCache;
  private readonly store: KeyValueStore;
  private readonly locks: LockProvider;
  private readonly channel: TabChannel;
  private readonly prefix: string;
  private readonly now: () => number;
  private readonly account: AccountApi;
  private readonly challenges = new Map<string, PendingChallenge>();
  private stream: EventStream | undefined;
  /** fetch with Authorization: Bearer, 401 → refresh once → replay once. */
  readonly fetch: AuthorizedFetch;

  constructor(opts: MoonSsoOptions) {
    if (!opts.issuer || !opts.clientId) {
      throw new MoonSsoError({ error: 'invalid_configuration', error_description: 'issuer and clientId are required' });
    }
    this.o = opts;
    this.issuer = trimSlash(opts.issuer);
    this.clientId = opts.clientId;
    this.now = opts.now ?? Date.now;
    this.prefix = opts.storageKeyPrefix ?? `moon-sso:${opts.clientId}`;
    this.events = new Emitter<MoonSsoEvents>((e) => this.events.emit('error', e));
    this.http = new HttpClient({ fetch: opts.fetch, timeoutMs: opts.timeoutMs });
    this.discovery = new Discovery(this.issuer, this.http, { now: this.now });
    this.jwks = new JwksCache({ http: this.http, jwksUri: async () => (await this.discovery.get()).jwks_uri, now: this.now });
    this.store = opts.storage ?? (IndexedDBStore.isAvailable() ? new IndexedDBStore() : new MemoryStore());
    const locks = opts.locks ?? (WebLocksProvider.isAvailable() ? new WebLocksProvider() : new InProcessLockProvider());
    this.locks = locks;
    this.channel =
      opts.channel === null ? new NoopTabChannel() : (opts.channel ?? (BroadcastTabChannel.isAvailable() ? new BroadcastTabChannel(this.prefix) : new NoopTabChannel()));
    this.tokens = new TokenManager({
      issuer: this.issuer,
      clientId: this.clientId,
      http: this.http,
      discovery: this.discovery,
      jwks: this.jwks,
      store: this.store,
      locks,
      channel: this.channel,
      dpop: opts.dpop ?? true,
      keyPrefix: this.prefix,
      refreshRatio: opts.refreshRatio,
      clockSkewSeconds: opts.clockSkewSeconds,
      now: this.now,
    });
    this.tokens.events.on('tokens', (s) => this.events.emit('tokens', s));
    this.tokens.events.on('sessionExpired', (e) => {
      void this.stopEvents();
      this.account.setCached(undefined);
      this.events.emit('sessionExpired', e);
    });
    this.tokens.events.on('remoteLogout', () => {
      void this.stopEvents();
      this.account.setCached(undefined);
      this.events.emit('logout', undefined);
    });
    this.tokens.events.on('error', (e) => this.events.emit('error', e));
    this.fetch = createAuthorizedFetch({ http: this.http, getAccessToken: (o) => this.tokens.getAccessToken(o) });
    this.account = new AccountApi({
      apiBase: `${this.issuer}/api/v1`,
      authorizedFetch: this.fetch,
      onProfile: (p) => this.events.emit('profileChanged', p),
      // The server's CORS preflight does not allow If-None-Match.
      conditionalGet: false,
    });
  }

  /** Restores a persisted session. Resolves to true when a session exists. */
  async init(): Promise<boolean> {
    await this.tokens.init();
    return this.tokens.hasSession;
  }

  /** Stops timers, the event stream and the tab channel. */
  async close(): Promise<void> {
    await this.stopEvents();
    this.tokens.close();
    this.channel.close();
  }

  on<K extends keyof MoonSsoEvents>(event: K, fn: (payload: MoonSsoEvents[K]) => void): () => void {
    return this.events.on(event, fn);
  }

  /** Discovery document (cached for one hour). */
  getDiscovery(): Promise<DiscoveryDocument> {
    return this.discovery.get();
  }

  get isAuthenticated(): boolean {
    return this.tokens.hasSession;
  }

  /** Claims of the latest validated ID token. */
  get user(): IdTokenClaims | undefined {
    return this.tokens.currentSession?.claims;
  }

  /** Last known profile (from getMe, writes or live events). */
  get profile(): Profile | undefined {
    return this.account.profile;
  }

  /** A valid access token (refreshing when needed). */
  getAccessToken(opts: { force?: boolean } = {}): Promise<string> {
    return this.tokens.getAccessToken(opts);
  }

  // -------------------------------------------------------------------------
  // Redirect login

  private get pendingKey(): string {
    return `${this.prefix}:pending`;
  }

  /**
   * Read-modify-write of the pending-login record (state → PKCE/nonce) under
   * a lock, dropping entries older than the pending TTL so abandoned logins
   * do not accumulate.
   */
  private updatePending<T>(fn: (all: Record<string, PendingLogin>) => T): Promise<T> {
    return this.locks.withLock(`${this.prefix}:pending`, async () => {
      const ttl = this.o.pendingLoginTtlMs ?? 600_000;
      const now = this.now();
      const all: Record<string, PendingLogin> = {};
      for (const [k, v] of Object.entries((await this.store.get<Record<string, PendingLogin>>(this.pendingKey)) ?? {})) {
        if (v && now - v.createdAt <= ttl) {
          all[k] = v;
        }
      }
      const out = fn(all);
      if (Object.keys(all).length === 0) {
        await this.store.delete(this.pendingKey);
      } else {
        await this.store.set(this.pendingKey, all);
      }
      return out;
    });
  }

  /** Builds the authorization URL and stores the PKCE/state/nonce for the callback. */
  async buildLoginUrl(opts: LoginOptions = {}): Promise<string> {
    const redirectUri = opts.redirectUri ?? this.o.redirectUri;
    if (!redirectUri) {
      throw new MoonSsoError({ error: 'invalid_configuration', error_description: 'redirectUri is required for redirect login' });
    }
    const disc = await this.discovery.get();
    const pkce = await createPkce();
    const state = randomState();
    const nonce = randomState();
    const u = new URL(disc.authorization_endpoint);
    for (const [k, v] of Object.entries(opts.extraParams ?? {})) {
      u.searchParams.set(k, v);
    }
    const params: Record<string, string> = {
      response_type: 'code',
      client_id: this.clientId,
      redirect_uri: redirectUri,
      scope: opts.scope ?? this.o.scope ?? DEFAULT_SCOPE,
      state,
      nonce,
      code_challenge: pkce.challenge,
      code_challenge_method: 'S256',
    };
    if (opts.prompt) {
      params['prompt'] = opts.prompt;
    }
    if (opts.loginHint) {
      params['login_hint'] = opts.loginHint;
    }
    if (opts.maxAge !== undefined) {
      params['max_age'] = String(opts.maxAge);
    }
    const dpop = await this.tokens.dpopIfEnabled();
    if (dpop) {
      params['dpop_jkt'] = dpop.jkt;
    }
    for (const [k, v] of Object.entries(params)) {
      u.searchParams.set(k, v);
    }
    const pending: PendingLogin = { verifier: pkce.verifier, nonce, redirectUri, createdAt: this.now() };
    if (opts.returnTo !== undefined) {
      pending.returnTo = opts.returnTo;
    }
    await this.updatePending((all) => {
      all[state] = pending;
    });
    return u.toString();
  }

  /** Redirects the browser to the login page. */
  async login(opts: LoginOptions = {}): Promise<void> {
    const url = await this.buildLoginUrl(opts);
    this.navigate(url);
  }

  private navigate(url: string): void {
    if (this.o.navigate) {
      this.o.navigate(url);
      return;
    }
    if (typeof location === 'undefined') {
      throw new MoonSsoError({ error: 'invalid_configuration', error_description: 'no navigate function and no window.location' });
    }
    location.assign(url);
  }

  /** True when `url` looks like an authorization response for this app. */
  isRedirectCallback(url: string = typeof location !== 'undefined' ? location.href : ''): boolean {
    if (!url) {
      return false;
    }
    const q = new URL(url).searchParams;
    return q.has('state') && (q.has('code') || q.has('error'));
  }

  /**
   * Completes the redirect login: validates state and iss, redeems the code
   * with PKCE (and DPoP), validates the ID token including nonce and at_hash.
   */
  async handleRedirectCallback(url: string = typeof location !== 'undefined' ? location.href : ''): Promise<CallbackResult> {
    if (!url) {
      throw new MoonSsoError({ error: 'invalid_request', error_description: 'no callback URL' });
    }
    await this.tokens.init();
    const q = new URL(url).searchParams;
    const state = q.get('state');
    if (!state) {
      throw new MoonSsoError({ error: 'invalid_state', error_description: 'callback has no state' });
    }
    // One-time use regardless of the outcome; expired entries were pruned.
    const pending = await this.updatePending((all) => {
      const p = all[state];
      delete all[state];
      return p;
    });
    if (!pending) {
      throw new MoonSsoError({ error: 'invalid_state', error_description: 'unknown or expired login state' });
    }
    const resp = parseAuthorizationResponse(q, { state, issuer: this.issuer });
    const disc = await this.discovery.get();
    const dpop = await this.tokens.dpopIfEnabled();
    const tokens = await requestToken(
      this.http,
      disc.token_endpoint,
      { grant_type: 'authorization_code', code: resp.code, redirect_uri: pending.redirectUri, code_verifier: pending.verifier },
      { auth: { clientId: this.clientId, method: 'none' }, dpop },
    );
    const user = await this.completeLogin(tokens, pending.nonce);
    if (typeof history !== 'undefined' && typeof location !== 'undefined' && url === location.href) {
      const clean = new URL(url);
      for (const p of ['code', 'state', 'iss', 'session_state', 'error', 'error_description']) {
        clean.searchParams.delete(p);
      }
      history.replaceState(history.state, '', clean.toString());
    }
    return { user, returnTo: pending.returnTo };
  }

  private async completeLogin(tokens: TokenResponse, nonce: string | undefined): Promise<IdTokenClaims | undefined> {
    let claims: IdTokenClaims | undefined;
    if (tokens.id_token) {
      claims = await validateIdToken(tokens.id_token, this.jwks, {
        issuer: this.issuer,
        clientId: this.clientId,
        nonce,
        accessToken: tokens.access_token,
        clockSkewSeconds: this.o.clockSkewSeconds,
        now: this.now,
      });
    }
    const sub = claims?.sub ?? (await this.subFromApi(tokens.access_token));
    this.account.setCached(undefined);
    await this.tokens.commit(tokens, sub, claims);
    this.tokens.announceLogin();
    this.events.emit('login', claims);
    return claims;
  }

  private async subFromApi(accessToken: string): Promise<string> {
    const res = await this.http.request(`${this.issuer}/api/v1/me`, {
      headers: { Authorization: `Bearer ${accessToken}`, Accept: 'application/json' },
      what: 'GET /me',
    });
    if (!res.ok) {
      throw errorFromBody(res.status, await res.json().catch(() => ({})));
    }
    const p = (await res.json()) as unknown;
    if (!isObject(p) || typeof p['sub'] !== 'string') {
      throw invalidResponse('cannot determine the subject (request the openid scope)');
    }
    return p['sub'];
  }

  // -------------------------------------------------------------------------
  // First-party in-app login and registration (sdk-spec §2)

  private async challengeEndpoint(): Promise<string> {
    const d = await this.discovery.get();
    return d.authorization_challenge_endpoint ?? `${this.issuer}/oauth/authorize-challenge`;
  }

  private sweepChallenges(): void {
    const now = this.now();
    for (const [k, v] of this.challenges) {
      if (now - v.createdAt > 5 * 60_000) {
        this.challenges.delete(k);
      }
    }
  }

  private async redeemDirectCode(code: string, verifier: string): Promise<IdTokenClaims | undefined> {
    const disc = await this.discovery.get();
    const dpop = await this.tokens.dpopIfEnabled();
    // First-party codes are redeemed without redirect_uri.
    const tokens = await requestToken(
      this.http,
      disc.token_endpoint,
      { grant_type: 'authorization_code', code, code_verifier: verifier },
      { auth: { clientId: this.clientId, method: 'none' }, dpop },
    );
    return this.completeLogin(tokens, undefined);
  }

  private codeFrom(status: number, body: unknown): string {
    if (status === 200 && isObject(body) && typeof body['authorization_code'] === 'string') {
      return body['authorization_code'];
    }
    if (status >= 200 && status < 300) {
      throw invalidResponse('response has no authorization_code', status);
    }
    throw errorFromBody(status, body ?? {});
  }

  /**
   * In-app username/password login. Throws OtpRequiredError when a second
   * factor is needed: ask the user for the code and call verifyOtp().
   * Throws PasswordChangeRequiredError (with changeUrl) after an admin reset.
   */
  async signIn(username: string, password: string, opts: { scope?: string } = {}): Promise<SignInResult> {
    await this.tokens.init();
    this.sweepChallenges();
    const pkce = await createPkce();
    const scope = opts.scope ?? this.o.scope ?? DEFAULT_SCOPE;
    const r = await oauthPost(
      this.http,
      await this.challengeEndpoint(),
      { username, password, scope, code_challenge: pkce.challenge, code_challenge_method: 'S256' },
      { auth: { clientId: this.clientId, method: 'none' }, dpop: await this.tokens.dpopIfEnabled(), what: 'sign-in' },
    );
    let code: string;
    try {
      code = this.codeFrom(r.status, r.body);
    } catch (e) {
      if (e instanceof OtpRequiredError) {
        this.challenges.set(e.authSession, { verifier: pkce.verifier, challenge: pkce.challenge, scope, createdAt: this.now() });
      }
      throw e;
    }
    return { user: await this.redeemDirectCode(code, pkce.verifier) };
  }

  /** Second step of signIn: submits the one-time code for `authSession`. */
  async verifyOtp(authSession: string, otp: string): Promise<SignInResult> {
    this.sweepChallenges();
    const pending = this.challenges.get(authSession);
    if (!pending) {
      throw new MoonSsoError({ error: 'invalid_request', error_description: 'unknown or expired auth_session; sign in again' });
    }
    const r = await oauthPost(
      this.http,
      await this.challengeEndpoint(),
      { auth_session: authSession, otp, scope: pending.scope, code_challenge: pending.challenge, code_challenge_method: 'S256' },
      { auth: { clientId: this.clientId, method: 'none' }, dpop: await this.tokens.dpopIfEnabled(), what: 'OTP verification' },
    );
    let code: string;
    try {
      code = this.codeFrom(r.status, r.body);
    } catch (e) {
      if (e instanceof OtpRequiredError && e.authSession !== authSession) {
        this.challenges.delete(authSession);
        this.challenges.set(e.authSession, { ...pending, createdAt: this.now() });
      } else if (!(e instanceof OtpRequiredError)) {
        this.challenges.delete(authSession);
      }
      throw e;
    }
    this.challenges.delete(authSession);
    return { user: await this.redeemDirectCode(code, pending.verifier) };
  }

  /** In-app registration; signs the new user in. 422 errors carry `field`; 403 means registration is closed. */
  async register(input: RegisterInput): Promise<SignInResult> {
    await this.tokens.init();
    const pkce = await createPkce();
    const url = `${this.issuer}/api/v1/native/register`;
    const form = {
      username: input.username,
      password: input.password,
      display_name: input.displayName,
      scope: input.scope ?? this.o.scope ?? DEFAULT_SCOPE,
      code_challenge: pkce.challenge,
      code_challenge_method: 'S256',
    };
    const dpop = await this.tokens.dpopIfEnabled();
    const post = (dpopHtu?: string) =>
      oauthPost(this.http, url, form, { auth: { clientId: this.clientId, method: 'none' }, dpop, what: 'registration', dpopHtu });
    let r = await post();
    if (dpop && r.status === 400 && isObject(r.body) && r.body['error'] === 'invalid_dpop_proof') {
      // Compatibility: some server versions verify the proof of this endpoint
      // against the authorize-challenge URL. The proof is checked before any
      // account is created, so retrying with that htu is safe.
      r = await post(await this.challengeEndpoint());
    }
    const code = this.codeFrom(r.status, r.body);
    return { user: await this.redeemDirectCode(code, pkce.verifier) };
  }

  /** GET /api/v1/registration: whether self-service registration is open, and the rules. */
  async registrationInfo(): Promise<{ registration_open: boolean; password_min_length: number; username_pattern: string; [k: string]: unknown }> {
    return this.http.json(`${this.issuer}/api/v1/registration`, { what: 'registration info' });
  }

  // -------------------------------------------------------------------------
  // Account API (sdk-spec §4)

  getMe(): Promise<Profile> {
    return this.account.getMe();
  }

  updateProfile(update: ProfileUpdate, opts: UpdateOptions = {}): Promise<Profile> {
    return this.account.updateProfile(update, opts);
  }

  uploadAvatar(image: AvatarInput, contentType?: string): Promise<Profile> {
    return this.account.uploadAvatar(image, contentType);
  }

  deleteAvatar(): Promise<Profile> {
    return this.account.deleteAvatar();
  }

  changePassword(input: ChangePasswordInput): Promise<void> {
    return this.account.changePassword(input);
  }

  /** OIDC userinfo with the current access token. */
  async userinfo(): Promise<Record<string, unknown>> {
    const disc = await this.discovery.get();
    const res = await this.fetch(disc.userinfo_endpoint, { headers: { Accept: 'application/json' }, what: 'userinfo' });
    if (!res.ok) {
      throw errorFromBody(res.status, await res.json().catch(() => ({})));
    }
    return (await res.json()) as Record<string, unknown>;
  }

  // -------------------------------------------------------------------------
  // Live events (sdk-spec §5.1)

  /** Opens the live profile event stream (fetch-based SSE). Idempotent. */
  async startEvents(opts: { lastEventId?: string } = {}): Promise<void> {
    if (this.stream?.isRunning) {
      return;
    }
    const disc = await this.discovery.get();
    const url = disc.moon_events_endpoint ?? `${this.issuer}/api/v1/me/events`;
    const streamOpts: ConstructorParameters<typeof EventStream>[0] = {
      http: this.http,
      url,
      getAccessToken: (o) => this.tokens.getAccessToken(o),
      onMessage: (m) => this.onLiveMessage(m),
      onOpen: () => this.events.emit('eventsConnected', undefined),
      onError: (e) => this.events.emit('error', e),
      isFatal: (e) => e instanceof MoonSsoError && (e.error === 'invalid_grant' || e.error === 'login_required' || e.status === 403),
    };
    if (opts.lastEventId !== undefined) {
      streamOpts.lastEventId = opts.lastEventId;
    }
    this.stream = new EventStream(streamOpts);
    this.stream.start();
  }

  async stopEvents(): Promise<void> {
    const s = this.stream;
    this.stream = undefined;
    await s?.stop();
  }

  /** Last-Event-ID of the live stream (persist it to resume across page loads). */
  get lastEventId(): string | undefined {
    return this.stream?.lastEventId;
  }

  private async onLiveMessage(m: SseMessage): Promise<void> {
    if (m.event === 'resync') {
      await this.account.getMe();
      return;
    }
    if (m.event === 'token_expired' || m.event === 'message') {
      return;
    }
    const ev = parseEvent(m.data);
    if (!ev) {
      return;
    }
    this.events.emit('event', ev);
    if (ev.type === 'user.updated') {
      const base = this.account.profile;
      if (base && base.profile_version > ev.data.profile_version) {
        return; // stale
      }
      const p = profileFromEvent(ev, base);
      this.account.setCached(p);
      this.events.emit('profileChanged', p);
      return;
    }
    if (SESSION_EVENTS.has(ev.type)) {
      // Refresh once: invalid_grant means the session died (sessionExpired is
      // emitted by the token manager); success means this device keeps its session.
      try {
        await this.tokens.getAccessToken({ force: true });
      } catch (e) {
        if (!(e instanceof MoonSsoError && (e.error === 'invalid_grant' || e.error === 'login_required'))) {
          this.events.emit('error', e);
        }
      }
    }
  }

  // -------------------------------------------------------------------------
  // Logout (sdk-spec §2)

  /**
   * Clears local tokens, revokes the refresh token (failures ignored) and
   * optionally redirects to end_session_endpoint.
   */
  async logout(opts: LogoutOptions = {}): Promise<void> {
    await this.tokens.init();
    const session = this.tokens.currentSession;
    await this.stopEvents();
    await this.tokens.logoutLocal();
    this.account.setCached(undefined);
    let disc: DiscoveryDocument | undefined;
    try {
      disc = await this.discovery.get();
    } catch {
      disc = undefined;
    }
    if (session && disc?.revocation_endpoint) {
      await revokeToken(this.http, disc.revocation_endpoint, session.refreshToken, 'refresh_token', { clientId: this.clientId, method: 'none' });
    }
    this.events.emit('logout', undefined);
    if (opts.endSession) {
      if (!disc?.end_session_endpoint) {
        throw new MoonSsoError({ error: 'network', error_description: 'cannot reach the server to end the SSO session' });
      }
      this.navigate(
        buildEndSessionUrl(disc.end_session_endpoint, {
          idTokenHint: session?.idToken,
          clientId: this.clientId,
          postLogoutRedirectUri: opts.postLogoutRedirectUri ?? this.o.postLogoutRedirectUri,
          state: opts.state,
        }),
      );
    }
  }
}

/** Creates the client and restores any persisted session. */
export async function createMoonSso(opts: MoonSsoOptions): Promise<MoonSso> {
  const sso = new MoonSso(opts);
  await sso.init();
  return sso;
}

/**
 * Confidential-client core for Node.js servers (BFF / web apps): discovery,
 * authorization URL, callback exchange with full ID token validation,
 * refresh with the retry rules, userinfo, revocation, end-session URL,
 * server-side user registration and a client_credentials token cache.
 */

import { AccountApi, createAuthorizedFetch, type TokenProvider } from './shared/account.js';
import { Discovery, type DiscoveryDocument } from './shared/discovery.js';
import { errorFromResponse, MoonSsoError } from './shared/errors.js';
import { type FetchLike, HttpClient, readJson, trimSlash } from './shared/http.js';
import { type IdTokenClaims, JwksCache, validateIdToken } from './shared/jose.js';
import {
  buildEndSessionUrl,
  type ClientAuth,
  type ClientAuthMethod,
  parseAuthorizationResponse,
  requestToken,
  revokeToken,
  type TokenResponse,
} from './shared/oauth.js';
import { createPkce, randomState } from './shared/pkce.js';
import { SingleFlight } from './shared/util.js';
import { ChangesFeed } from './feed.js';
import { USER_AGENT } from './version.js';

export const DEFAULT_SCOPE = 'openid profile offline_access';

export interface MoonSsoClientOptions {
  /** e.g. https://sso.moonl.cloud */
  issuer: string;
  clientId: string;
  clientSecret?: string;
  /** Default client_secret_basic when a secret is set, none otherwise. */
  tokenEndpointAuthMethod?: ClientAuthMethod;
  /** Registered callback URL (exact match). */
  redirectUri?: string;
  postLogoutRedirectUri?: string;
  /** Default "openid profile offline_access". */
  scope?: string;
  fetch?: FetchLike;
  /** Appended to the SDK User-Agent, e.g. "my-app/2.1". */
  userAgentSuffix?: string;
  timeoutMs?: number;
  clockSkewSeconds?: number;
  now?: () => number;
}

/** Tokens of one signed-in user. `expiresAt` is in epoch seconds. */
export interface TokenSet {
  accessToken: string;
  tokenType: string;
  expiresAt: number;
  refreshToken?: string;
  idToken?: string;
  scope?: string;
  /** Validated ID token claims (kept from the login when a refresh returns no ID token). */
  claims?: IdTokenClaims;
}

/** State of an authorization request; keep it server-side until the callback. */
export interface PendingAuthorization {
  state: string;
  nonce: string;
  codeVerifier: string;
  redirectUri: string;
  returnTo?: string;
  createdAt: number;
}

export interface AuthorizationUrlOptions {
  scope?: string;
  prompt?: 'none' | 'login' | 'consent' | 'select_account';
  loginHint?: string;
  maxAge?: number;
  redirectUri?: string;
  returnTo?: string;
  /** Request a resource-specific audience (RFC 8707). */
  resource?: string;
  responseMode?: 'query' | 'form_post';
  extraParams?: Record<string, string>;
}

export interface RegisterUserInput {
  username: string;
  password: string;
  displayName?: string;
}

export interface RegisterUserResult {
  created: boolean;
  username: string;
  login_hint: string;
  authorization_endpoint: string;
  [k: string]: unknown;
}

export interface RegistrationInfo {
  registration_open: boolean;
  password_min_length: number;
  username_pattern: string;
  client_registration?: string;
  [k: string]: unknown;
}

export class MoonSsoClient {
  readonly issuer: string;
  readonly clientId: string;
  readonly http: HttpClient;
  readonly jwks: JwksCache;
  readonly options: Readonly<MoonSsoClientOptions>;
  private readonly disco: Discovery;
  private readonly auth: ClientAuth;
  private readonly now: () => number;
  private readonly cc = new Map<string, ClientCredentialsProvider>();

  constructor(opts: MoonSsoClientOptions) {
    if (!opts.issuer || !opts.clientId) {
      throw new MoonSsoError({ error: 'invalid_configuration', error_description: 'issuer and clientId are required' });
    }
    this.options = opts;
    this.issuer = trimSlash(opts.issuer);
    this.clientId = opts.clientId;
    this.now = opts.now ?? Date.now;
    this.http = new HttpClient({
      fetch: opts.fetch,
      userAgent: opts.userAgentSuffix ? `${USER_AGENT} ${opts.userAgentSuffix}` : USER_AGENT,
      timeoutMs: opts.timeoutMs,
    });
    this.disco = new Discovery(this.issuer, this.http, { now: this.now });
    this.jwks = new JwksCache({ http: this.http, jwksUri: async () => (await this.disco.get()).jwks_uri, now: this.now });
    this.auth = {
      clientId: opts.clientId,
      clientSecret: opts.clientSecret,
      method: opts.tokenEndpointAuthMethod ?? (opts.clientSecret ? 'client_secret_basic' : 'none'),
    };
  }

  discovery(): Promise<DiscoveryDocument> {
    return this.disco.get();
  }

  /** Base URL of the REST API (…/api/v1). */
  get apiBase(): string {
    return `${this.issuer}/api/v1`;
  }

  /** Builds the authorization URL (PKCE S256, state, nonce). Store `pending` until the callback. */
  async createAuthorizationUrl(opts: AuthorizationUrlOptions = {}): Promise<{ url: string; pending: PendingAuthorization }> {
    const redirectUri = opts.redirectUri ?? this.options.redirectUri;
    if (!redirectUri) {
      throw new MoonSsoError({ error: 'invalid_configuration', error_description: 'redirectUri is required' });
    }
    const disc = await this.disco.get();
    const pkce = await createPkce();
    const pending: PendingAuthorization = {
      state: randomState(),
      nonce: randomState(),
      codeVerifier: pkce.verifier,
      redirectUri,
      createdAt: this.now(),
    };
    if (opts.returnTo !== undefined) {
      pending.returnTo = opts.returnTo;
    }
    const u = new URL(disc.authorization_endpoint);
    for (const [k, v] of Object.entries(opts.extraParams ?? {})) {
      u.searchParams.set(k, v);
    }
    const params: Record<string, string | undefined> = {
      response_type: 'code',
      client_id: this.clientId,
      redirect_uri: redirectUri,
      scope: opts.scope ?? this.options.scope ?? DEFAULT_SCOPE,
      state: pending.state,
      nonce: pending.nonce,
      code_challenge: pkce.challenge,
      code_challenge_method: 'S256',
      prompt: opts.prompt,
      login_hint: opts.loginHint,
      max_age: opts.maxAge === undefined ? undefined : String(opts.maxAge),
      resource: opts.resource,
      response_mode: opts.responseMode,
    };
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined) {
        u.searchParams.set(k, v);
      }
    }
    return { url: u.toString(), pending };
  }

  /**
   * Completes the login: validates state + iss, exchanges the code with the
   * verifier and the exact redirect_uri, validates the ID token (nonce, at_hash).
   * `callback` is the full callback URL, its query string, or form_post parameters.
   */
  async handleCallback(callback: string | URL | URLSearchParams, pending: PendingAuthorization, opts: { maxAgeMs?: number } = {}): Promise<TokenSet> {
    let params: URLSearchParams;
    if (callback instanceof URLSearchParams) {
      params = callback;
    } else if (callback instanceof URL) {
      params = callback.searchParams;
    } else if (/^https?:\/\//i.test(callback)) {
      params = new URL(callback).searchParams;
    } else {
      params = new URLSearchParams(callback.startsWith('?') ? callback.slice(1) : callback);
    }
    if (this.now() - pending.createdAt > (opts.maxAgeMs ?? 600_000)) {
      throw new MoonSsoError({ error: 'invalid_state', error_description: 'login attempt expired; start again' });
    }
    const resp = parseAuthorizationResponse(params, { state: pending.state, issuer: this.issuer });
    const disc = await this.disco.get();
    const tokens = await requestToken(
      this.http,
      disc.token_endpoint,
      { grant_type: 'authorization_code', code: resp.code, redirect_uri: pending.redirectUri, code_verifier: pending.codeVerifier },
      { auth: this.auth },
    );
    return this.toTokenSet(tokens, { nonce: pending.nonce });
  }

  /** Exchanges a first-party authorization code (no redirect_uri). */
  async exchangeDirectCode(code: string, codeVerifier: string): Promise<TokenSet> {
    const disc = await this.disco.get();
    const tokens = await requestToken(this.http, disc.token_endpoint, { grant_type: 'authorization_code', code, code_verifier: codeVerifier }, { auth: this.auth });
    return this.toTokenSet(tokens, {});
  }

  /**
   * Refreshes tokens. Network errors and 502/503/504 are retried once;
   * invalid_grant means the session is over.
   */
  async refresh(refreshToken: string, opts: { scope?: string; previous?: TokenSet } = {}): Promise<TokenSet> {
    const disc = await this.disco.get();
    const tokens = await requestToken(
      this.http,
      disc.token_endpoint,
      { grant_type: 'refresh_token', refresh_token: refreshToken, scope: opts.scope },
      { auth: this.auth },
    );
    const set = await this.toTokenSet(tokens, { expectedSub: opts.previous?.claims?.sub, previous: opts.previous });
    if (!set.refreshToken) {
      set.refreshToken = refreshToken;
    }
    return set;
  }

  private async toTokenSet(t: TokenResponse, check: { nonce?: string; expectedSub?: string | undefined; previous?: TokenSet | undefined }): Promise<TokenSet> {
    const set: TokenSet = {
      accessToken: t.access_token,
      tokenType: t.token_type,
      expiresAt: Math.floor(this.now() / 1000) + t.expires_in,
    };
    if (t.refresh_token) {
      set.refreshToken = t.refresh_token;
    }
    if (t.scope !== undefined) {
      set.scope = t.scope;
    } else if (check.previous?.scope !== undefined) {
      set.scope = check.previous.scope;
    }
    if (t.id_token) {
      set.idToken = t.id_token;
      set.claims = await validateIdToken(t.id_token, this.jwks, {
        issuer: this.issuer,
        clientId: this.clientId,
        nonce: check.nonce,
        accessToken: t.access_token,
        expectedSub: check.expectedSub,
        clockSkewSeconds: this.options.clockSkewSeconds,
        now: this.now,
      });
    } else if (check.previous) {
      if (check.previous.idToken) {
        set.idToken = check.previous.idToken;
      }
      if (check.previous.claims) {
        set.claims = check.previous.claims;
      }
    }
    return set;
  }

  /** OIDC userinfo. */
  async userinfo(accessToken: string): Promise<Record<string, unknown>> {
    const disc = await this.disco.get();
    return this.http.json(disc.userinfo_endpoint, {
      headers: { Authorization: `Bearer ${accessToken}`, Accept: 'application/json' },
      what: 'userinfo',
    });
  }

  /** RFC 7009 revocation; never throws (returns false on failure). */
  async revoke(token: string, hint: 'refresh_token' | 'access_token' = 'refresh_token'): Promise<boolean> {
    let endpoint: string | undefined;
    try {
      endpoint = (await this.disco.get()).revocation_endpoint;
    } catch {
      return false;
    }
    return endpoint ? revokeToken(this.http, endpoint, token, hint, this.auth) : false;
  }

  /** RP-initiated logout URL. */
  async endSessionUrl(opts: { idTokenHint?: string; postLogoutRedirectUri?: string; state?: string } = {}): Promise<string> {
    const disc = await this.disco.get();
    if (!disc.end_session_endpoint) {
      throw new MoonSsoError({ error: 'invalid_response', error_description: 'server has no end_session_endpoint' });
    }
    return buildEndSessionUrl(disc.end_session_endpoint, {
      idTokenHint: opts.idTokenHint,
      clientId: this.clientId,
      postLogoutRedirectUri: opts.postLogoutRedirectUri ?? this.options.postLogoutRedirectUri,
      state: opts.state,
    });
  }

  /** Account API (/api/v1/me…) for a user, given a token provider (see SessionManager.account). */
  account(getAccessToken: TokenProvider): AccountApi {
    return new AccountApi({ apiBase: this.apiBase, authorizedFetch: createAuthorizedFetch({ http: this.http, getAccessToken }) });
  }

  /**
   * POST /api/v1/register: creates an end-user account (client authentication).
   * client_secret_basic sends JSON; client_secret_post sends a form, because
   * the server reads posted client credentials from form fields only.
   */
  async registerUser(input: RegisterUserInput): Promise<RegisterUserResult> {
    const fields: Record<string, string> = { username: input.username, password: input.password };
    if (input.displayName !== undefined) {
      fields['display_name'] = input.displayName;
    }
    const headers: Record<string, string> = { Accept: 'application/json' };
    let body: string;
    if (this.auth.method === 'client_secret_basic' && this.auth.clientSecret) {
      const enc = (s: string) => encodeURIComponent(s).replace(/%20/g, '+');
      headers['Authorization'] = `Basic ${Buffer.from(`${enc(this.clientId)}:${enc(this.auth.clientSecret)}`).toString('base64')}`;
      headers['Content-Type'] = 'application/json';
      body = JSON.stringify(fields);
    } else {
      const form = new URLSearchParams({ ...fields, client_id: this.clientId });
      if (this.auth.clientSecret) {
        form.set('client_secret', this.auth.clientSecret);
      }
      headers['Content-Type'] = 'application/x-www-form-urlencoded';
      body = form.toString();
    }
    const res = await this.http.request(`${this.apiBase}/register`, { method: 'POST', headers, body, what: 'user registration' });
    if (!res.ok) {
      throw await errorFromResponse(res);
    }
    return readJson<RegisterUserResult>(res);
  }

  /** GET /api/v1/registration. */
  registrationInfo(): Promise<RegistrationInfo> {
    return this.http.json(`${this.apiBase}/registration`, { what: 'registration info' });
  }

  /** Cached client_credentials tokens for `scope` (default users:sync). */
  clientCredentials(scope = 'users:sync'): ClientCredentialsProvider {
    let p = this.cc.get(scope);
    if (!p) {
      p = new ClientCredentialsProvider(this, scope);
      this.cc.set(scope, p);
    }
    return p;
  }

  /** Users changes feed authenticated with cached client_credentials (scope users:sync). */
  changesFeed(scope = 'users:sync'): ChangesFeed {
    return new ChangesFeed({ http: this.http, apiBase: this.apiBase, getAccessToken: this.clientCredentials(scope).provider });
  }

  /** Raw client_credentials grant (prefer clientCredentials(scope) which caches). */
  async requestClientCredentials(scope: string): Promise<TokenSet> {
    const disc = await this.disco.get();
    const t = await requestToken(this.http, disc.token_endpoint, { grant_type: 'client_credentials', scope }, { auth: this.auth });
    const set: TokenSet = { accessToken: t.access_token, tokenType: t.token_type, expiresAt: Math.floor(this.now() / 1000) + t.expires_in };
    if (t.scope !== undefined) {
      set.scope = t.scope;
    }
    return set;
  }

  /** @internal */
  nowMs(): number {
    return this.now();
  }
}

/** Caches a client_credentials token and renews it when less than 120 s remain (single-flight). */
export class ClientCredentialsProvider {
  private token: TokenSet | undefined;
  private readonly flight = new SingleFlight<string, TokenSet>();
  /** Number of token requests made (diagnostics). */
  requestCount = 0;

  constructor(
    private readonly client: MoonSsoClient,
    readonly scope: string,
    private readonly minRemainingSeconds = 120,
  ) {}

  async getAccessToken(opts: { force?: boolean; rejected?: string } = {}): Promise<string> {
    const nowS = Math.floor(this.client.nowMs() / 1000);
    const t = this.token;
    if (t && !opts.force && t.expiresAt - nowS > this.minRemainingSeconds) {
      return t.accessToken;
    }
    if (t && opts.force && opts.rejected && t.accessToken !== opts.rejected && t.expiresAt - nowS > this.minRemainingSeconds) {
      return t.accessToken; // someone else already replaced the rejected token
    }
    const fresh = await this.flight.run('cc', async () => {
      this.requestCount++;
      return this.client.requestClientCredentials(this.scope);
    });
    this.token = fresh;
    return fresh.accessToken;
  }

  /** Forgets the cached token. */
  reset(): void {
    this.token = undefined;
  }

  /** TokenProvider adapter. */
  readonly provider: TokenProvider = (o) => this.getAccessToken(o);
}

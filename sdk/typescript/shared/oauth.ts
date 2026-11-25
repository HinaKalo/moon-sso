/**
 * Form POSTs to OAuth endpoints with client authentication, DPoP proofs,
 * use_dpop_nonce handling and the token-endpoint retry rule (sdk-spec §1.5, §3).
 */

import type { DPoP } from './dpop.js';
import { errorFromBody, invalidResponse, MoonSsoError, TRANSIENT_STATUSES } from './errors.js';
import { drain, type HttpClient, readJsonLoose } from './http.js';
import { isObject } from './jose.js';

export type ClientAuthMethod = 'client_secret_basic' | 'client_secret_post' | 'none';

export interface ClientAuth {
  clientId: string;
  clientSecret?: string | undefined;
  /** Defaults to client_secret_basic with a secret, none otherwise. */
  method?: ClientAuthMethod | undefined;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
  id_token?: string;
  scope?: string;
}

export interface OAuthPostOptions {
  auth: ClientAuth;
  dpop?: DPoP | undefined;
  /** Retry once on network errors and 502/503/504 (token endpoint only). */
  retryTransient?: boolean;
  what?: string;
  signal?: AbortSignal | undefined;
  /** URL used for the DPoP htu claim when it differs from the request URL. */
  dpopHtu?: string | undefined;
}

export interface OAuthPostResult {
  status: number;
  headers: Headers;
  body: unknown;
}

/** RFC 6749 §2.3.1: client id and secret are form-urlencoded before Basic encoding. */
function basicAuth(id: string, secret: string): string {
  const enc = (s: string) => encodeURIComponent(s).replace(/%20/g, '+');
  return `Basic ${btoa(`${enc(id)}:${enc(secret)}`)}`;
}

function authMethod(auth: ClientAuth): ClientAuthMethod {
  return auth.method ?? (auth.clientSecret ? 'client_secret_basic' : 'none');
}

/** POSTs a form and returns status + parsed JSON body; never throws for HTTP errors. */
export async function oauthPost(http: HttpClient, url: string, params: Record<string, string | undefined>, opts: OAuthPostOptions): Promise<OAuthPostResult> {
  const form = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== '') {
      form.set(k, v);
    }
  }
  const method = authMethod(opts.auth);
  const headers: Record<string, string> = {
    'Content-Type': 'application/x-www-form-urlencoded',
    Accept: 'application/json',
  };
  if (method === 'client_secret_basic') {
    if (!opts.auth.clientSecret) {
      throw new MoonSsoError({ error: 'invalid_client', error_description: 'client_secret_basic requires a client secret' });
    }
    headers['Authorization'] = basicAuth(opts.auth.clientId, opts.auth.clientSecret);
  } else {
    form.set('client_id', opts.auth.clientId);
    if (method === 'client_secret_post') {
      if (!opts.auth.clientSecret) {
        throw new MoonSsoError({ error: 'invalid_client', error_description: 'client_secret_post requires a client secret' });
      }
      form.set('client_secret', opts.auth.clientSecret);
    }
  }
  const body = form.toString();
  let transientRetried = false;
  let nonceRetried = false;
  for (;;) {
    const h: Record<string, string> = { ...headers };
    if (opts.dpop) {
      // A fresh proof (new jti, current nonce) for every attempt.
      h['DPoP'] = await opts.dpop.proof('POST', opts.dpopHtu ?? url);
    }
    let res: Response;
    try {
      res = await http.request(url, { method: 'POST', headers: h, body, what: opts.what ?? 'OAuth request', signal: opts.signal });
    } catch (e) {
      if (opts.retryTransient && !transientRetried && e instanceof MoonSsoError && e.error === 'network') {
        transientRetried = true;
        continue;
      }
      throw e;
    }
    opts.dpop?.captureNonce(url, res);
    if (opts.retryTransient && !transientRetried && TRANSIENT_STATUSES.has(res.status)) {
      transientRetried = true;
      await drain(res);
      continue;
    }
    const json = await readJsonLoose(res);
    if (
      opts.dpop &&
      !nonceRetried &&
      (res.status === 400 || res.status === 401) &&
      isObject(json) &&
      json['error'] === 'use_dpop_nonce' &&
      res.headers.get('DPoP-Nonce')
    ) {
      nonceRetried = true;
      continue;
    }
    return { status: res.status, headers: res.headers, body: json };
  }
}

/** Throws the error carried by a non-2xx result. */
export function throwIfError(r: OAuthPostResult): void {
  if (r.status < 200 || r.status > 299) {
    throw errorFromBody(r.status, r.body ?? {});
  }
}

/** Calls the token endpoint and validates the token response shape. */
export async function requestToken(
  http: HttpClient,
  tokenEndpoint: string,
  params: Record<string, string | undefined>,
  opts: Omit<OAuthPostOptions, 'retryTransient' | 'what'>,
): Promise<TokenResponse> {
  const r = await oauthPost(http, tokenEndpoint, params, { ...opts, retryTransient: true, what: 'token request' });
  throwIfError(r);
  const b = r.body;
  if (!isObject(b) || typeof b['access_token'] !== 'string' || b['access_token'] === '') {
    throw invalidResponse('token response has no access_token', r.status);
  }
  const tokenType = typeof b['token_type'] === 'string' ? b['token_type'] : 'Bearer';
  if (tokenType.toLowerCase() !== 'bearer' && tokenType.toLowerCase() !== 'dpop') {
    throw invalidResponse(`unsupported token_type ${tokenType}`, r.status);
  }
  const expiresIn = typeof b['expires_in'] === 'number' && b['expires_in'] > 0 ? b['expires_in'] : 300;
  const out: TokenResponse = { access_token: b['access_token'], token_type: tokenType, expires_in: expiresIn };
  if (typeof b['refresh_token'] === 'string' && b['refresh_token']) {
    out.refresh_token = b['refresh_token'];
  }
  if (typeof b['id_token'] === 'string' && b['id_token']) {
    out.id_token = b['id_token'];
  }
  if (typeof b['scope'] === 'string') {
    out.scope = b['scope'];
  }
  return out;
}

/** RFC 7009 revocation; failures are swallowed (logout must not fail on them). */
export async function revokeToken(
  http: HttpClient,
  revocationEndpoint: string,
  token: string,
  hint: 'refresh_token' | 'access_token',
  auth: ClientAuth,
): Promise<boolean> {
  try {
    const r = await oauthPost(http, revocationEndpoint, { token, token_type_hint: hint }, { auth, what: 'revocation' });
    return r.status >= 200 && r.status < 300;
  } catch {
    return false;
  }
}

export interface EndSessionParams {
  idTokenHint?: string | undefined;
  postLogoutRedirectUri?: string | undefined;
  state?: string | undefined;
  clientId?: string | undefined;
}

export function buildEndSessionUrl(endSessionEndpoint: string, p: EndSessionParams): string {
  const u = new URL(endSessionEndpoint);
  if (p.idTokenHint) {
    u.searchParams.set('id_token_hint', p.idTokenHint);
  }
  if (p.clientId) {
    u.searchParams.set('client_id', p.clientId);
  }
  if (p.postLogoutRedirectUri) {
    u.searchParams.set('post_logout_redirect_uri', p.postLogoutRedirectUri);
  }
  if (p.state) {
    u.searchParams.set('state', p.state);
  }
  return u.toString();
}

export interface AuthorizationResponse {
  code: string;
  state: string;
  iss: string | undefined;
}

/**
 * Parses and validates an authorization response (state and RFC 9207 iss,
 * sdk-spec §1.9). Throws the OAuth error if the server returned one.
 */
export function parseAuthorizationResponse(params: URLSearchParams, expected: { state: string; issuer: string }): AuthorizationResponse {
  const state = params.get('state') ?? '';
  if (!state || state !== expected.state) {
    throw new MoonSsoError({ error: 'invalid_state', error_description: 'authorization response state does not match' });
  }
  const iss = params.get('iss') ?? undefined;
  if (iss !== undefined && iss.replace(/\/+$/, '') !== expected.issuer) {
    throw new MoonSsoError({ error: 'invalid_issuer', error_description: 'authorization response iss does not match the issuer' });
  }
  const err = params.get('error');
  if (err) {
    throw new MoonSsoError({ error: err, error_description: params.get('error_description') ?? undefined });
  }
  if (iss === undefined) {
    // The server always sends iss (authorization_response_iss_parameter_supported).
    throw new MoonSsoError({ error: 'invalid_issuer', error_description: 'authorization response lacks iss' });
  }
  const code = params.get('code');
  if (!code) {
    throw new MoonSsoError({ error: 'invalid_request', error_description: 'authorization response has no code' });
  }
  return { code, state, iss };
}

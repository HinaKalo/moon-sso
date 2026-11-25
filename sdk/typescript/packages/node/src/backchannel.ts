/**
 * OpenID Connect Back-Channel Logout receiver (sdk-spec §5.3).
 */

import type { IncomingMessage, ServerResponse } from 'node:http';
import { Discovery } from './shared/discovery.js';
import { nowSeconds } from './shared/encoding.js';
import { MoonSsoError } from './shared/errors.js';
import { type FetchLike, HttpClient, trimSlash } from './shared/http.js';
import { audienceOf, isObject, JwksCache, type JwtPayload, SUPPORTED_ALGS, verifyJwt } from './shared/jose.js';
import { ExpiringSet } from './shared/util.js';
import { readForm, sendJson } from './http-util.js';
import { USER_AGENT } from './version.js';

export const BACKCHANNEL_LOGOUT_EVENT = 'http://schemas.openid.net/event/backchannel-logout';

export interface LogoutTokenClaims extends JwtPayload {
  iss: string;
  aud: string | string[];
  iat: number;
  exp: number;
  jti: string;
  sub?: string;
  sid?: string;
  events: Record<string, unknown>;
}

export interface BackchannelLogoutVerifierOptions {
  issuer: string;
  clientId: string;
  /** Reuse a JWKS cache (e.g. MoonSsoClient.jwks); otherwise one is created from discovery. */
  jwks?: JwksCache;
  fetch?: FetchLike;
  /** jti replay window (default 300 s). */
  replayWindowSeconds?: number;
  clockSkewSeconds?: number;
  now?: () => number;
}

export class BackchannelLogoutVerifier {
  readonly issuer: string;
  readonly clientId: string;
  private readonly jwks: JwksCache;
  private readonly seen: ExpiringSet;
  private readonly replayMs: number;
  private readonly skew: number;
  private readonly now: () => number;

  constructor(opts: BackchannelLogoutVerifierOptions) {
    this.issuer = trimSlash(opts.issuer);
    this.clientId = opts.clientId;
    this.now = opts.now ?? Date.now;
    this.replayMs = (opts.replayWindowSeconds ?? 300) * 1000;
    this.skew = opts.clockSkewSeconds ?? 60;
    this.seen = new ExpiringSet({ now: this.now });
    if (opts.jwks) {
      this.jwks = opts.jwks;
    } else {
      const http = new HttpClient({ fetch: opts.fetch, userAgent: USER_AGENT });
      const disco = new Discovery(this.issuer, http, { now: this.now });
      this.jwks = new JwksCache({ http, jwksUri: async () => (await disco.get()).jwks_uri, now: this.now });
    }
  }

  /**
   * Verifies a logout token: signature (JWKS), typ logout+jwt, iss, aud,
   * iat ≤ now + skew, exp, the back-channel-logout event, sub or sid, no
   * nonce, and jti not seen within the replay window.
   */
  async verify(logoutToken: string): Promise<LogoutTokenClaims> {
    const code = 'invalid_logout_token';
    const fail = (d: string) => new MoonSsoError({ error: code, error_description: d, status: 400 });
    const jwt = await verifyJwt(logoutToken, this.jwks, { algorithms: SUPPORTED_ALGS, typ: 'logout+jwt', errorCode: code });
    const p = jwt.payload;
    const now = nowSeconds(this.now);
    if (p['iss'] !== this.issuer) {
      throw fail('iss mismatch');
    }
    if (!audienceOf(p).includes(this.clientId)) {
      throw fail('aud does not include this client');
    }
    const iat = p['iat'];
    if (typeof iat !== 'number' || iat > now + this.skew) {
      throw fail('iat missing or in the future');
    }
    const exp = p['exp'];
    if (typeof exp !== 'number' || exp + this.skew <= now) {
      throw fail('token expired');
    }
    const events = p['events'];
    if (!isObject(events) || !(BACKCHANNEL_LOGOUT_EVENT in events) || !isObject(events[BACKCHANNEL_LOGOUT_EVENT])) {
      throw fail('events claim lacks the back-channel logout event');
    }
    const sub = typeof p['sub'] === 'string' && p['sub'] !== '' ? p['sub'] : undefined;
    const sid = typeof p['sid'] === 'string' && p['sid'] !== '' ? p['sid'] : undefined;
    if (!sub && !sid) {
      throw fail('neither sub nor sid present');
    }
    if ('nonce' in p) {
      throw fail('nonce is not allowed in a logout token');
    }
    const jti = p['jti'];
    if (typeof jti !== 'string' || jti === '') {
      throw fail('jti missing');
    }
    if (!this.seen.add(`${this.issuer}|${jti}`, this.replayMs)) {
      throw fail('logout token replayed');
    }
    return p as LogoutTokenClaims;
  }
}

export interface BackchannelLogoutHandlerOptions {
  verifier: BackchannelLogoutVerifier;
  /** Ends the application's sessions for the subject / SSO session id. */
  onLogout: (sub: string | undefined, sid: string | undefined, claims: LogoutTokenClaims) => void | Promise<void>;
  /** Called with verification failures (logging); never receives the token. */
  onError?: (e: unknown) => void;
}

/** POST handler: reads form field logout_token, verifies, calls onLogout, answers 200 (400 on invalid tokens). */
export function createBackchannelLogoutHandler(opts: BackchannelLogoutHandlerOptions): (req: IncomingMessage, res: ServerResponse) => Promise<void> {
  return async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    if (req.method !== 'POST') {
      res.setHeader('Allow', 'POST');
      sendJson(res, 405, { error: 'invalid_request', error_description: 'POST required' });
      return;
    }
    try {
      const form = await readForm(req);
      const token = form.get('logout_token');
      if (!token) {
        throw new MoonSsoError({ error: 'invalid_request', error_description: 'missing logout_token', status: 400 });
      }
      const claims = await opts.verifier.verify(token);
      await opts.onLogout(claims.sub, claims.sid, claims);
      res.statusCode = 200;
      res.end();
    } catch (e) {
      opts.onError?.(e);
      if (e instanceof MoonSsoError && (e.status === 400 || e.status === 413 || e.error === 'invalid_logout_token' || e.error === 'invalid_request')) {
        sendJson(res, e.status === 413 ? 413 : 400, { error: e.error, error_description: e.error_description });
        return;
      }
      // Key download failures and application errors: let the server retry.
      sendJson(res, 500, { error: 'server_error' });
    }
  };
}

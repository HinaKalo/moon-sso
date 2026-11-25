/**
 * Access-token verification for resource servers (sdk-spec §1.8): local JWS
 * verification against the JWKS (cached one hour, refetch on unknown kid at
 * most every 30 s), typ at+jwt, iss, exp/nbf and audience.
 */

import type { IncomingMessage, ServerResponse } from 'node:http';
import { Discovery } from './shared/discovery.js';
import { MoonSsoError } from './shared/errors.js';
import { type FetchLike, HttpClient, trimSlash } from './shared/http.js';
import { type AccessTokenClaims, JwksCache, validateAccessToken } from './shared/jose.js';
import { header, type NextFunction, sendJson } from './http-util.js';
import { USER_AGENT } from './version.js';

export interface AccessTokenVerifierOptions {
  issuer: string;
  /** Accepted audiences: this API's client_id, a configured resource, or the Moon API audience. */
  audience: string | string[];
  /** Reuse an existing JWKS cache. */
  jwks?: JwksCache;
  fetch?: FetchLike;
  clockSkewSeconds?: number;
  now?: () => number;
}

export interface VerifyOptions {
  /** All of these scopes must be present. */
  scopes?: string[];
}

export type RequestWithAuth = IncomingMessage & { auth?: AccessTokenClaims };

export class AccessTokenVerifier {
  readonly issuer: string;
  readonly jwks: JwksCache;
  private readonly audience: string[];
  private readonly skew: number | undefined;
  private readonly now: (() => number) | undefined;

  constructor(opts: AccessTokenVerifierOptions) {
    this.issuer = trimSlash(opts.issuer);
    this.audience = typeof opts.audience === 'string' ? [opts.audience] : [...opts.audience];
    if (this.audience.length === 0) {
      throw new MoonSsoError({ error: 'invalid_configuration', error_description: 'audience is required' });
    }
    this.skew = opts.clockSkewSeconds;
    this.now = opts.now;
    if (opts.jwks) {
      this.jwks = opts.jwks;
    } else {
      const http = new HttpClient({ fetch: opts.fetch, userAgent: USER_AGENT });
      const disco = new Discovery(this.issuer, http, opts.now ? { now: opts.now } : {});
      this.jwks = new JwksCache({ http, jwksUri: async () => (await disco.get()).jwks_uri, ...(opts.now ? { now: opts.now } : {}) });
    }
  }

  /** Verifies a bearer access token; throws MoonSsoError invalid_token (401) / insufficient_scope (403). */
  async verify(token: string, opts: VerifyOptions = {}): Promise<AccessTokenClaims> {
    const check: Parameters<typeof validateAccessToken>[2] = { issuer: this.issuer, audience: this.audience };
    if (opts.scopes) {
      check.requiredScopes = opts.scopes;
    }
    if (this.skew !== undefined) {
      check.clockSkewSeconds = this.skew;
    }
    if (this.now) {
      check.now = this.now;
    }
    try {
      return await validateAccessToken(token, this.jwks, check);
    } catch (e) {
      if (e instanceof MoonSsoError && (e.error === 'invalid_token' || e.error === 'insufficient_scope')) {
        throw e;
      }
      if (e instanceof MoonSsoError && e.error === 'network') {
        throw e;
      }
      throw new MoonSsoError({ error: 'invalid_token', error_description: 'token verification failed', status: 401, cause: e });
    }
  }

  /** Extracts the bearer token from an Authorization header value. */
  static bearer(authorization: string | undefined): string | undefined {
    if (!authorization) {
      return undefined;
    }
    const m = /^Bearer\s+(.+)$/i.exec(authorization.trim());
    return m?.[1]?.trim() || undefined;
  }

  /**
   * (req, res, next) middleware: sets `req.auth` to the verified claims or
   * answers 401/403 with a WWW-Authenticate header (RFC 6750).
   */
  middleware(opts: VerifyOptions & { optional?: boolean } = {}): (req: IncomingMessage, res: ServerResponse, next: NextFunction) => void {
    return (req, res, next) => {
      const token = AccessTokenVerifier.bearer(header(req, 'authorization'));
      if (!token) {
        if (opts.optional) {
          next();
          return;
        }
        sendJson(res, 401, { error: 'invalid_request', error_description: 'missing bearer token' }, { 'WWW-Authenticate': 'Bearer realm="api"' });
        return;
      }
      this.verify(token, opts).then(
        (claims) => {
          (req as RequestWithAuth).auth = claims;
          next();
        },
        (e: unknown) => {
          if (e instanceof MoonSsoError && e.error === 'insufficient_scope') {
            const scope = (opts.scopes ?? []).join(' ');
            sendJson(res, 403, { error: 'insufficient_scope', error_description: e.error_description }, {
              'WWW-Authenticate': `Bearer error="insufficient_scope", scope="${scope}"`,
            });
            return;
          }
          if (e instanceof MoonSsoError && e.error === 'invalid_token') {
            const desc = (e.error_description ?? 'invalid token').replace(/"/g, "'");
            sendJson(res, 401, { error: 'invalid_token', error_description: desc }, {
              'WWW-Authenticate': `Bearer error="invalid_token", error_description="${desc}"`,
            });
            return;
          }
          next(e);
        },
      );
    };
  }
}

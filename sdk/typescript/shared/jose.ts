/**
 * JWS verification (RS256, ES256) on WebCrypto, a JWKS cache with
 * rate-limited refetch on unknown kid (sdk-spec §1.7), and claim checks for
 * ID tokens and access tokens.
 */

import { base64UrlDecode, base64UrlEncode, type Bytes, fromUtf8, nowSeconds, sha256, utf8, type WebCryptoKey, webCrypto } from './encoding.js';
import { MoonSsoError } from './errors.js';
import type { HttpClient } from './http.js';

export type JwsAlgorithm = 'RS256' | 'ES256';
export const SUPPORTED_ALGS: readonly JwsAlgorithm[] = ['RS256', 'ES256'];

export interface Jwk {
  kty: string;
  kid?: string;
  alg?: string;
  use?: string;
  key_ops?: string[];
  n?: string;
  e?: string;
  crv?: string;
  x?: string;
  y?: string;
  [k: string]: unknown;
}

export interface JwsHeader {
  alg: string;
  kid?: string;
  typ?: string;
  crit?: string[];
  jwk?: Jwk;
  [k: string]: unknown;
}

export type JwtPayload = Record<string, unknown>;

export interface DecodedJwt {
  header: JwsHeader;
  payload: JwtPayload;
  signingInput: Bytes;
  signature: Bytes;
}

function invalid(desc: string, code = 'invalid_token'): MoonSsoError {
  return new MoonSsoError({ error: code, error_description: desc });
}

/** Splits and decodes a compact JWS without verifying it. */
export function decodeJwt(token: string, code = 'invalid_token'): DecodedJwt {
  if (typeof token !== 'string' || token.length > 16_384) {
    throw invalid('token is missing or too large', code);
  }
  const parts = token.split('.');
  if (parts.length !== 3 || !parts[0] || !parts[1] || !parts[2]) {
    throw invalid('token is not a compact JWS', code);
  }
  let header: unknown;
  let payload: unknown;
  let signature: Bytes;
  try {
    header = JSON.parse(fromUtf8(base64UrlDecode(parts[0])));
    payload = JSON.parse(fromUtf8(base64UrlDecode(parts[1])));
    signature = base64UrlDecode(parts[2]);
  } catch {
    throw invalid('token is not well-formed', code);
  }
  if (!isObject(header) || typeof header['alg'] !== 'string') {
    throw invalid('token header is invalid', code);
  }
  if (!isObject(payload)) {
    throw invalid('token payload is not a JSON object', code);
  }
  return { header: header as JwsHeader, payload, signingInput: utf8(`${parts[0]}.${parts[1]}`), signature };
}

export function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function algParams(alg: JwsAlgorithm): { importAlg: object; verifyAlg: object } {
  if (alg === 'RS256') {
    return {
      importAlg: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      verifyAlg: { name: 'RSASSA-PKCS1-v1_5' },
    };
  }
  return {
    importAlg: { name: 'ECDSA', namedCurve: 'P-256' },
    verifyAlg: { name: 'ECDSA', hash: 'SHA-256' },
  };
}

/** Returns the JWS algorithm a JWK can verify, or undefined if unsupported. */
export function jwkAlgorithm(jwk: Jwk): JwsAlgorithm | undefined {
  if (jwk.use !== undefined && jwk.use !== 'sig') {
    return undefined;
  }
  if (jwk.kty === 'RSA' && typeof jwk.n === 'string' && typeof jwk.e === 'string' && (jwk.alg === undefined || jwk.alg === 'RS256')) {
    return 'RS256';
  }
  if (
    jwk.kty === 'EC' &&
    jwk.crv === 'P-256' &&
    typeof jwk.x === 'string' &&
    typeof jwk.y === 'string' &&
    (jwk.alg === undefined || jwk.alg === 'ES256')
  ) {
    return 'ES256';
  }
  return undefined;
}

export async function importVerifyKey(jwk: Jwk, alg: JwsAlgorithm): Promise<WebCryptoKey> {
  const pub: Record<string, unknown> =
    alg === 'RS256' ? { kty: 'RSA', n: jwk.n, e: jwk.e, ext: true } : { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y, ext: true };
  return webCrypto().subtle.importKey('jwk', pub, algParams(alg).importAlg, true, ['verify']);
}

export async function verifySignature(jwt: DecodedJwt, key: WebCryptoKey, alg: JwsAlgorithm): Promise<boolean> {
  if (alg === 'ES256' && jwt.signature.length !== 64) {
    return false;
  }
  return webCrypto().subtle.verify(algParams(alg).verifyAlg, key, jwt.signature, jwt.signingInput);
}

interface CachedKey {
  jwk: Jwk;
  alg: JwsAlgorithm;
  key?: Promise<WebCryptoKey>;
}

export interface JwksCacheOptions {
  http: HttpClient;
  /** Resolves the JWKS URL (usually from discovery). */
  jwksUri: () => Promise<string>;
  /** Cache lifetime (default one hour). */
  ttlMs?: number;
  /** Minimum interval between forced refetches on unknown kid (default 30 s). */
  minRefetchMs?: number;
  now?: () => number;
}

/** JWKS cache: one-hour TTL, stale-on-error, forced refetch on unknown kid at most every 30 s. */
export class JwksCache {
  private readonly opts: Required<Omit<JwksCacheOptions, 'http' | 'jwksUri'>> & Pick<JwksCacheOptions, 'http' | 'jwksUri'>;
  private keys: CachedKey[] = [];
  private loaded = false;
  private fetchedAt = 0;
  private lastAttempt = -Infinity;
  private inflight: Promise<void> | undefined;

  constructor(opts: JwksCacheOptions) {
    this.opts = { ttlMs: 3_600_000, minRefetchMs: 30_000, now: Date.now, ...opts };
  }

  /** Number of JWKS downloads performed (for diagnostics and tests). */
  fetchCount = 0;

  private async refresh(): Promise<void> {
    if (!this.inflight) {
      this.inflight = (async () => {
        this.lastAttempt = this.opts.now();
        const uri = await this.opts.jwksUri();
        this.fetchCount++;
        const body = await this.opts.http.json<unknown>(uri, { what: 'JWKS download', headers: { Accept: 'application/json' } });
        if (!isObject(body) || !Array.isArray(body['keys'])) {
          throw new MoonSsoError({ error: 'invalid_response', error_description: 'JWKS has no keys array' });
        }
        const next: CachedKey[] = [];
        for (const k of body['keys'] as unknown[]) {
          if (!isObject(k) || typeof k['kty'] !== 'string') {
            continue;
          }
          const jwk = k as Jwk;
          const alg = jwkAlgorithm(jwk);
          if (!alg) {
            continue;
          }
          const prev = this.keys.find((p) => p.jwk.kid === jwk.kid && p.alg === alg && sameKey(p.jwk, jwk));
          next.push(prev ?? { jwk, alg });
        }
        this.keys = next;
        this.loaded = true;
        this.fetchedAt = this.opts.now();
      })().finally(() => {
        this.inflight = undefined;
      });
    }
    return this.inflight;
  }

  private find(kid: string | undefined, alg: JwsAlgorithm): CachedKey[] {
    return this.keys.filter((k) => k.alg === alg && (kid === undefined || k.jwk.kid === kid));
  }

  /** Candidate verification keys for a JWS header. */
  async keysFor(kid: string | undefined, alg: JwsAlgorithm): Promise<WebCryptoKey[]> {
    const now = this.opts.now();
    if (!this.loaded || now - this.fetchedAt >= this.opts.ttlMs) {
      try {
        await this.refresh();
      } catch (e) {
        if (!this.loaded) {
          throw e;
        }
        // stale-on-error: keep using the cached set
      }
    }
    let found = this.find(kid, alg);
    if (found.length === 0 && this.opts.now() - this.lastAttempt >= this.opts.minRefetchMs) {
      try {
        await this.refresh();
      } catch {
        // fall through with whatever is cached
      }
      found = this.find(kid, alg);
    }
    if (found.length === 0) {
      throw invalid(kid ? `no signing key with kid ${kid}` : 'no matching signing key');
    }
    return Promise.all(
      found.map((k) => {
        if (!k.key) {
          k.key = importVerifyKey(k.jwk, k.alg);
          k.key.catch(() => {
            k.key = undefined;
          });
        }
        return k.key;
      }),
    );
  }
}

function sameKey(a: Jwk, b: Jwk): boolean {
  return a.n === b.n && a.e === b.e && a.x === b.x && a.y === b.y && a.crv === b.crv;
}

export interface VerifyJwtOptions {
  /** Accepted algorithms (default RS256 and ES256). */
  algorithms?: readonly JwsAlgorithm[];
  /** Required `typ` header value(s); compared case-insensitively, "application/" prefix tolerated. */
  typ?: string | readonly string[];
  /** Error code used on failure (default invalid_token). */
  errorCode?: string;
}

function normTyp(t: string): string {
  const l = t.toLowerCase();
  return l.startsWith('application/') ? l.slice('application/'.length) : l;
}

/** Verifies the signature and header of a JWT against the JWKS. Claims are checked separately. */
export async function verifyJwt(token: string, jwks: JwksCache, opts: VerifyJwtOptions = {}): Promise<DecodedJwt> {
  const code = opts.errorCode ?? 'invalid_token';
  const jwt = decodeJwt(token, code);
  const algs = opts.algorithms ?? SUPPORTED_ALGS;
  const alg = jwt.header.alg as JwsAlgorithm;
  if (!algs.includes(alg)) {
    throw invalid(`unsupported token algorithm ${jwt.header.alg}`, code);
  }
  if (jwt.header.crit !== undefined) {
    throw invalid('token uses unsupported critical header parameters', code);
  }
  if (opts.typ !== undefined) {
    const want = (typeof opts.typ === 'string' ? [opts.typ] : opts.typ).map(normTyp);
    const got = typeof jwt.header.typ === 'string' ? normTyp(jwt.header.typ) : '';
    if (!want.includes(got)) {
      throw invalid(`unexpected token type ${jwt.header.typ ?? '(none)'}`, code);
    }
  }
  const kid = typeof jwt.header.kid === 'string' ? jwt.header.kid : undefined;
  let keys: WebCryptoKey[];
  try {
    keys = await jwks.keysFor(kid, alg);
  } catch (e) {
    if (e instanceof MoonSsoError && e.error === 'invalid_token' && code !== 'invalid_token') {
      throw invalid(e.error_description ?? 'no matching key', code);
    }
    throw e;
  }
  for (const key of keys) {
    if (await verifySignature(jwt, key, alg)) {
      return jwt;
    }
  }
  throw invalid('token signature is invalid', code);
}

// ---------------------------------------------------------------------------
// Claims

export function audienceOf(payload: JwtPayload): string[] {
  const aud = payload['aud'];
  if (typeof aud === 'string') {
    return [aud];
  }
  if (Array.isArray(aud)) {
    return aud.filter((a): a is string => typeof a === 'string');
  }
  return [];
}

function numClaim(payload: JwtPayload, name: string): number | undefined {
  const v = payload[name];
  return typeof v === 'number' && Number.isFinite(v) ? v : undefined;
}

/** Left-half SHA-256 hash used by at_hash for RS256/ES256. */
export async function leftHalfHash(value: string): Promise<string> {
  const h = await sha256(value);
  return base64UrlEncode(h.subarray(0, h.length / 2));
}

export interface IdTokenClaims extends JwtPayload {
  iss: string;
  sub: string;
  aud: string | string[];
  exp: number;
  iat: number;
  auth_time?: number;
  nonce?: string;
  sid?: string;
  amr?: string[];
  azp?: string;
  at_hash?: string;
  preferred_username?: string;
  name?: string;
  nickname?: string;
  picture?: string;
  updated_at?: number;
  profile_version?: number;
}

export interface IdTokenCheck {
  issuer: string;
  clientId: string;
  /** Required on authorization code exchange. */
  nonce?: string | undefined;
  /** When present and the token has at_hash, it must match. */
  accessToken?: string | undefined;
  /** On refresh, the sub must stay the same. */
  expectedSub?: string | undefined;
  clockSkewSeconds?: number;
  now?: () => number;
}

/** Verifies an ID token's signature and claims (sdk-spec §1.7). */
export async function validateIdToken(idToken: string, jwks: JwksCache, check: IdTokenCheck): Promise<IdTokenClaims> {
  const code = 'invalid_id_token';
  const jwt = await verifyJwt(idToken, jwks, { algorithms: SUPPORTED_ALGS, errorCode: code });
  const p = jwt.payload;
  const skew = check.clockSkewSeconds ?? 60;
  const now = nowSeconds(check.now);
  const fail = (d: string) => new MoonSsoError({ error: code, error_description: d });
  if (p['iss'] !== check.issuer) {
    throw fail('ID token issuer mismatch');
  }
  if (typeof p['sub'] !== 'string' || p['sub'] === '') {
    throw fail('ID token has no sub');
  }
  const aud = audienceOf(p);
  if (!aud.includes(check.clientId)) {
    throw fail('ID token audience does not include this client');
  }
  if (aud.length > 1 && p['azp'] !== check.clientId) {
    throw fail('ID token azp does not match this client');
  }
  if (p['azp'] !== undefined && p['azp'] !== check.clientId) {
    throw fail('ID token azp does not match this client');
  }
  const exp = numClaim(p, 'exp');
  const iat = numClaim(p, 'iat');
  if (exp === undefined || exp + skew <= now) {
    throw fail('ID token is expired');
  }
  if (iat === undefined || iat > now + skew) {
    throw fail('ID token iat is in the future');
  }
  if (check.nonce !== undefined) {
    if (p['nonce'] !== check.nonce) {
      throw fail('ID token nonce mismatch');
    }
  }
  if (check.expectedSub !== undefined && p['sub'] !== check.expectedSub) {
    throw fail('ID token sub changed');
  }
  if (typeof p['at_hash'] === 'string' && check.accessToken !== undefined) {
    if ((await leftHalfHash(check.accessToken)) !== p['at_hash']) {
      throw fail('ID token at_hash does not match the access token');
    }
  }
  return p as IdTokenClaims;
}

export interface AccessTokenClaims extends JwtPayload {
  iss: string;
  sub: string;
  aud: string[] | string;
  exp: number;
  iat: number;
  nbf?: number;
  jti: string;
  client_id: string;
  scope?: string;
  sid?: string;
  auth_time?: number;
  /** Profile version of the user when the token was minted. */
  pv?: number;
  cnf?: { jkt: string };
}

export interface AccessTokenCheck {
  issuer: string;
  /** At least one of these must be in `aud`. */
  audience: string | readonly string[];
  /** Every listed scope must be granted. */
  requiredScopes?: readonly string[];
  clockSkewSeconds?: number;
  now?: () => number;
}

/** Verifies an access token for a resource server (sdk-spec §1.8). */
export async function validateAccessToken(token: string, jwks: JwksCache, check: AccessTokenCheck): Promise<AccessTokenClaims> {
  const jwt = await verifyJwt(token, jwks, { algorithms: SUPPORTED_ALGS, typ: 'at+jwt' });
  const p = jwt.payload;
  const skew = check.clockSkewSeconds ?? 60;
  const now = nowSeconds(check.now);
  const fail = (d: string, error = 'invalid_token') => new MoonSsoError({ error, error_description: d, status: error === 'insufficient_scope' ? 403 : 401 });
  if (p['iss'] !== check.issuer) {
    throw fail('token issuer mismatch');
  }
  const exp = numClaim(p, 'exp');
  if (exp === undefined || exp + skew <= now) {
    throw fail('token is expired');
  }
  const nbf = numClaim(p, 'nbf');
  if (nbf !== undefined && nbf > now + skew) {
    throw fail('token is not valid yet');
  }
  const iat = numClaim(p, 'iat');
  if (iat !== undefined && iat > now + skew) {
    throw fail('token iat is in the future');
  }
  if (typeof p['sub'] !== 'string') {
    throw fail('token has no sub');
  }
  const want = typeof check.audience === 'string' ? [check.audience] : check.audience;
  const aud = audienceOf(p);
  if (!want.some((a) => aud.includes(a))) {
    throw fail('token audience is not accepted by this resource server');
  }
  if (check.requiredScopes && check.requiredScopes.length > 0) {
    const granted = new Set(typeof p['scope'] === 'string' ? p['scope'].split(' ').filter(Boolean) : []);
    const missing = check.requiredScopes.filter((s) => !granted.has(s));
    if (missing.length > 0) {
      throw fail(`token lacks scope: ${missing.join(' ')}`, 'insufficient_scope');
    }
  }
  return p as AccessTokenClaims;
}

/** Reads claims without verification (only for tokens the SDK itself just received over TLS). */
export function unsafeDecodeClaims(token: string): JwtPayload | undefined {
  try {
    return decodeJwt(token).payload;
  } catch {
    return undefined;
  }
}

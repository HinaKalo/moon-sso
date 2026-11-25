/**
 * DPoP (RFC 9449, sdk-spec §3): ES256 proofs from a P-256 key pair, JWK
 * thumbprints, and tracking of the most recent server DPoP-Nonce.
 */

import { base64UrlEncode, nowSeconds, randomToken, sha256, utf8, type WebCryptoKeyPair, webCrypto } from './encoding.js';
import { MoonSsoError } from './errors.js';

export interface PublicEcJwk {
  kty: 'EC';
  crv: 'P-256';
  x: string;
  y: string;
}

/**
 * Generates a P-256 signing key pair. In browsers keep `extractable` false
 * so the private key can never leave WebCrypto (it can still be stored in IndexedDB).
 */
export async function generateDPoPKeyPair(extractable = false): Promise<WebCryptoKeyPair> {
  return webCrypto().subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, extractable, ['sign', 'verify']);
}

/** RFC 7638 JWK thumbprint (SHA-256, base64url) of a P-256 public key. */
export async function jwkThumbprint(jwk: PublicEcJwk): Promise<string> {
  const canonical = `{"crv":"${jwk.crv}","kty":"${jwk.kty}","x":"${jwk.x}","y":"${jwk.y}"}`;
  return base64UrlEncode(await sha256(canonical));
}

/** Removes query and fragment as required for the htu claim. */
export function htuOf(url: string): string {
  const u = new URL(url);
  u.search = '';
  u.hash = '';
  return u.toString();
}

export class DPoP {
  readonly keyPair: WebCryptoKeyPair;
  readonly publicJwk: PublicEcJwk;
  /** base64url SHA-256 JWK thumbprint, sent as dpop_jkt. */
  readonly jkt: string;
  private readonly nonces = new Map<string, string>();
  private readonly now: () => number;

  private constructor(keyPair: WebCryptoKeyPair, publicJwk: PublicEcJwk, jkt: string, now: () => number) {
    this.keyPair = keyPair;
    this.publicJwk = publicJwk;
    this.jkt = jkt;
    this.now = now;
  }

  static async fromKeyPair(keyPair: WebCryptoKeyPair, opts: { now?: () => number } = {}): Promise<DPoP> {
    const exported = await webCrypto().subtle.exportKey('jwk', keyPair.publicKey);
    if (exported['kty'] !== 'EC' || exported['crv'] !== 'P-256' || typeof exported['x'] !== 'string' || typeof exported['y'] !== 'string') {
      throw new MoonSsoError({ error: 'invalid_dpop_key', error_description: 'DPoP key must be an ECDSA P-256 key' });
    }
    const jwk: PublicEcJwk = { kty: 'EC', crv: 'P-256', x: exported['x'], y: exported['y'] };
    return new DPoP(keyPair, jwk, await jwkThumbprint(jwk), opts.now ?? Date.now);
  }

  static async generate(opts: { extractable?: boolean; now?: () => number } = {}): Promise<DPoP> {
    return DPoP.fromKeyPair(await generateDPoPKeyPair(opts.extractable ?? false), opts);
  }

  /** Latest nonce seen from the origin of `url`. */
  nonceFor(url: string): string | undefined {
    return this.nonces.get(new URL(url).origin);
  }

  /** Records the DPoP-Nonce header of any response from the server. */
  captureNonce(url: string, res: Response): void {
    const n = res.headers.get('DPoP-Nonce');
    if (n) {
      this.nonces.set(new URL(url).origin, n);
    }
  }

  /** Creates a proof JWT for a request. */
  async proof(htm: string, url: string, opts: { nonce?: string | undefined; accessToken?: string | undefined } = {}): Promise<string> {
    const header = { typ: 'dpop+jwt', alg: 'ES256', jwk: this.publicJwk };
    const claims: Record<string, unknown> = {
      jti: randomToken(16),
      htm: htm.toUpperCase(),
      htu: htuOf(url),
      iat: nowSeconds(this.now),
    };
    const nonce = opts.nonce ?? this.nonceFor(url);
    if (nonce) {
      claims['nonce'] = nonce;
    }
    if (opts.accessToken) {
      claims['ath'] = base64UrlEncode(await sha256(opts.accessToken));
    }
    const input = `${base64UrlEncode(JSON.stringify(header))}.${base64UrlEncode(JSON.stringify(claims))}`;
    const sig = await webCrypto().subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, this.keyPair.privateKey, utf8(input));
    return `${input}.${base64UrlEncode(new Uint8Array(sig))}`;
  }
}

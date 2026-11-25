/**
 * PKCE S256 (always required, sdk-spec §2) and random state / nonce values.
 */

import { base64UrlEncode, randomToken, sha256 } from './encoding.js';

export interface Pkce {
  /** 43-char base64url verifier (256 bits of entropy). */
  verifier: string;
  /** base64url(SHA-256(verifier)). */
  challenge: string;
  method: 'S256';
}

const VERIFIER_RE = /^[A-Za-z0-9\-._~]{43,128}$/;

export async function pkceChallenge(verifier: string): Promise<string> {
  if (!VERIFIER_RE.test(verifier)) {
    throw new RangeError('code_verifier must be 43-128 characters of [A-Za-z0-9-._~]');
  }
  return base64UrlEncode(await sha256(verifier));
}

export async function createPkce(): Promise<Pkce> {
  const verifier = randomToken(32);
  return { verifier, challenge: await pkceChallenge(verifier), method: 'S256' };
}

/** state / nonce: 256 random bits, base64url. */
export function randomState(): string {
  return randomToken(32);
}

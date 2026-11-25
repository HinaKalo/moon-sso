/**
 * Byte/encoding helpers and a narrow, environment-neutral view of WebCrypto.
 * Works unchanged in browsers and Node.js >= 20 (globalThis.crypto).
 */

import { MoonSsoError } from './errors.js';

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

export type Bytes = Uint8Array<ArrayBuffer>;

/**
 * Structural stand-ins for CryptoKey / CryptoKeyPair that type-check under
 * both the DOM lib and @types/node (whose CryptoKey is declared differently).
 * Real WebCrypto keys satisfy them.
 */
export interface WebCryptoKey {
  readonly type: string;
  readonly extractable: boolean;
  readonly algorithm: object;
  readonly usages: readonly string[];
}

export interface WebCryptoKeyPair {
  readonly privateKey: WebCryptoKey;
  readonly publicKey: WebCryptoKey;
}

/** Algorithms and formats used by the SDK; kept minimal so DOM and Node typings both satisfy it. */
export interface SubtleLike {
  importKey(format: 'jwk', keyData: object, algorithm: object, extractable: boolean, usages: string[]): Promise<WebCryptoKey>;
  importKey(format: 'raw', keyData: Bytes, algorithm: object, extractable: boolean, usages: string[]): Promise<WebCryptoKey>;
  exportKey(format: 'jwk', key: WebCryptoKey): Promise<Record<string, unknown>>;
  generateKey(algorithm: object, extractable: boolean, usages: string[]): Promise<WebCryptoKeyPair>;
  sign(algorithm: object, key: WebCryptoKey, data: Bytes): Promise<ArrayBuffer>;
  verify(algorithm: object, key: WebCryptoKey, signature: Bytes, data: Bytes): Promise<boolean>;
  digest(algorithm: string, data: Bytes): Promise<ArrayBuffer>;
}

export function webCrypto(): { subtle: SubtleLike; getRandomValues<T extends ArrayBufferView>(a: T): T } {
  const c = (globalThis as { crypto?: { subtle?: unknown; getRandomValues?: unknown } }).crypto;
  if (!c || !c.subtle || typeof c.getRandomValues !== 'function') {
    throw new MoonSsoError({
      error: 'unsupported_environment',
      error_description: 'WebCrypto (crypto.subtle) is not available; use a secure context (https or localhost) or Node.js >= 20',
    });
  }
  return c as unknown as { subtle: SubtleLike; getRandomValues<T extends ArrayBufferView>(a: T): T };
}

export function utf8(s: string): Bytes {
  return encoder.encode(s) as Bytes;
}

export function fromUtf8(b: Uint8Array): string {
  return decoder.decode(b);
}

export function randomBytes(n: number): Bytes {
  const out = new Uint8Array(n);
  webCrypto().getRandomValues(out);
  return out;
}

/** Random base64url string with `bytes` bytes of entropy. */
export function randomToken(bytes = 32): string {
  return base64UrlEncode(randomBytes(bytes));
}

export function base64Encode(b: Uint8Array): string {
  let s = '';
  for (let i = 0; i < b.length; i += 0x8000) {
    s += String.fromCharCode(...b.subarray(i, i + 0x8000));
  }
  return btoa(s);
}

export function base64Decode(s: string): Bytes {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    out[i] = bin.charCodeAt(i);
  }
  return out;
}

export function base64UrlEncode(b: Uint8Array | string): string {
  const bytes = typeof b === 'string' ? utf8(b) : b;
  return base64Encode(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function base64UrlDecode(s: string): Bytes {
  if (!/^[A-Za-z0-9_-]*$/.test(s)) {
    throw new Error('invalid base64url');
  }
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
  const pad = b64.length % 4;
  if (pad === 1) {
    throw new Error('invalid base64url length');
  }
  return base64Decode(pad ? b64 + '='.repeat(4 - pad) : b64);
}

export async function sha256(data: Uint8Array | string): Promise<Bytes> {
  const bytes = typeof data === 'string' ? utf8(data) : (data as Bytes);
  return new Uint8Array(await webCrypto().subtle.digest('SHA-256', bytes));
}

export function concatBytes(...parts: Uint8Array[]): Bytes {
  const len = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(len);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/** Constant-time comparison of two equal-length strings (length itself is not secret). */
export function timingSafeEqualString(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

export function nowSeconds(now: () => number = Date.now): number {
  return Math.floor(now() / 1000);
}

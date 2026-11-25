// Local signing keys, JWT minting and a scripted fetch for unit tests.

const subtle = globalThis.crypto.subtle;

export interface TestKey {
  alg: 'RS256' | 'ES256';
  kid: string;
  privateKey: CryptoKey;
  jwk: JsonWebKey & { kid: string; alg: string; use: string };
}

export async function makeKey(alg: 'RS256' | 'ES256', kid: string): Promise<TestKey> {
  const pair =
    alg === 'RS256'
      ? await subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify'])
      : await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const pub = await subtle.exportKey('jwk', pair.publicKey);
  delete pub.key_ops;
  delete pub.ext;
  return { alg, kid, privateKey: pair.privateKey, jwk: { ...pub, kid, alg, use: 'sig' } };
}

const b64u = (b: Uint8Array | string) => Buffer.from(b).toString('base64url');

export async function signJwt(key: TestKey, payload: Record<string, unknown>, header: Record<string, unknown> = {}): Promise<string> {
  const h = { alg: key.alg, kid: key.kid, ...header };
  const input = `${b64u(JSON.stringify(h))}.${b64u(JSON.stringify(payload))}`;
  const algo = key.alg === 'RS256' ? { name: 'RSASSA-PKCS1-v1_5' } : { name: 'ECDSA', hash: 'SHA-256' };
  const sig = new Uint8Array(await subtle.sign(algo, key.privateKey, new TextEncoder().encode(input)));
  return `${input}.${b64u(sig)}`;
}

export const ISSUER = 'https://sso.test';

/** Discovery document for ISSUER. */
export function discoveryDoc(): Record<string, string> {
  return {
    issuer: ISSUER,
    authorization_endpoint: `${ISSUER}/oauth/authorize`,
    token_endpoint: `${ISSUER}/oauth/token`,
    userinfo_endpoint: `${ISSUER}/oauth/userinfo`,
    jwks_uri: `${ISSUER}/.well-known/jwks.json`,
    revocation_endpoint: `${ISSUER}/oauth/revoke`,
    end_session_endpoint: `${ISSUER}/oauth/end_session`,
    authorization_challenge_endpoint: `${ISSUER}/oauth/authorize-challenge`,
    moon_events_endpoint: `${ISSUER}/api/v1/me/events`,
  };
}

export type Route = (req: Request) => Response | undefined | Promise<Response | undefined>;

export interface ScriptedFetch {
  fetch: typeof fetch;
  calls: Request[];
  count(pathname: string): number;
}

/** fetch that serves discovery + JWKS for ISSUER and delegates everything else to `route`. */
export function scriptedFetch(keys: () => TestKey[], route: Route = () => undefined): ScriptedFetch {
  const calls: Request[] = [];
  const f: typeof fetch = async (input, init) => {
    const req = new Request(input, init);
    calls.push(req);
    const url = new URL(req.url);
    if (url.pathname === '/.well-known/openid-configuration') {
      return Response.json(discoveryDoc());
    }
    if (url.pathname === '/.well-known/jwks.json') {
      return Response.json({ keys: keys().map((k) => k.jwk) });
    }
    const r = await route(req);
    if (r) {
      return r;
    }
    return new Response('not found', { status: 404 });
  };
  return { fetch: f, calls, count: (p) => calls.filter((c) => new URL(c.url).pathname === p).length };
}

export function nowS(): number {
  return Math.floor(Date.now() / 1000);
}

/**
 * Standard Webhooks verification (sdk-spec §5.2): HMAC-SHA256 over
 * "{id}.{timestamp}.{body}", any of several space-separated v1 signatures,
 * constant-time comparison (WebCrypto verify), ±5 minute timestamp tolerance.
 */

import type { IncomingMessage, ServerResponse } from 'node:http';
import { type MoonEvent, parseEvent } from './shared/account.js';
import { base64Decode, base64Encode, type Bytes, concatBytes, nowSeconds, utf8, type WebCryptoKey, webCrypto } from './shared/encoding.js';
import { MoonSsoError } from './shared/errors.js';
import { ExpiringSet } from './shared/util.js';
import { readRawBody, sendJson } from './http-util.js';

export class WebhookVerificationError extends MoonSsoError {
  constructor(description: string) {
    super({ error: 'invalid_webhook', error_description: description, status: 400 });
    this.name = 'WebhookVerificationError';
  }
}

export type HeaderSource = Headers | Record<string, string | string[] | undefined>;

function getHeader(h: HeaderSource, name: string): string | undefined {
  if (typeof (h as Headers).get === 'function') {
    return (h as Headers).get(name) ?? undefined;
  }
  const rec = h as Record<string, string | string[] | undefined>;
  let v = rec[name];
  if (v === undefined) {
    const lower = name.toLowerCase();
    for (const [k, val] of Object.entries(rec)) {
      if (k.toLowerCase() === lower) {
        v = val;
        break;
      }
    }
  }
  return Array.isArray(v) ? v.join(' ') : v;
}

export interface WebhookMessage {
  /** webhook-id (use it for de-duplication). */
  id: string;
  /** webhook-timestamp, epoch seconds. */
  timestamp: number;
  /** Parsed JSON body. */
  payload: unknown;
  /** Raw body text. */
  body: string;
}

export interface WebhookVerifierOptions {
  /** Allowed clock difference (default 300 s). */
  toleranceSeconds?: number;
  now?: () => number;
}

export class WebhookVerifier {
  private readonly key: Promise<WebCryptoKey>;
  private readonly tolerance: number;
  private readonly now: () => number;

  /** `secret` is the "whsec_…" value (base64 key after the prefix). */
  constructor(secret: string, opts: WebhookVerifierOptions = {}) {
    if (typeof secret !== 'string' || secret === '') {
      throw new MoonSsoError({ error: 'invalid_configuration', error_description: 'webhook secret is required' });
    }
    const b64 = secret.startsWith('whsec_') ? secret.slice('whsec_'.length) : secret;
    let raw: Bytes;
    try {
      raw = base64Decode(b64);
    } catch {
      throw new MoonSsoError({ error: 'invalid_configuration', error_description: 'webhook secret is not valid base64' });
    }
    if (raw.length === 0) {
      throw new MoonSsoError({ error: 'invalid_configuration', error_description: 'webhook secret is empty' });
    }
    this.key = webCrypto().subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
    this.tolerance = opts.toleranceSeconds ?? 300;
    this.now = opts.now ?? Date.now;
  }

  private static signedContent(id: string, timestamp: string, body: Uint8Array): Bytes {
    return concatBytes(utf8(`${id}.${timestamp}.`), body);
  }

  /** Computes the "v1,<base64>" signature (useful for tests and for re-signing). */
  async sign(id: string, timestamp: number | string, body: string | Uint8Array): Promise<string> {
    const bytes = typeof body === 'string' ? utf8(body) : body;
    const mac = await webCrypto().subtle.sign({ name: 'HMAC' }, await this.key, WebhookVerifier.signedContent(id, String(timestamp), bytes));
    return `v1,${base64Encode(new Uint8Array(mac))}`;
  }

  /**
   * Verifies headers + raw body. The body must be the exact bytes received
   * (do not re-serialize parsed JSON).
   */
  async verify(headers: HeaderSource, body: string | Uint8Array): Promise<WebhookMessage> {
    const id = getHeader(headers, 'webhook-id');
    const ts = getHeader(headers, 'webhook-timestamp');
    const sigs = getHeader(headers, 'webhook-signature');
    if (!id || !ts || !sigs) {
      throw new WebhookVerificationError('missing webhook-id, webhook-timestamp or webhook-signature header');
    }
    if (!/^\d{1,12}$/.test(ts)) {
      throw new WebhookVerificationError('invalid webhook-timestamp');
    }
    const t = Number(ts);
    if (Math.abs(nowSeconds(this.now) - t) > this.tolerance) {
      throw new WebhookVerificationError('webhook timestamp outside the tolerance window');
    }
    const bytes = typeof body === 'string' ? utf8(body) : (body as Bytes);
    const content = WebhookVerifier.signedContent(id, ts, bytes);
    const key = await this.key;
    let ok = false;
    for (const entry of sigs.split(' ')) {
      const comma = entry.indexOf(',');
      if (comma < 0 || entry.slice(0, comma) !== 'v1') {
        continue;
      }
      let mac: Bytes;
      try {
        mac = base64Decode(entry.slice(comma + 1));
      } catch {
        continue;
      }
      if (mac.length !== 32) {
        continue;
      }
      // WebCrypto HMAC verify compares in constant time.
      if (await webCrypto().subtle.verify({ name: 'HMAC' }, key, mac, content)) {
        ok = true;
        break;
      }
    }
    if (!ok) {
      throw new WebhookVerificationError('no matching signature');
    }
    const text = new TextDecoder().decode(bytes);
    let payload: unknown;
    try {
      payload = JSON.parse(text);
    } catch {
      throw new WebhookVerificationError('body is not JSON');
    }
    return { id, timestamp: t, payload, body: text };
  }

  /** verify() + Event shape check. */
  async verifyEvent(headers: HeaderSource, body: string | Uint8Array): Promise<{ message: WebhookMessage; event: MoonEvent }> {
    const message = await this.verify(headers, body);
    const event = parseEvent(message.payload);
    if (!event) {
      throw new WebhookVerificationError('body is not a Moon SSO event');
    }
    return { message, event };
  }
}

export interface WebhookHandlerOptions {
  /** "whsec_…" secret or a prepared verifier. */
  secret?: string;
  verifier?: WebhookVerifier;
  /** Handles one event; throw to make the server retry later. */
  onEvent: (event: MoonEvent, message: WebhookMessage) => void | Promise<void>;
  /** Drop repeated webhook-id values within 10 minutes (default true). */
  dedupe?: boolean;
  /** Logging hook for rejected or failed deliveries. */
  onError?: (e: unknown) => void;
  maxBodyBytes?: number;
}

/**
 * Request handler for webhook deliveries. Mount it before any body parser
 * (or behind express.raw()) so the exact bytes can be verified.
 * Answers 204 on success, 400 on verification failure, 500 when onEvent throws.
 */
export function createWebhookHandler(opts: WebhookHandlerOptions): (req: IncomingMessage, res: ServerResponse) => Promise<void> {
  const verifier = opts.verifier ?? (opts.secret ? new WebhookVerifier(opts.secret) : undefined);
  if (!verifier) {
    throw new MoonSsoError({ error: 'invalid_configuration', error_description: 'secret or verifier is required' });
  }
  const seen = new ExpiringSet();
  return async (req, res) => {
    if (req.method !== 'POST') {
      res.setHeader('Allow', 'POST');
      sendJson(res, 405, { error: 'invalid_request' });
      return;
    }
    let message: WebhookMessage;
    let event: MoonEvent;
    try {
      const body = await readRawBody(req, opts.maxBodyBytes ?? 1024 * 1024);
      ({ message, event } = await verifier.verifyEvent(req.headers, body));
    } catch (e) {
      opts.onError?.(e);
      const status = e instanceof MoonSsoError && e.status === 413 ? 413 : 400;
      sendJson(res, status, { error: e instanceof MoonSsoError ? e.error : 'invalid_webhook' });
      return;
    }
    if ((opts.dedupe ?? true) && seen.has(message.id)) {
      res.statusCode = 204;
      res.end();
      return;
    }
    try {
      await opts.onEvent(event, message);
      if (opts.dedupe ?? true) {
        seen.add(message.id, 10 * 60_000);
      }
      res.statusCode = 204;
      res.end();
    } catch (e) {
      opts.onError?.(e);
      sendJson(res, 500, { error: 'server_error' });
    }
  };
}

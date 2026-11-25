/**
 * Minimal node:http helpers (cookies, bodies, redirects) so the middleware
 * works with plain http, Connect and Express alike.
 */

import type { IncomingMessage, ServerResponse } from 'node:http';
import { MoonSsoError } from './shared/errors.js';

export type NextFunction = (err?: unknown) => void;
export type Middleware = (req: IncomingMessage, res: ServerResponse, next: NextFunction) => void;

export function header(req: IncomingMessage, name: string): string | undefined {
  const v = req.headers[name.toLowerCase()];
  return Array.isArray(v) ? v[0] : v;
}

export function parseCookies(req: IncomingMessage): Record<string, string> {
  const out: Record<string, string> = {};
  const raw = req.headers.cookie;
  if (!raw) {
    return out;
  }
  for (const part of raw.split(';')) {
    const i = part.indexOf('=');
    if (i <= 0) {
      continue;
    }
    const k = part.slice(0, i).trim();
    let v = part.slice(i + 1).trim();
    if (v.startsWith('"') && v.endsWith('"')) {
      v = v.slice(1, -1);
    }
    if (!(k in out)) {
      try {
        out[k] = decodeURIComponent(v);
      } catch {
        out[k] = v;
      }
    }
  }
  return out;
}

export interface CookieOptions {
  path?: string;
  domain?: string;
  secure?: boolean;
  httpOnly?: boolean;
  sameSite?: 'Lax' | 'Strict' | 'None';
  /** seconds; omit for a browser-session cookie */
  maxAge?: number;
}

export function serializeCookie(name: string, value: string, o: CookieOptions = {}): string {
  const parts = [`${name}=${encodeURIComponent(value)}`, `Path=${o.path ?? '/'}`];
  if (o.domain) {
    parts.push(`Domain=${o.domain}`);
  }
  if (o.maxAge !== undefined) {
    parts.push(`Max-Age=${Math.floor(o.maxAge)}`);
    if (o.maxAge <= 0) {
      parts.push('Expires=Thu, 01 Jan 1970 00:00:00 GMT');
    }
  }
  if (o.httpOnly ?? true) {
    parts.push('HttpOnly');
  }
  if (o.secure) {
    parts.push('Secure');
  }
  parts.push(`SameSite=${o.sameSite ?? 'Lax'}`);
  return parts.join('; ');
}

export function appendSetCookie(res: ServerResponse, cookie: string): void {
  const prev = res.getHeader('Set-Cookie');
  if (prev === undefined) {
    res.setHeader('Set-Cookie', [cookie]);
  } else if (Array.isArray(prev)) {
    res.setHeader('Set-Cookie', [...prev, cookie]);
  } else {
    res.setHeader('Set-Cookie', [String(prev), cookie]);
  }
}

/** Reads the raw request body (up to `limit` bytes). Uses an already-buffered body (express.raw / text) when present. */
export async function readRawBody(req: IncomingMessage, limit = 1024 * 1024): Promise<Buffer> {
  const pre = (req as IncomingMessage & { body?: unknown; rawBody?: unknown }).rawBody ?? (req as { body?: unknown }).body;
  if (Buffer.isBuffer(pre)) {
    return pre;
  }
  if (typeof pre === 'string') {
    return Buffer.from(pre, 'utf8');
  }
  if (pre !== undefined && pre !== null && typeof pre === 'object' && (req as { readableEnded?: boolean }).readableEnded) {
    throw new MoonSsoError({
      error: 'invalid_request',
      error_description: 'request body was already parsed; mount this handler before JSON/urlencoded body parsers or use express.raw()',
    });
  }
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    const b = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as string);
    size += b.length;
    if (size > limit) {
      throw new MoonSsoError({ error: 'invalid_request', error_description: 'request body too large', status: 413 });
    }
    chunks.push(b);
  }
  return Buffer.concat(chunks);
}

/** Reads an application/x-www-form-urlencoded body (or uses an already-parsed object). */
export async function readForm(req: IncomingMessage, limit = 64 * 1024): Promise<URLSearchParams> {
  const pre = (req as { body?: unknown }).body;
  if (pre && typeof pre === 'object' && !Buffer.isBuffer(pre)) {
    const out = new URLSearchParams();
    for (const [k, v] of Object.entries(pre as Record<string, unknown>)) {
      if (typeof v === 'string') {
        out.set(k, v);
      }
    }
    return out;
  }
  return new URLSearchParams((await readRawBody(req, limit)).toString('utf8'));
}

export function sendJson(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  const text = JSON.stringify(body);
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  for (const [k, v] of Object.entries(headers)) {
    res.setHeader(k, v);
  }
  res.end(text);
}

export function isHtmx(req: IncomingMessage): boolean {
  return header(req, 'hx-request') === 'true';
}

/**
 * HTMX-aware redirect (sdk-spec §2): HTMX requests get `200` + `HX-Redirect`
 * (a 302 would be followed by XHR and swapped into the page); others get 302.
 */
export function redirect(req: IncomingMessage, res: ServerResponse, url: string): void {
  res.setHeader('Cache-Control', 'no-store');
  if (isHtmx(req)) {
    res.statusCode = 200;
    res.setHeader('HX-Redirect', url);
    res.end();
    return;
  }
  res.statusCode = 302;
  res.setHeader('Location', url);
  res.end();
}

/** Path + query of the request as the client sees it (Express mounts rewrite req.url). */
export function originalUrl(req: IncomingMessage): string {
  return (req as IncomingMessage & { originalUrl?: string }).originalUrl ?? req.url ?? '/';
}

/** Accepts only same-site relative paths ("/x", not "//host" or "http://"), otherwise `fallback`. */
export function safeReturnTo(v: string | null | undefined, fallback = '/'): string {
  if (!v || !v.startsWith('/') || v.startsWith('//') || v.startsWith('/\\') || /[\r\n]/.test(v)) {
    return fallback;
  }
  return v;
}

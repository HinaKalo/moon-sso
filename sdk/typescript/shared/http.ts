/**
 * Thin fetch wrapper: User-Agent, timeouts and the unified error model.
 */

import { errorFromResponse, invalidResponse, MoonSsoError, networkError } from './errors.js';

export type FetchLike = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;

export interface HttpOptions {
  /** fetch implementation; defaults to globalThis.fetch. */
  fetch?: FetchLike | undefined;
  /**
   * User-Agent header (sdk-spec §0). Browsers control User-Agent themselves,
   * so the browser SDK leaves it unset.
   */
  userAgent?: string | undefined;
  /** Per-request timeout in milliseconds (default 30 000). Streaming requests opt out. */
  timeoutMs?: number | undefined;
}

export interface RequestOptions extends RequestInit {
  /** Overrides the client timeout; 0 disables it (used for SSE). */
  timeoutMs?: number;
  /** Short description used in network error messages, e.g. "token request". */
  what?: string;
}

export class HttpClient {
  readonly fetchImpl: FetchLike;
  readonly userAgent: string | undefined;
  readonly timeoutMs: number;

  constructor(opts: HttpOptions = {}) {
    const f = opts.fetch ?? (globalThis.fetch as FetchLike | undefined);
    if (!f) {
      throw new MoonSsoError({ error: 'unsupported_environment', error_description: 'fetch is not available' });
    }
    // Bind so that window.fetch is not invoked with a foreign `this`.
    this.fetchImpl = opts.fetch ? opts.fetch : (input, init) => f.call(globalThis, input, init);
    this.userAgent = opts.userAgent;
    this.timeoutMs = opts.timeoutMs ?? 30_000;
  }

  /** Performs a request. Transport failures become MoonSsoError("network"); HTTP errors are returned as responses. */
  async request(url: string, init: RequestOptions = {}): Promise<Response> {
    const { timeoutMs, what, ...rest } = init;
    const headers = new Headers(rest.headers);
    if (this.userAgent && !headers.has('User-Agent')) {
      headers.set('User-Agent', this.userAgent);
    }
    const t = timeoutMs ?? this.timeoutMs;
    const signals: AbortSignal[] = [];
    if (rest.signal) {
      signals.push(rest.signal);
    }
    if (t > 0) {
      signals.push(AbortSignal.timeout(t));
    }
    const signal = signals.length === 0 ? undefined : signals.length === 1 ? signals[0] : AbortSignal.any(signals);
    try {
      return await this.fetchImpl(url, { ...rest, headers, signal: signal ?? null });
    } catch (e) {
      if (rest.signal?.aborted) {
        throw new MoonSsoError({ error: 'aborted', error_description: `${what ?? 'request'} was aborted`, cause: e });
      }
      throw networkError(e, what ?? 'request');
    }
  }

  /** Request + JSON body for 2xx, MoonSsoError otherwise. */
  async json<T>(url: string, init: RequestOptions = {}): Promise<T> {
    const res = await this.request(url, init);
    if (!res.ok) {
      throw await errorFromResponse(res);
    }
    return readJson<T>(res);
  }
}

export async function readJson<T>(res: Response): Promise<T> {
  let text: string;
  try {
    text = await res.text();
  } catch (e) {
    throw networkError(e, 'reading response');
  }
  try {
    return JSON.parse(text) as T;
  } catch {
    throw invalidResponse('response body is not valid JSON', res.status);
  }
}

/** Reads a JSON body of any status without throwing on HTTP errors. */
export async function readJsonLoose(res: Response): Promise<unknown> {
  let text: string;
  try {
    text = await res.text();
  } catch (e) {
    throw networkError(e, 'reading response');
  }
  if (!text) {
    return undefined;
  }
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return undefined;
  }
}

/** Discards a body so the connection can be reused. */
export async function drain(res: Response): Promise<void> {
  try {
    await res.body?.cancel();
  } catch {
    // ignore
  }
}

export function trimSlash(s: string): string {
  return s.replace(/\/+$/, '');
}

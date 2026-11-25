/**
 * Server-Sent Events over fetch (sdk-spec §5.1): a WHATWG-conformant frame
 * parser and a reconnecting stream with Last-Event-ID resume, retry: hints,
 * jittered backoff and token refresh on 401 / token_expired.
 */

import { errorFromResponse, MoonSsoError } from './errors.js';
import type { HttpClient } from './http.js';

export interface SseMessage {
  /** Event type ("message" when the frame had no event: field). */
  event: string;
  data: string;
  /** Last event ID in effect after this message (may be inherited from earlier frames). */
  lastEventId: string;
  /** True when this frame carried its own id: field. */
  hasId: boolean;
}

/** Incremental SSE parser. Feed decoded text; complete frames are emitted to `onMessage`. */
export class SseParser {
  private buf = '';
  private data: string[] = [];
  private hasData = false;
  private eventType = '';
  private frameHasId = false;
  private sawCR = false;
  lastEventId = '';
  retry: number | undefined;

  constructor(
    private readonly onMessage: (m: SseMessage) => void,
    private readonly onRetry?: (ms: number) => void,
  ) {}

  feed(text: string): void {
    let chunk = text;
    if (this.sawCR && chunk.startsWith('\n')) {
      // CRLF split across chunks: the CR already ended the line.
      chunk = chunk.slice(1);
    }
    this.sawCR = false;
    this.buf += chunk;
    let start = 0;
    for (let i = 0; i < this.buf.length; i++) {
      const c = this.buf.charCodeAt(i);
      if (c !== 10 && c !== 13) {
        continue;
      }
      const line = this.buf.slice(start, i);
      if (c === 13) {
        if (i + 1 < this.buf.length) {
          if (this.buf.charCodeAt(i + 1) === 10) {
            i++;
          }
        } else {
          this.sawCR = true;
        }
      }
      start = i + 1;
      this.line(line);
    }
    this.buf = this.buf.slice(start);
  }

  /** Signals end of stream; an incomplete trailing frame is discarded (per spec). */
  end(): void {
    this.buf = '';
    this.reset();
  }

  private reset(): void {
    this.data = [];
    this.hasData = false;
    this.eventType = '';
    this.frameHasId = false;
  }

  private line(line: string): void {
    if (line === '') {
      this.dispatch();
      return;
    }
    if (line.startsWith(':')) {
      return; // comment, e.g. ": ping"
    }
    const colon = line.indexOf(':');
    let field = line;
    let value = '';
    if (colon >= 0) {
      field = line.slice(0, colon);
      value = line.slice(colon + 1);
      if (value.startsWith(' ')) {
        value = value.slice(1);
      }
    }
    switch (field) {
      case 'data':
        this.data.push(value);
        this.hasData = true;
        break;
      case 'event':
        this.eventType = value;
        break;
      case 'id':
        if (!value.includes('\0')) {
          this.lastEventId = value;
          this.frameHasId = true;
        }
        break;
      case 'retry':
        if (/^\d+$/.test(value)) {
          this.retry = Number(value);
          this.onRetry?.(this.retry);
        }
        break;
      default:
        break; // unknown fields are ignored
    }
  }

  private dispatch(): void {
    if (!this.hasData) {
      this.reset();
      return;
    }
    const msg: SseMessage = {
      event: this.eventType || 'message',
      data: this.data.join('\n'),
      lastEventId: this.lastEventId,
      hasId: this.frameHasId,
    };
    this.reset();
    this.onMessage(msg);
  }
}

/** Reads a fetch body stream through the parser until it ends or `signal` aborts. */
export async function readSse(body: ReadableStream<Uint8Array>, parser: SseParser, signal?: AbortSignal): Promise<void> {
  const reader = body.getReader();
  const decoder = new TextDecoder('utf-8');
  const onAbort = () => {
    reader.cancel().catch(() => undefined);
  };
  signal?.addEventListener('abort', onAbort, { once: true });
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) {
        const tail = decoder.decode();
        if (tail) {
          parser.feed(tail);
        }
        parser.end();
        return;
      }
      parser.feed(decoder.decode(value, { stream: true }));
    }
  } finally {
    signal?.removeEventListener('abort', onAbort);
    reader.releaseLock();
  }
}

export interface EventStreamOptions {
  http: HttpClient;
  url: string;
  /** Returns a usable access token; `force` asks for a refresh, `rejected` is the token the server refused. */
  getAccessToken: (opts: { force?: boolean; rejected?: string }) => Promise<string>;
  onMessage: (m: SseMessage) => void | Promise<void>;
  onOpen?: () => void;
  /** Called with each connection failure; the stream keeps retrying unless `isFatal` says otherwise. */
  onError?: (e: unknown) => void;
  /** Stops reconnecting for errors that cannot heal (default: invalid_grant and 403). */
  isFatal?: (e: unknown) => boolean;
  /** Initial Last-Event-ID. */
  lastEventId?: string;
  /** Delay bounds without a retry: hint (default 3000–8000 ms, sdk-spec §5.1). */
  minDelayMs?: number;
  maxDelayMs?: number;
  /** Upper bound of the exponential backoff on consecutive failures (default 60 000 ms). */
  maxBackoffMs?: number;
  random?: () => number;
}

function defaultFatal(e: unknown): boolean {
  return e instanceof MoonSsoError && (e.error === 'invalid_grant' || e.status === 403 || e.error === 'session_expired');
}

/**
 * A reconnecting SSE connection. Call start() once; stop() aborts it.
 * `reconnectNow()` drops the current connection and reconnects immediately.
 */
export class EventStream {
  private readonly o: EventStreamOptions;
  private abort: AbortController | undefined;
  private running = false;
  private loop: Promise<void> | undefined;
  private wake: (() => void) | undefined;
  private failures = 0;
  private retryHint: number | undefined;
  private forceRefresh = false;
  private immediate = false;
  lastEventId: string;
  connected = false;

  constructor(opts: EventStreamOptions) {
    this.o = opts;
    this.lastEventId = opts.lastEventId ?? '';
  }

  get isRunning(): boolean {
    return this.running;
  }

  start(): void {
    if (this.running) {
      return;
    }
    this.running = true;
    this.loop = this.run();
  }

  async stop(): Promise<void> {
    this.running = false;
    this.abort?.abort();
    this.wake?.();
    await this.loop?.catch(() => undefined);
    this.loop = undefined;
  }

  /** Reconnects at once, refreshing the access token first when `refresh` is true. */
  reconnectNow(refresh = false): void {
    this.forceRefresh = this.forceRefresh || refresh;
    this.immediate = true;
    this.abort?.abort();
    this.wake?.();
  }

  private delay(): number {
    const random = this.o.random ?? Math.random;
    const min = this.o.minDelayMs ?? 3000;
    const max = this.o.maxDelayMs ?? 8000;
    const base = this.retryHint ?? min + random() * (max - min);
    const factor = 2 ** Math.min(Math.max(this.failures - 1, 0), 5);
    const capped = Math.min(base * factor, this.o.maxBackoffMs ?? 60_000);
    return Math.round(capped + random() * Math.min(1000, capped * 0.25));
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => {
      const t = setTimeout(done, ms);
      function done() {
        clearTimeout(t);
        resolve();
      }
      this.wake = () => {
        this.wake = undefined;
        done();
      };
    });
  }

  private async run(): Promise<void> {
    while (this.running) {
      this.immediate = false;
      try {
        await this.connectOnce();
        // Clean end of stream (server closed): normal reconnect delay.
      } catch (e) {
        if (!this.running) {
          break;
        }
        if (!(e instanceof MoonSsoError && e.error === 'aborted' && this.immediate)) {
          this.failures++;
          this.o.onError?.(e);
          if ((this.o.isFatal ?? defaultFatal)(e)) {
            this.running = false;
            break;
          }
        }
      } finally {
        this.connected = false;
      }
      if (!this.running) {
        break;
      }
      if (!this.immediate) {
        await this.sleep(this.delay());
      }
    }
  }

  private async connectOnce(): Promise<void> {
    const force = this.forceRefresh;
    this.forceRefresh = false;
    let token = await this.o.getAccessToken({ force });
    let res = await this.open(token);
    if (res.status === 401) {
      await res.body?.cancel().catch(() => undefined);
      token = await this.o.getAccessToken({ force: true, rejected: token });
      res = await this.open(token);
    }
    if (!res.ok || !res.body) {
      throw await errorFromResponse(res);
    }
    const ct = res.headers.get('Content-Type') ?? '';
    if (!ct.toLowerCase().startsWith('text/event-stream')) {
      await res.body.cancel().catch(() => undefined);
      throw new MoonSsoError({ error: 'invalid_response', error_description: `unexpected content type ${ct}`, status: res.status });
    }
    this.connected = true;
    this.failures = 0;
    this.o.onOpen?.();
    const parser = new SseParser(
      (m) => {
        if (m.hasId) {
          this.lastEventId = m.lastEventId;
        }
        if (m.event === 'token_expired') {
          // The server ends the stream when the token expires: refresh, then reconnect immediately.
          this.forceRefresh = true;
          this.immediate = true;
        }
        try {
          const r = this.o.onMessage(m);
          if (r && typeof (r as Promise<void>).catch === 'function') {
            (r as Promise<void>).catch((e) => this.o.onError?.(e));
          }
        } catch (e) {
          this.o.onError?.(e);
        }
      },
      (ms) => {
        this.retryHint = ms;
      },
    );
    parser.lastEventId = this.lastEventId;
    await readSse(res.body, parser, this.abort?.signal);
  }

  private open(token: string): Promise<Response> {
    this.abort = new AbortController();
    // Only headers the server's CORS preflight allows (Authorization, Last-Event-ID).
    const headers: Record<string, string> = {
      Authorization: `Bearer ${token}`,
      Accept: 'text/event-stream',
    };
    if (this.lastEventId) {
      headers['Last-Event-ID'] = this.lastEventId;
    }
    return this.o.http.request(this.o.url, { method: 'GET', headers, signal: this.abort.signal, timeoutMs: 0, what: 'event stream' });
  }
}

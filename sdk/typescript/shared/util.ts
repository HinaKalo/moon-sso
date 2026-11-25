/**
 * Small concurrency and event helpers shared by both SDKs.
 */

/**
 * Coalesces concurrent calls per key: while a call for `key` is running,
 * further calls receive the same promise (sdk-spec §1.3 single-flight).
 */
export class SingleFlight<K, V> {
  private readonly inflight = new Map<K, Promise<V>>();

  run(key: K, fn: () => Promise<V>): Promise<V> {
    const existing = this.inflight.get(key);
    if (existing) {
      return existing;
    }
    const p = (async () => fn())().finally(() => {
      if (this.inflight.get(key) === p) {
        this.inflight.delete(key);
      }
    });
    this.inflight.set(key, p);
    return p;
  }

  has(key: K): boolean {
    return this.inflight.has(key);
  }

  get size(): number {
    return this.inflight.size;
  }
}

/** In-process mutex keyed by name (FIFO). */
export class KeyedMutex {
  private readonly tails = new Map<string, Promise<void>>();

  async run<T>(name: string, fn: () => Promise<T>): Promise<T> {
    const prev = this.tails.get(name) ?? Promise.resolve();
    let release!: () => void;
    const mine = new Promise<void>((r) => {
      release = r;
    });
    const tail = prev.then(() => mine);
    this.tails.set(name, tail);
    await prev;
    try {
      return await fn();
    } finally {
      release();
      if (this.tails.get(name) === tail) {
        this.tails.delete(name);
      }
    }
  }
}

export type Listener<T> = (payload: T) => void;

/** Minimal typed event emitter; listener exceptions are isolated. */
export class Emitter<Events extends { [K in keyof Events]: unknown }> {
  private readonly listeners = new Map<keyof Events, Set<Listener<never>>>();
  private readonly onListenerError: ((e: unknown) => void) | undefined;

  constructor(onListenerError?: (e: unknown) => void) {
    this.onListenerError = onListenerError;
  }

  on<K extends keyof Events>(event: K, fn: Listener<Events[K]>): () => void {
    let set = this.listeners.get(event);
    if (!set) {
      set = new Set();
      this.listeners.set(event, set);
    }
    set.add(fn as Listener<never>);
    return () => this.off(event, fn);
  }

  once<K extends keyof Events>(event: K, fn: Listener<Events[K]>): () => void {
    const off = this.on(event, (p) => {
      off();
      fn(p);
    });
    return off;
  }

  off<K extends keyof Events>(event: K, fn: Listener<Events[K]>): void {
    this.listeners.get(event)?.delete(fn as Listener<never>);
  }

  emit<K extends keyof Events>(event: K, payload: Events[K]): void {
    const set = this.listeners.get(event);
    if (!set) {
      return;
    }
    for (const fn of [...set]) {
      try {
        (fn as Listener<Events[K]>)(payload);
      } catch (e) {
        if (this.onListenerError) {
          this.onListenerError(e);
        } else {
          queueMicrotask(() => {
            throw e;
          });
        }
      }
    }
  }
}

/** A TTL set for replay detection (jti, webhook-id). Bounded in size. */
export class ExpiringSet {
  private readonly items = new Map<string, number>();
  private readonly maxSize: number;
  private readonly now: () => number;

  constructor(opts: { maxSize?: number; now?: () => number } = {}) {
    this.maxSize = opts.maxSize ?? 100_000;
    this.now = opts.now ?? Date.now;
  }

  /** Adds `key` for `ttlMs`; returns false if it was already present and unexpired. */
  add(key: string, ttlMs: number): boolean {
    const now = this.now();
    const exp = this.items.get(key);
    if (exp !== undefined && exp > now) {
      return false;
    }
    if (this.items.size >= this.maxSize) {
      this.sweep(now);
      while (this.items.size >= this.maxSize) {
        const oldest = this.items.keys().next();
        if (oldest.done) {
          break;
        }
        this.items.delete(oldest.value);
      }
    }
    this.items.delete(key);
    this.items.set(key, now + ttlMs);
    return true;
  }

  has(key: string): boolean {
    const exp = this.items.get(key);
    return exp !== undefined && exp > this.now();
  }

  private sweep(now: number): void {
    for (const [k, exp] of this.items) {
      if (exp <= now) {
        this.items.delete(k);
      }
    }
  }
}

export function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(signal.reason);
      return;
    }
    const t = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    const onAbort = () => {
      clearTimeout(t);
      reject(signal?.reason);
    };
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

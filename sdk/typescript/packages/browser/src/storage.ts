/**
 * Pluggable persistence, locking and tab-sync primitives. The defaults use
 * IndexedDB, the Web Locks API and BroadcastChannel; the in-memory variants
 * let the SDK run in Node.js (tests, SSR) or in restricted browsers.
 */

import { KeyedMutex } from './shared/util.js';

/** Async key/value store. Values must survive structured cloning (CryptoKey included). */
export interface KeyValueStore {
  get<T>(key: string): Promise<T | undefined>;
  set<T>(key: string, value: T): Promise<void>;
  delete(key: string): Promise<void>;
}

/** Exclusive named lock, held for the duration of `fn`. */
export interface LockProvider {
  withLock<T>(name: string, fn: () => Promise<T>): Promise<T>;
}

/** Same-origin broadcast between tabs. */
export interface TabChannel {
  post(message: unknown): void;
  subscribe(fn: (message: unknown) => void): () => void;
  close(): void;
}

/** In-memory store. Share one instance between clients to simulate several tabs. */
export class MemoryStore implements KeyValueStore {
  private readonly map = new Map<string, unknown>();

  async get<T>(key: string): Promise<T | undefined> {
    return this.map.get(key) as T | undefined;
  }

  async set<T>(key: string, value: T): Promise<void> {
    this.map.set(key, value);
  }

  async delete(key: string): Promise<void> {
    this.map.delete(key);
  }

  /** Number of stored entries (diagnostics). */
  get size(): number {
    return this.map.size;
  }
}

function idbRequest<T>(req: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error('IndexedDB request failed'));
  });
}

/**
 * IndexedDB-backed store (one object store, keys are strings). CryptoKey
 * objects are stored by structured clone, so non-extractable keys stay non-extractable.
 */
export class IndexedDBStore implements KeyValueStore {
  private readonly dbName: string;
  private readonly storeName: string;
  private db: Promise<IDBDatabase> | undefined;

  constructor(opts: { dbName?: string; storeName?: string } = {}) {
    this.dbName = opts.dbName ?? 'moon-sso';
    this.storeName = opts.storeName ?? 'kv';
  }

  static isAvailable(): boolean {
    return typeof indexedDB !== 'undefined';
  }

  private open(): Promise<IDBDatabase> {
    if (!this.db) {
      this.db = new Promise<IDBDatabase>((resolve, reject) => {
        const req = indexedDB.open(this.dbName, 1);
        req.onupgradeneeded = () => {
          if (!req.result.objectStoreNames.contains(this.storeName)) {
            req.result.createObjectStore(this.storeName);
          }
        };
        req.onsuccess = () => {
          const db = req.result;
          db.onversionchange = () => {
            db.close();
            this.db = undefined;
          };
          resolve(db);
        };
        req.onerror = () => reject(req.error ?? new Error('cannot open IndexedDB'));
        req.onblocked = () => reject(new Error('IndexedDB open is blocked by another tab'));
      });
      this.db.catch(() => {
        this.db = undefined;
      });
    }
    return this.db;
  }

  private async tx<T>(mode: IDBTransactionMode, fn: (s: IDBObjectStore) => IDBRequest<T>): Promise<T> {
    const db = await this.open();
    const tx = db.transaction(this.storeName, mode);
    const result = idbRequest(fn(tx.objectStore(this.storeName)));
    await new Promise<void>((resolve, reject) => {
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error ?? new Error('IndexedDB transaction failed'));
      tx.onabort = () => reject(tx.error ?? new Error('IndexedDB transaction aborted'));
    });
    return result;
  }

  async get<T>(key: string): Promise<T | undefined> {
    return (await this.tx('readonly', (s) => s.get(key))) as T | undefined;
  }

  async set<T>(key: string, value: T): Promise<void> {
    await this.tx('readwrite', (s) => s.put(value, key));
  }

  async delete(key: string): Promise<void> {
    await this.tx('readwrite', (s) => s.delete(key));
  }
}

/** Web Locks API (navigator.locks): exclusive across all tabs and workers of the origin. */
export class WebLocksProvider implements LockProvider {
  static isAvailable(): boolean {
    return typeof navigator !== 'undefined' && typeof (navigator as Navigator & { locks?: unknown }).locks === 'object' && navigator.locks !== null;
  }

  withLock<T>(name: string, fn: () => Promise<T>): Promise<T> {
    return navigator.locks.request(name, { mode: 'exclusive' }, () => fn()) as Promise<T>;
  }
}

/** Lock within one JavaScript realm. Share an instance between clients to simulate tabs. */
export class InProcessLockProvider implements LockProvider {
  private readonly mutex = new KeyedMutex();

  withLock<T>(name: string, fn: () => Promise<T>): Promise<T> {
    return this.mutex.run(name, fn);
  }
}

/** BroadcastChannel-based tab channel (available in browsers and Node.js >= 18). */
export class BroadcastTabChannel implements TabChannel {
  private readonly bc: BroadcastChannel;
  private readonly subs = new Set<(m: unknown) => void>();

  constructor(name: string) {
    this.bc = new BroadcastChannel(name);
    this.bc.onmessage = (ev: MessageEvent) => {
      for (const fn of [...this.subs]) {
        try {
          fn(ev.data);
        } catch {
          // a faulty subscriber must not break the others
        }
      }
    };
  }

  static isAvailable(): boolean {
    return typeof BroadcastChannel !== 'undefined';
  }

  post(message: unknown): void {
    try {
      this.bc.postMessage(message);
    } catch {
      // channel closed
    }
  }

  subscribe(fn: (message: unknown) => void): () => void {
    this.subs.add(fn);
    return () => this.subs.delete(fn);
  }

  close(): void {
    this.subs.clear();
    this.bc.onmessage = null;
    this.bc.close();
  }
}

/** Channel that delivers nothing (single-tab environments). */
export class NoopTabChannel implements TabChannel {
  post(): void {}
  subscribe(): () => void {
    return () => undefined;
  }
  close(): void {}
}

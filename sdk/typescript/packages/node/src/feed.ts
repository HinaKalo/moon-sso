/**
 * Users changes feed (sdk-spec §5.4): client_credentials (scope users:sync),
 * paged GET /api/v1/users/changes; on 410 a full snapshot via GET /api/v1/users,
 * then continue from the first page's watermark.
 */

import { createAuthorizedFetch, type AuthorizedFetch, type MoonEvent, type TokenProvider } from './shared/account.js';
import { errorFromResponse, invalidResponse, MoonSsoError } from './shared/errors.js';
import { type HttpClient, readJson } from './shared/http.js';
import { isObject } from './shared/jose.js';

export interface UserSnapshot {
  sub: string;
  status: 'active' | 'disabled' | 'deleted' | string;
  preferred_username: string;
  name: string;
  nickname: string;
  picture?: string | null;
  updated_at: number;
  profile_version: number;
  [k: string]: unknown;
}

export interface ChangesPage {
  events: MoonEvent[];
  nextCursor: string;
  hasMore: boolean;
}

export interface SnapshotPage {
  users: UserSnapshot[];
  /** Feed position to continue from after the snapshot (taken from the first page). */
  watermark: string;
  hasMore: boolean;
}

export type SyncItem =
  | { kind: 'events'; events: MoonEvent[]; cursor: string }
  | { kind: 'snapshot'; users: UserSnapshot[]; watermark: string; done: boolean };

export class CursorExpiredError extends MoonSsoError {
  constructor(description?: string) {
    super({ error: 'cursor_expired', error_description: description ?? 'cursor is older than the retention period; run a full sync', status: 410 });
    this.name = 'CursorExpiredError';
  }
}

export interface ChangesFeedOptions {
  http: HttpClient;
  apiBase: string;
  /** client_credentials token provider with scope users:sync. */
  getAccessToken: TokenProvider;
}

export class ChangesFeed {
  private readonly base: string;
  private readonly fetch: AuthorizedFetch;

  constructor(opts: ChangesFeedOptions) {
    this.base = opts.apiBase.replace(/\/+$/, '');
    this.fetch = createAuthorizedFetch({ http: opts.http, getAccessToken: opts.getAccessToken });
  }

  /** One page of events after `cursor` ("" or "0" = from the beginning). Throws CursorExpiredError on 410. */
  async syncChanges(cursor = '', opts: { limit?: number } = {}): Promise<ChangesPage> {
    const u = new URL(`${this.base}/users/changes`);
    if (cursor) {
      u.searchParams.set('cursor', cursor);
    }
    u.searchParams.set('limit', String(Math.min(Math.max(opts.limit ?? 100, 1), 500)));
    const res = await this.fetch(u.toString(), { headers: { Accept: 'application/json' }, what: 'changes feed' });
    if (res.status === 410) {
      const err = await errorFromResponse(res);
      throw new CursorExpiredError(err.error_description);
    }
    if (!res.ok) {
      throw await errorFromResponse(res);
    }
    const b = await readJson<unknown>(res);
    if (!isObject(b) || !Array.isArray(b['events']) || typeof b['next_cursor'] !== 'string') {
      throw invalidResponse('changes feed response is invalid', res.status);
    }
    return { events: b['events'] as MoonEvent[], nextCursor: b['next_cursor'], hasMore: b['has_more'] === true };
  }

  /** Full snapshot of all users who granted this client, page by page. */
  async *fullSync(opts: { limit?: number } = {}): AsyncGenerator<SnapshotPage, string, void> {
    let cursor: string | undefined;
    let watermark: string | undefined;
    for (;;) {
      const u = new URL(`${this.base}/users`);
      u.searchParams.set('limit', String(Math.min(Math.max(opts.limit ?? 200, 1), 500)));
      if (cursor) {
        u.searchParams.set('cursor', cursor);
      }
      const res = await this.fetch(u.toString(), { headers: { Accept: 'application/json' }, what: 'users snapshot' });
      if (!res.ok) {
        throw await errorFromResponse(res);
      }
      const b = await readJson<unknown>(res);
      if (!isObject(b) || !Array.isArray(b['users']) || typeof b['watermark'] !== 'string') {
        throw invalidResponse('users snapshot response is invalid', res.status);
      }
      // The first page's watermark is where the feed continues; later pages may report newer values.
      watermark ??= b['watermark'];
      const hasMore = b['has_more'] === true && typeof b['next_cursor'] === 'string' && b['next_cursor'] !== '';
      yield { users: b['users'] as UserSnapshot[], watermark, hasMore };
      if (!hasMore) {
        return watermark;
      }
      cursor = b['next_cursor'] as string;
    }
  }

  /**
   * Catches up from `cursor` until the feed has no more events. On 410 it
   * yields the snapshot pages first, then continues from the watermark.
   * Persist `cursor` / `watermark` from each item after processing it.
   */
  async *changes(cursor = '', opts: { limit?: number } = {}): AsyncGenerator<SyncItem, string, void> {
    let cur = cursor;
    for (;;) {
      let page: ChangesPage;
      try {
        page = await this.syncChanges(cur, opts);
      } catch (e) {
        if (!(e instanceof CursorExpiredError)) {
          throw e;
        }
        let watermark = '';
        for await (const snap of this.fullSync(opts)) {
          watermark = snap.watermark;
          yield { kind: 'snapshot', users: snap.users, watermark: snap.watermark, done: !snap.hasMore };
        }
        cur = watermark;
        continue;
      }
      if (page.events.length > 0 || page.nextCursor !== cur) {
        yield { kind: 'events', events: page.events, cursor: page.nextCursor };
      }
      cur = page.nextCursor;
      if (!page.hasMore) {
        return cur;
      }
    }
  }
}

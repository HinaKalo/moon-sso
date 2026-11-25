/**
 * Authorized fetch (401 → refresh once → replay once, sdk-spec §1.6) and the
 * account API under /api/v1/me (sdk-spec §4).
 */

import { errorFromResponse, invalidResponse, MoonSsoError } from './errors.js';
import { type HttpClient, readJson } from './http.js';
import { isObject } from './jose.js';

/** The user's profile as seen by this client. */
export interface Profile {
  sub: string;
  preferred_username: string;
  name: string;
  nickname: string;
  picture: string | null;
  updated_at: number;
  profile_version: number;
  totp_enabled?: boolean;
  [k: string]: unknown;
}

export type EventType =
  | 'user.updated'
  | 'user.password_changed'
  | 'user.disabled'
  | 'user.enabled'
  | 'user.deleted'
  | 'consent.revoked';

export interface EventData {
  sub: string;
  status: 'active' | 'disabled' | 'deleted';
  preferred_username?: string;
  name?: string;
  nickname?: string;
  picture?: string | null;
  profile_version: number;
  updated_at: number;
  changed?: string[];
  [k: string]: unknown;
}

/** Event object shared by webhooks, the changes feed and SSE. */
export interface MoonEvent {
  id: string;
  seq: number;
  type: EventType | string;
  occurred_at: string;
  data: EventData;
}

export type TokenProvider = (opts: { force?: boolean; rejected?: string }) => Promise<string>;

export interface AuthorizedFetchOptions {
  http: HttpClient;
  getAccessToken: TokenProvider;
}

export type AuthorizedFetch = (url: string, init?: RequestInit & { what?: string }) => Promise<Response>;

function replayable(body: RequestInit['body']): boolean {
  if (body === undefined || body === null) {
    return true;
  }
  return !(typeof ReadableStream !== 'undefined' && body instanceof ReadableStream);
}

/**
 * Wraps fetch with `Authorization: Bearer`. A 401 forces one token refresh and
 * replays the request once; a second 401 is returned to the caller unchanged.
 * Bodies that are streams cannot be replayed and are sent only once.
 */
export function createAuthorizedFetch(opts: AuthorizedFetchOptions): AuthorizedFetch {
  return async (url, init = {}) => {
    const { what, ...rest } = init;
    const send = (token: string) => {
      const headers = new Headers(rest.headers);
      headers.set('Authorization', `Bearer ${token}`);
      return opts.http.request(url, { ...rest, headers, what: what ?? 'API request' });
    };
    const token = await opts.getAccessToken({});
    const res = await send(token);
    if (res.status !== 401 || !replayable(rest.body)) {
      return res;
    }
    await res.body?.cancel().catch(() => undefined);
    const fresh = await opts.getAccessToken({ force: true, rejected: token });
    return send(fresh);
  };
}

export interface ProfileUpdate {
  username?: string;
  displayName?: string;
}

export interface UpdateOptions {
  /** Expected profile version (number) or full ETag; the server answers 412 on conflict. */
  ifMatch?: number | string;
}

export interface ChangePasswordInput {
  currentPassword: string;
  newPassword: string;
  /** Keep the session of this token signed in (default true). Other devices are always signed out. */
  keepThisDevice?: boolean;
}

export type AvatarInput = Blob | ArrayBuffer | Uint8Array;

export function etagFor(version: number): string {
  return `"pv-${version}"`;
}

export function parseProfile(body: unknown, status?: number): Profile {
  if (!isObject(body) || typeof body['sub'] !== 'string') {
    throw invalidResponse('profile response is invalid', status);
  }
  return body as Profile;
}

/** Account API bound to a token provider. `onProfile` is called after every successful read or write. */
export class AccountApi {
  private readonly base: string;
  private readonly fetch: AuthorizedFetch;
  private readonly onProfile: ((p: Profile) => void) | undefined;
  private readonly conditionalGet: boolean;
  private cached: Profile | undefined;

  /**
   * `conditionalGet` sends If-None-Match on getMe. Browsers must leave it off:
   * the server's CORS preflight does not allow the If-None-Match header.
   */
  constructor(opts: { apiBase: string; authorizedFetch: AuthorizedFetch; onProfile?: (p: Profile) => void; conditionalGet?: boolean }) {
    this.base = opts.apiBase.replace(/\/+$/, '');
    this.fetch = opts.authorizedFetch;
    this.onProfile = opts.onProfile;
    this.conditionalGet = opts.conditionalGet ?? true;
  }

  /** Last profile returned by the server (or seeded via setCached). */
  get profile(): Profile | undefined {
    return this.cached;
  }

  setCached(p: Profile | undefined): void {
    this.cached = p;
  }

  private async profileFrom(res: Response): Promise<Profile> {
    if (!res.ok) {
      throw await errorFromResponse(res);
    }
    const p = parseProfile(await readJson<unknown>(res), res.status);
    this.cached = p;
    this.onProfile?.(p);
    return p;
  }

  /** GET /api/v1/me. Uses If-None-Match with the cached version and returns the cache on 304. */
  async getMe(opts: { revalidate?: boolean } = {}): Promise<Profile> {
    const headers: Record<string, string> = { Accept: 'application/json' };
    const cached = this.cached;
    if (cached && this.conditionalGet && opts.revalidate !== false) {
      headers['If-None-Match'] = etagFor(cached.profile_version);
    }
    const res = await this.fetch(`${this.base}/me`, { method: 'GET', headers, what: 'GET /me' });
    if (res.status === 304 && cached) {
      await res.body?.cancel().catch(() => undefined);
      return cached;
    }
    return this.profileFrom(res);
  }

  /** PATCH /api/v1/me (scope profile:write). */
  async updateProfile(update: ProfileUpdate, opts: UpdateOptions = {}): Promise<Profile> {
    const body: Record<string, string> = {};
    if (update.username !== undefined) {
      body['username'] = update.username;
    }
    if (update.displayName !== undefined) {
      body['display_name'] = update.displayName;
    }
    if (Object.keys(body).length === 0) {
      throw new MoonSsoError({ error: 'invalid_request', error_description: 'nothing to update' });
    }
    const headers: Record<string, string> = { 'Content-Type': 'application/json', Accept: 'application/json' };
    if (opts.ifMatch !== undefined) {
      headers['If-Match'] = typeof opts.ifMatch === 'number' ? etagFor(opts.ifMatch) : opts.ifMatch;
    }
    const res = await this.fetch(`${this.base}/me`, { method: 'PATCH', headers, body: JSON.stringify(body), what: 'PATCH /me' });
    return this.profileFrom(res);
  }

  /** PUT /api/v1/me/avatar with the raw image bytes (≤ 5 MB). */
  async uploadAvatar(image: AvatarInput, contentType?: string): Promise<Profile> {
    let type = contentType;
    let body: Blob | Uint8Array<ArrayBuffer>;
    if (typeof Blob !== 'undefined' && image instanceof Blob) {
      type = type ?? (image.type || undefined);
      body = image;
    } else if (image instanceof ArrayBuffer) {
      body = new Uint8Array(image);
    } else {
      body = new Uint8Array(image as Uint8Array);
    }
    if (!type || !type.toLowerCase().startsWith('image/')) {
      throw new MoonSsoError({ error: 'invalid_request', error_description: 'avatar content type must be image/*' });
    }
    const size = body instanceof Uint8Array ? body.byteLength : body.size;
    if (size > 5 * 1024 * 1024) {
      throw new MoonSsoError({ error: 'avatar_too_large', error_description: 'avatar must not exceed 5 MB' });
    }
    const res = await this.fetch(`${this.base}/me/avatar`, {
      method: 'PUT',
      headers: { 'Content-Type': type, Accept: 'application/json' },
      body,
      what: 'PUT /me/avatar',
    });
    return this.profileFrom(res);
  }

  /** DELETE /api/v1/me/avatar. */
  async deleteAvatar(): Promise<Profile> {
    const res = await this.fetch(`${this.base}/me/avatar`, { method: 'DELETE', headers: { Accept: 'application/json' }, what: 'DELETE /me/avatar' });
    return this.profileFrom(res);
  }

  /** POST /api/v1/me/password (scope password:write). Other devices are signed out by the server. */
  async changePassword(input: ChangePasswordInput): Promise<void> {
    const res = await this.fetch(`${this.base}/me/password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({
        current_password: input.currentPassword,
        new_password: input.newPassword,
        keep_this_device: input.keepThisDevice ?? true,
      }),
      what: 'POST /me/password',
    });
    if (!res.ok) {
      throw await errorFromResponse(res);
    }
    await res.body?.cancel().catch(() => undefined);
  }
}

/** Parses an SSE / webhook / feed event payload. */
export function parseEvent(data: string | unknown): MoonEvent | undefined {
  let v: unknown = data;
  if (typeof data === 'string') {
    try {
      v = JSON.parse(data);
    } catch {
      return undefined;
    }
  }
  if (!isObject(v) || typeof v['type'] !== 'string' || !isObject(v['data'])) {
    return undefined;
  }
  return v as unknown as MoonEvent;
}

/** Converts an event's data into the Profile shape (fields the event does not carry stay as in `base`). */
export function profileFromEvent(ev: MoonEvent, base?: Profile): Profile {
  const d = ev.data;
  const p: Profile = {
    ...(base ?? {}),
    sub: d.sub,
    preferred_username: d.preferred_username ?? base?.preferred_username ?? '',
    name: d.name ?? base?.name ?? '',
    nickname: d.nickname ?? base?.nickname ?? '',
    picture: d.picture === undefined ? (base?.picture ?? null) : d.picture,
    updated_at: d.updated_at,
    profile_version: d.profile_version,
  };
  if (base?.totp_enabled !== undefined) {
    p.totp_enabled = base.totp_enabled;
  }
  return p;
}

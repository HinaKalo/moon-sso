/**
 * OpenID Provider discovery (sdk-spec §0): cached for one hour; a failed
 * refetch keeps serving the stale document.
 */

import { invalidResponse, MoonSsoError } from './errors.js';
import { type HttpClient, trimSlash } from './http.js';

export interface DiscoveryDocument {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint: string;
  jwks_uri: string;
  registration_endpoint?: string;
  revocation_endpoint?: string;
  introspection_endpoint?: string;
  end_session_endpoint?: string;
  authorization_challenge_endpoint?: string;
  moon_api_audience?: string;
  moon_events_endpoint?: string;
  scopes_supported?: string[];
  [key: string]: unknown;
}

const REQUIRED: (keyof DiscoveryDocument)[] = ['issuer', 'authorization_endpoint', 'token_endpoint', 'jwks_uri'];

export class Discovery {
  readonly issuer: string;
  private readonly http: HttpClient;
  private readonly ttlMs: number;
  private readonly now: () => number;
  private doc: DiscoveryDocument | undefined;
  private fetchedAt = 0;
  private inflight: Promise<DiscoveryDocument> | undefined;

  constructor(issuer: string, http: HttpClient, opts: { ttlMs?: number; now?: () => number } = {}) {
    this.issuer = trimSlash(issuer);
    this.http = http;
    this.ttlMs = opts.ttlMs ?? 3_600_000;
    this.now = opts.now ?? Date.now;
  }

  /** Returns the (possibly cached) discovery document. */
  async get(): Promise<DiscoveryDocument> {
    if (this.doc && this.now() - this.fetchedAt < this.ttlMs) {
      return this.doc;
    }
    if (!this.inflight) {
      this.inflight = this.load().finally(() => {
        this.inflight = undefined;
      });
    }
    return this.inflight;
  }

  private async load(): Promise<DiscoveryDocument> {
    try {
      const doc = await this.http.json<DiscoveryDocument>(`${this.issuer}/.well-known/openid-configuration`, {
        what: 'discovery',
      });
      for (const k of REQUIRED) {
        if (typeof doc[k] !== 'string') {
          throw invalidResponse(`discovery document lacks ${String(k)}`);
        }
      }
      if (trimSlash(doc.issuer) !== this.issuer) {
        throw new MoonSsoError({
          error: 'invalid_issuer',
          error_description: `discovery issuer ${doc.issuer} does not match configured issuer ${this.issuer}`,
        });
      }
      this.doc = doc;
      this.fetchedAt = this.now();
      return doc;
    } catch (e) {
      if (this.doc) {
        // Keep serving the stale document; retry no sooner than in a minute.
        this.fetchedAt = this.now() - this.ttlMs + 60_000;
        return this.doc;
      }
      throw e;
    }
  }

  /** Base URL of the account / sync REST API. */
  apiBase(): string {
    return `${this.issuer}/api/v1`;
  }
}

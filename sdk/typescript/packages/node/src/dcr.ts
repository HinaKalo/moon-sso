/**
 * Dynamic client registration (RFC 7591, sdk-spec §6).
 */

import { Discovery } from './shared/discovery.js';
import { errorFromResponse, invalidResponse, MoonSsoError } from './shared/errors.js';
import { type FetchLike, HttpClient, readJson } from './shared/http.js';
import { isObject } from './shared/jose.js';
import { USER_AGENT } from './version.js';

export interface ClientMetadata {
  client_name: string;
  redirect_uris: string[];
  post_logout_redirect_uris?: string[];
  grant_types?: string[];
  token_endpoint_auth_method?: 'client_secret_basic' | 'client_secret_post' | 'none';
  application_type?: 'web' | 'native';
  scope?: string;
  id_token_signed_response_alg?: 'RS256' | 'ES256';
  backchannel_logout_uri?: string;
  dpop_bound_access_tokens?: boolean;
  webhook_url?: string;
  webhook_events?: string[];
  logo_uri?: string;
  client_uri?: string;
  policy_uri?: string;
  tos_uri?: string;
  [k: string]: unknown;
}

export interface ClientInformation extends ClientMetadata {
  client_id: string;
  client_secret?: string;
  registration_access_token: string;
  registration_client_uri?: string;
  webhook_secret?: string;
  status: 'active' | 'pending_approval' | 'disabled' | string;
}

export interface RegisterClientOptions {
  /** Issuer (registration_endpoint is discovered) … */
  issuer?: string;
  /** … or the registration endpoint itself. */
  registrationEndpoint?: string;
  /** Initial access token from the developer center ("iat_…"). */
  initialAccessToken: string;
  metadata: ClientMetadata;
  fetch?: FetchLike;
}

/** Registers a client. The result's client_secret / registration_access_token are secrets: store them safely. */
export async function registerClient(opts: RegisterClientOptions): Promise<ClientInformation> {
  const http = new HttpClient({ fetch: opts.fetch, userAgent: USER_AGENT });
  let endpoint = opts.registrationEndpoint;
  if (!endpoint) {
    if (!opts.issuer) {
      throw new MoonSsoError({ error: 'invalid_configuration', error_description: 'issuer or registrationEndpoint is required' });
    }
    const doc = await new Discovery(opts.issuer, http).get();
    endpoint = doc.registration_endpoint;
    if (!endpoint) {
      throw new MoonSsoError({ error: 'invalid_response', error_description: 'server does not advertise registration_endpoint' });
    }
  }
  const res = await http.request(endpoint, {
    method: 'POST',
    headers: { Authorization: `Bearer ${opts.initialAccessToken}`, 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify(opts.metadata),
    what: 'client registration',
  });
  if (!res.ok) {
    throw await errorFromResponse(res);
  }
  const b = await readJson<unknown>(res);
  if (!isObject(b) || typeof b['client_id'] !== 'string') {
    throw invalidResponse('registration response has no client_id', res.status);
  }
  return b as ClientInformation;
}

/** Reads (GET), updates (PUT) or deletes (DELETE) a registration with its registration access token (RFC 7592). */
export class ClientRegistration {
  private readonly http: HttpClient;

  constructor(
    readonly registrationClientUri: string,
    private readonly registrationAccessToken: string,
    opts: { fetch?: FetchLike } = {},
  ) {
    this.http = new HttpClient({ fetch: opts.fetch, userAgent: USER_AGENT });
  }

  private headers(json = false): Record<string, string> {
    const h: Record<string, string> = { Authorization: `Bearer ${this.registrationAccessToken}`, Accept: 'application/json' };
    if (json) {
      h['Content-Type'] = 'application/json';
    }
    return h;
  }

  async read(): Promise<ClientInformation> {
    return this.http.json(this.registrationClientUri, { headers: this.headers(), what: 'read registration' });
  }

  async update(metadata: ClientMetadata): Promise<ClientInformation> {
    return this.http.json(this.registrationClientUri, { method: 'PUT', headers: this.headers(true), body: JSON.stringify(metadata), what: 'update registration' });
  }

  async delete(): Promise<void> {
    const res = await this.http.request(this.registrationClientUri, { method: 'DELETE', headers: this.headers(), what: 'delete registration' });
    if (!res.ok) {
      throw await errorFromResponse(res);
    }
  }
}

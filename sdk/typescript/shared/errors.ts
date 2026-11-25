/**
 * Unified error model (sdk-spec §0): every failure surfaces as a MoonSsoError
 * carrying the OAuth error code (or "network" / "invalid_response"), the
 * server's description, the HTTP status and, for 422, the offending field.
 * Messages never contain tokens, secrets or passwords.
 */

export interface MoonSsoErrorInit {
  /** OAuth error code, or "network" / "invalid_response" / an SDK code. */
  error: string;
  error_description?: string | undefined;
  /** HTTP status code, when the error came from a response. */
  status?: number | undefined;
  /** Field name for 422 validation errors. */
  field?: string | undefined;
  /** Extra JSON members of the error body (e.g. auth_session, change_url). */
  body?: Record<string, unknown> | undefined;
  cause?: unknown;
}

export class MoonSsoError extends Error {
  readonly error: string;
  readonly error_description: string | undefined;
  readonly status: number | undefined;
  readonly field: string | undefined;
  readonly body: Record<string, unknown> | undefined;

  constructor(init: MoonSsoErrorInit) {
    const msg = init.error_description ? `${init.error}: ${init.error_description}` : init.error;
    super(init.status ? `${msg} (HTTP ${init.status})` : msg, init.cause === undefined ? undefined : { cause: init.cause });
    this.name = 'MoonSsoError';
    this.error = init.error;
    this.error_description = init.error_description;
    this.status = init.status;
    this.field = init.field;
    this.body = init.body;
  }

  /** True for transport failures (no HTTP response was received). */
  get isNetworkError(): boolean {
    return this.error === 'network';
  }

  /** True when the refresh token is dead and the user must sign in again. */
  get isSessionExpired(): boolean {
    return this.error === 'invalid_grant';
  }
}

/** First-party login needs a second factor (sdk-spec §2). */
export class OtpRequiredError extends MoonSsoError {
  /** Opaque value to send back with the one-time code. */
  readonly authSession: string;
  /** Factor required by the server, currently always "otp". */
  readonly required: string;

  constructor(init: MoonSsoErrorInit & { authSession: string; required?: string | undefined }) {
    super(init);
    this.name = 'OtpRequiredError';
    this.authSession = init.authSession;
    this.required = init.required ?? 'otp';
  }
}

/** The administrator reset the password; the user must change it in a browser first. */
export class PasswordChangeRequiredError extends MoonSsoError {
  readonly changeUrl: string;

  constructor(init: MoonSsoErrorInit & { changeUrl: string }) {
    super(init);
    this.name = 'PasswordChangeRequiredError';
    this.changeUrl = init.changeUrl;
  }
}

/** Statuses after which a token request is retried once (sdk-spec §1.5). */
export const TRANSIENT_STATUSES: ReadonlySet<number> = new Set([502, 503, 504]);

export function isMoonSsoError(e: unknown): e is MoonSsoError {
  return e instanceof MoonSsoError;
}

export function networkError(cause: unknown, what: string): MoonSsoError {
  let detail = 'request failed';
  if (cause instanceof Error) {
    detail = cause.name === 'TimeoutError' ? 'request timed out' : cause.name === 'AbortError' ? 'request aborted' : cause.message;
  }
  return new MoonSsoError({ error: 'network', error_description: `${what}: ${detail}`, cause });
}

export function invalidResponse(description: string, status?: number): MoonSsoError {
  return new MoonSsoError({ error: 'invalid_response', error_description: description, status });
}

function str(v: unknown): string | undefined {
  return typeof v === 'string' && v !== '' ? v : undefined;
}

/**
 * Builds the matching error from a parsed JSON error body. Recognizes the
 * first-party login errors insufficient_authorization and password_change_required.
 */
export function errorFromBody(status: number, body: unknown): MoonSsoError {
  if (body === null || typeof body !== 'object' || Array.isArray(body)) {
    return invalidResponse(`unexpected HTTP ${status} response`, status);
  }
  const b = body as Record<string, unknown>;
  const error = str(b['error']) ?? (status === 401 ? 'invalid_token' : status === 403 ? 'access_denied' : `http_${status}`);
  const init: MoonSsoErrorInit = {
    error,
    error_description: str(b['error_description']),
    status,
    field: str(b['field']),
    body: b,
  };
  const authSession = str(b['auth_session']);
  if (error === 'insufficient_authorization' && authSession) {
    return new OtpRequiredError({ ...init, authSession, required: str(b['required']) });
  }
  const changeUrl = str(b['change_url']);
  if (error === 'password_change_required' && changeUrl) {
    return new PasswordChangeRequiredError({ ...init, changeUrl });
  }
  return new MoonSsoError(init);
}

/** Reads an error response. Never throws; a non-JSON body yields invalid_response or http_<status>. */
export async function errorFromResponse(res: Response): Promise<MoonSsoError> {
  let text = '';
  try {
    text = await res.text();
  } catch (e) {
    return networkError(e, 'reading error response');
  }
  if (text) {
    try {
      return errorFromBody(res.status, JSON.parse(text));
    } catch {
      // fall through: not JSON
    }
  }
  const wwwAuth = res.headers.get('WWW-Authenticate');
  if (wwwAuth) {
    const m = /error="([^"]+)"/.exec(wwwAuth);
    if (m?.[1]) {
      return new MoonSsoError({ error: m[1], status: res.status });
    }
  }
  const code = res.status === 401 ? 'invalid_token' : res.status === 403 ? 'access_denied' : `http_${res.status}`;
  return new MoonSsoError({ error: code, error_description: res.statusText || undefined, status: res.status });
}

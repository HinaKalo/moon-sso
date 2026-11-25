"""Synchronous Moon SSO client."""

from __future__ import annotations

from typing import Any, Callable, Iterable, Iterator, Mapping

import httpx

from ._base import DEFAULT_SCOPE, _ClientBase
from ._util import DEFAULT_TIMEOUT, RETRY_STATUSES, error_from_response, expect_json, json_body, network_error
from .discovery import JWKS, Discovery
from .dpop import DPoPKey
from .errors import CursorExpired, MoonSSOError, OtpRequired, TokenValidationError
from .jose import unverified_header, validate_access_token, validate_id_token, validate_logout_token, verify_signature
from .models import (
    AccessTokenClaims,
    AuthorizationRequest,
    ChangesPage,
    ClientRegistration,
    LogoutToken,
    PendingChallenge,
    ProviderMetadata,
    SyncBatch,
    TokenSet,
    UsersPage,
)
from .pkce import PKCE
from .session import UserSession
from .store import TokenStore

__all__ = ["MoonSSO", "register_client", "unregister_client"]


class MoonSSO(_ClientBase):
    """Thread-safe synchronous client for one registered application.

    Only the issuer is configured; every endpoint comes from discovery.

    :param issuer: e.g. ``https://sso.moonl.cloud``
    :param client_id: the application's client id
    :param client_secret: confidential clients only
    :param redirect_uri: default callback for the authorization code flow
    :param scope: default scope (``openid profile offline_access``)
    :param dpop: enable DPoP (default: on for public clients)
    :param dpop_key: persisted :class:`DPoPKey` (generated when omitted)
    :param audience: expected ``aud`` when verifying access tokens (default ``client_id``)
    :param http_client: custom ``httpx.Client`` (the SDK sets its User-Agent per request)
    """

    def __init__(
        self,
        issuer: str,
        client_id: str,
        client_secret: str | None = None,
        *,
        redirect_uri: str | None = None,
        scope: str = DEFAULT_SCOPE,
        token_endpoint_auth_method: str | None = None,
        dpop: bool | None = None,
        dpop_key: DPoPKey | None = None,
        audience: str | Iterable[str] | None = None,
        leeway: float = 60.0,
        refresh_skew: float = 120.0,
        http_client: httpx.Client | None = None,
        timeout: float | httpx.Timeout | None = None,
        user_agent: str | None = None,
    ) -> None:
        super().__init__(
            issuer,
            client_id,
            client_secret,
            redirect_uri=redirect_uri,
            scope=scope,
            token_endpoint_auth_method=token_endpoint_auth_method,
            dpop=dpop,
            dpop_key=dpop_key,
            audience=audience,
            leeway=leeway,
            refresh_skew=refresh_skew,
            user_agent=user_agent,
        )
        self._owns_http = http_client is None
        self.http = http_client or httpx.Client(
            timeout=timeout if timeout is not None else DEFAULT_TIMEOUT,
            follow_redirects=False,
            headers=self._default_headers(),
        )
        self.discovery = Discovery(self.issuer, self.http)
        self.jwks = JWKS(self.http, lambda: self.metadata().jwks_uri)

    # ---- lifecycle ----

    def close(self) -> None:
        if self._owns_http:
            self.http.close()

    def __enter__(self) -> "MoonSSO":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def metadata(self, force: bool = False) -> ProviderMetadata:
        """The discovery document (cached for an hour)."""
        return self.discovery.get(force)

    # ---- low-level HTTP ----

    def _post_form(
        self,
        url: str,
        data: Mapping[str, str],
        *,
        authenticate: bool = True,
        use_dpop: bool = False,
        retry_transient: bool = False,
        htu: str | None = None,
    ) -> httpx.Response:
        """POST a form with client auth, DPoP nonce handling and retry rules."""
        form: dict[str, str] = dict(data)
        headers = {"Accept": "application/json", "User-Agent": self.user_agent}
        if authenticate:
            form, _, auth_headers = self._client_auth(form)
            headers.update(auth_headers)
        key = self.dpop_key if use_dpop else None
        transient_left = 1 if retry_transient else 0
        nonce_left = 1
        while True:
            h = dict(headers)
            if key is not None:
                h["DPoP"] = key.proof("POST", htu or url)
            try:
                resp = self.http.post(url, data=form, headers=h)
            except httpx.TransportError as exc:
                if transient_left:
                    transient_left -= 1
                    continue
                raise network_error(exc) from exc
            if key is not None:
                key.update_nonce(resp.headers.get("DPoP-Nonce"))
            if resp.status_code in RETRY_STATUSES and transient_left:
                transient_left -= 1
                continue
            if key is not None and resp.status_code in (400, 401) and nonce_left:
                if json_body(resp).get("error") == "use_dpop_nonce":
                    nonce_left -= 1
                    continue
            return resp

    def _token_request(self, data: Mapping[str, str], *, refreshing: bool = False) -> TokenSet:
        meta = self.metadata()
        resp = self._post_form(meta.token_endpoint, data, use_dpop=self.dpop_key is not None, retry_transient=True)
        return self._tokens_from(resp, refreshing)

    # ---- authorization code flow ----

    def authorization_request(
        self,
        *,
        redirect_uri: str | None = None,
        scope: str | None = None,
        prompt: str | None = None,
        login_hint: str | None = None,
        resource: str | None = None,
        max_age: int | None = None,
        response_mode: str | None = None,
        return_to: str | None = None,
        extra: Mapping[str, str] | None = None,
    ) -> AuthorizationRequest:
        """Build an authorization URL with PKCE S256, ``state`` and ``nonce``.

        Store the returned object (``to_dict()``) until the callback arrives.
        """
        return self._build_authorization_request(
            self.metadata(),
            redirect_uri=redirect_uri,
            scope=scope,
            prompt=prompt,
            login_hint=login_hint,
            resource=resource,
            max_age=max_age,
            response_mode=response_mode,
            return_to=return_to,
            extra=extra,
        )

    def handle_callback(
        self,
        callback: str | Mapping[str, Any],
        request: AuthorizationRequest,
        *,
        max_age: float = 600.0,
    ) -> TokenSet:
        """Validate the callback (``state``, ``iss``, ``error``), redeem the code and validate the ID token."""
        code = self._validate_callback(self.metadata(), callback, request, max_age)
        return self.exchange_code(code, request.code_verifier, redirect_uri=request.redirect_uri, nonce=request.nonce)

    def exchange_code(
        self,
        code: str,
        code_verifier: str,
        *,
        redirect_uri: str | None = None,
        nonce: str | None = None,
    ) -> TokenSet:
        """Redeem an authorization code. ``redirect_uri`` is omitted for first-party challenge codes."""
        data = {"grant_type": "authorization_code", "code": code, "code_verifier": code_verifier}
        if redirect_uri:
            data["redirect_uri"] = redirect_uri
        tokens = self._token_request(data)
        if tokens.id_token:
            tokens.id_claims = self.verify_id_token(tokens.id_token, nonce=nonce, access_token=tokens.access_token)
        return tokens

    def refresh_tokens(self, refresh_token: str, *, scope: str | None = None, expected_sub: str | None = None) -> TokenSet:
        """Use a refresh token once (rotation). ``invalid_grant`` raises :class:`SessionExpired`.

        Prefer :class:`UserSession`, which adds single-flight and persistence.
        """
        data = {"grant_type": "refresh_token", "refresh_token": refresh_token}
        if scope:
            data["scope"] = scope
        tokens = self._token_request(data, refreshing=True)
        if tokens.id_token:
            tokens.id_claims = self.verify_id_token(tokens.id_token, access_token=tokens.access_token, expected_sub=expected_sub)
        return tokens

    def revoke(self, token: str, token_type_hint: str | None = "refresh_token") -> None:
        """RFC 7009 revocation; errors are raised (logout swallows them)."""
        meta = self.metadata()
        if not meta.revocation_endpoint:
            return
        data = {"token": token}
        if token_type_hint:
            data["token_type_hint"] = token_type_hint
        resp = self._post_form(meta.revocation_endpoint, data, retry_transient=True)
        if resp.status_code != 200:
            raise error_from_response(resp)

    def introspect(self, token: str) -> dict[str, Any]:
        """RFC 7662 introspection (confidential clients)."""
        meta = self.metadata()
        if not meta.introspection_endpoint:
            raise MoonSSOError("unsupported", "server has no introspection endpoint")
        return expect_json(self._post_form(meta.introspection_endpoint, {"token": token}, retry_transient=True))

    def end_session_url(
        self,
        id_token_hint: str | None = None,
        *,
        post_logout_redirect_uri: str | None = None,
        state: str | None = None,
    ) -> str | None:
        """RP-initiated logout URL (``None`` when the server has no end_session endpoint)."""
        return self._end_session_url(self.metadata(), id_token_hint, post_logout_redirect_uri, state)

    # ---- token validation ----

    def verify_id_token(
        self,
        id_token: str,
        *,
        nonce: str | None = None,
        access_token: str | None = None,
        expected_sub: str | None = None,
    ) -> dict[str, Any]:
        header = unverified_header(id_token)
        key = self.jwks.get_key(header.get("kid"), header["alg"])
        claims = verify_signature(id_token, key, header["alg"])
        return validate_id_token(
            header,
            claims,
            issuer=self.issuer,
            client_id=self.client_id,
            nonce=nonce,
            access_token=access_token,
            expected_sub=expected_sub,
            leeway=self.leeway,
        )

    def verify_access_token(
        self,
        token: str,
        *,
        audience: str | Iterable[str] | None = None,
        required_scopes: Iterable[str] = (),
    ) -> AccessTokenClaims:
        """Validate a bearer access token locally (resource-server use)."""
        header = unverified_header(token)
        key = self.jwks.get_key(header.get("kid"), header["alg"])
        claims = verify_signature(token, key, header["alg"])
        auds = self.audiences if audience is None else ([audience] if isinstance(audience, str) else list(audience))
        return validate_access_token(
            header, claims, issuer=self.issuer, audiences=auds, required_scopes=tuple(required_scopes), leeway=self.leeway
        )

    def verify_logout_token(self, logout_token: str) -> LogoutToken:
        """Validate a back-channel logout token, including ``jti`` replay (5 minutes)."""
        from .errors import LogoutTokenError

        try:
            header = unverified_header(logout_token)
            key = self.jwks.get_key(header.get("kid"), header["alg"])
            claims = verify_signature(logout_token, key, header["alg"])
        except TokenValidationError as exc:
            raise LogoutTokenError(exc.error_description or "invalid logout token") from exc
        token = validate_logout_token(header, claims, issuer=self.issuer, client_id=self.client_id, leeway=self.leeway)
        return self._check_logout_replay(token)

    # ---- first-party (in-app) login ----

    def _challenge_endpoint(self) -> str:
        meta = self.metadata()
        return meta.authorization_challenge_endpoint or (self.issuer + "/oauth/authorize-challenge")

    def login_with_password(self, username: str, password: str, *, scope: str | None = None) -> TokenSet:
        """First-party login. Raises :class:`OtpRequired` when a second factor is needed."""
        sc = scope or self.scope
        pkce = PKCE.generate()
        url = self._challenge_endpoint()
        form = self._challenge_form(pkce, sc, username=username, password=password)
        resp = self._post_form(url, form, use_dpop=self.dpop_key is not None)
        code = self._challenge_result(resp, pkce, sc, "challenge")
        return self.exchange_code(code, pkce.verifier)

    def submit_otp(self, pending: PendingChallenge | OtpRequired, otp: str) -> TokenSet:
        """Second step of :meth:`login_with_password` with the same PKCE parameters."""
        p = pending.pending if isinstance(pending, OtpRequired) else pending
        pkce = PKCE(verifier=p.code_verifier, challenge=p.code_challenge)
        url = self._challenge_endpoint()
        form = self._challenge_form(pkce, p.scope, auth_session=p.auth_session, otp=otp)
        resp = self._post_form(url, form, use_dpop=self.dpop_key is not None)
        code = self._challenge_result(resp, pkce, p.scope, p.endpoint)
        return self.exchange_code(code, pkce.verifier)

    def native_register(
        self, username: str, password: str, *, display_name: str | None = None, scope: str | None = None
    ) -> TokenSet:
        """Create an account inside a first-party app and sign it in (``/api/v1/native/register``)."""
        sc = scope or self.scope
        pkce = PKCE.generate()
        url = self.api_base + "/native/register"
        form = self._challenge_form(pkce, sc, username=username, password=password, display_name=display_name)
        use_dpop = self.dpop_key is not None
        resp = self._post_form(url, form, use_dpop=use_dpop)
        if use_dpop and self._dpop_htu_mismatch(resp):
            # Compatibility: the server validates this proof against the
            # authorize-challenge URL (see README "已知服务端问题").
            resp = self._post_form(url, form, use_dpop=True, htu=self._challenge_endpoint())
        code = self._challenge_result(resp, pkce, sc, "native_register")
        return self.exchange_code(code, pkce.verifier)

    # ---- server-side registration ----

    def registration_info(self) -> dict[str, Any]:
        """Whether self-service registration is open, plus username/password rules."""
        try:
            resp = self.http.get(self.api_base + "/registration", headers={"User-Agent": self.user_agent})
        except httpx.HTTPError as exc:
            raise network_error(exc) from exc
        return expect_json(resp)

    def register_user(self, username: str, password: str, *, display_name: str | None = None) -> dict[str, Any]:
        """``POST /api/v1/register`` with client authentication. 422 errors carry ``field``."""
        body: dict[str, str] = {"username": username, "password": password}
        if display_name:
            body["display_name"] = display_name
        _, _, auth_headers = self._client_auth({})
        headers = {"Accept": "application/json", "User-Agent": self.user_agent, **auth_headers}
        if self.token_endpoint_auth_method != "client_secret_basic":
            # client_secret_post / public clients authenticate with form fields,
            # which the endpoint accepts as an alternative to JSON.
            form, _, h2 = self._client_auth(body)
            try:
                resp = self.http.post(self.api_base + "/register", data=form, headers={**headers, **h2})
            except httpx.HTTPError as exc:
                raise network_error(exc) from exc
            return expect_json(resp)
        try:
            resp = self.http.post(self.api_base + "/register", json=body, headers=headers)
        except httpx.HTTPError as exc:
            raise network_error(exc) from exc
        return expect_json(resp)

    def register_client(self, initial_access_token: str, metadata: Mapping[str, Any]) -> ClientRegistration:
        """Dynamic client registration (RFC 7591) with an initial access token."""
        return register_client(self.issuer, initial_access_token, metadata, http_client=self.http, user_agent=self.user_agent)

    # ---- client credentials and the users feed ----

    def client_credentials(self, scope: str = "users:sync", *, force: bool = False) -> TokenSet:
        """A cached ``client_credentials`` token (refreshed 120 s before expiry)."""
        if not force:
            cached = self._cc_get(scope)
            if cached is not None:
                return cached
        with self._cc_lock:
            if not force:
                cached = self._cc_get(scope)
                if cached is not None:
                    return cached
            tokens = self._token_request({"grant_type": "client_credentials", "scope": scope})
            self._cc_tokens[scope] = tokens
            return tokens

    def client_credentials_token(self, scope: str = "users:sync") -> str:
        return self.client_credentials(scope).access_token

    def _client_api(self, method: str, path: str, *, scope: str = "users:sync", **kwargs: Any) -> httpx.Response:
        url = path if path.startswith("http") else self.api_base + path
        token = self.client_credentials(scope).access_token
        for attempt in (0, 1):
            headers = {"Authorization": f"Bearer {token}", "Accept": "application/json", "User-Agent": self.user_agent}
            try:
                resp = self.http.request(method, url, headers=headers, **kwargs)
            except httpx.HTTPError as exc:
                raise network_error(exc) from exc
            if resp.status_code == 401 and attempt == 0:
                token = self.client_credentials(scope, force=True).access_token
                continue
            return resp
        raise AssertionError("unreachable")  # pragma: no cover

    def sync_changes(self, cursor: str | int | None = None, *, limit: int = 100) -> ChangesPage:
        """One page of the change feed after ``cursor``. Raises :class:`CursorExpired` on 410."""
        params: dict[str, str] = {"limit": str(limit)}
        if cursor not in (None, ""):
            params["cursor"] = str(cursor)
        resp = self._client_api("GET", "/users/changes", params=params)
        return self._changes_page(expect_json(resp))

    def list_users(self, cursor: str | None = None, *, limit: int = 200) -> UsersPage:
        """One page of the user snapshot (``GET /api/v1/users``)."""
        params: dict[str, str] = {"limit": str(limit)}
        if cursor:
            params["cursor"] = cursor
        return self._users_page(expect_json(self._client_api("GET", "/users", params=params)))

    def full_sync(self, *, limit: int = 200) -> Iterator[UsersPage]:
        """Iterate snapshot pages; continue the feed from the first page's ``watermark``."""
        cursor: str | None = None
        while True:
            page = self.list_users(cursor, limit=limit)
            yield page
            if not page.has_more or not page.next_cursor:
                return
            cursor = page.next_cursor

    def get_user(self, sub: str) -> dict[str, Any]:
        """Snapshot of one granted user by client-specific ``sub``."""
        from urllib.parse import quote

        return expect_json(self._client_api("GET", "/users/" + quote(sub, safe="")))

    def iter_changes(self, cursor: str | int | None, *, limit: int = 100) -> Iterator[SyncBatch]:
        """Drain the feed from ``cursor``; falls back to a full sync when needed.

        ``cursor=None`` means "never synced" and starts with a full sync. A 410
        (cursor older than retention) triggers a full sync followed by the
        feed from the snapshot watermark. Persist ``batch.cursor`` after
        applying each batch whenever it is not ``None``.
        """
        resyncs = 0
        cur: str | None = None if cursor in (None, "") else str(cursor)
        while True:
            if cur is None:
                watermark: str | None = None
                for page in self.full_sync(limit=max(limit, 1)):
                    if watermark is None:
                        watermark = page.watermark
                    yield SyncBatch(events=[], users=page.users, cursor=None if page.has_more else watermark,
                                    full_sync=True, has_more=True)
                cur = watermark or "0"
            try:
                while True:
                    page_c = self.sync_changes(cur, limit=limit)
                    yield SyncBatch(events=page_c.events, users=[], cursor=page_c.next_cursor or cur,
                                    full_sync=False, has_more=page_c.has_more)
                    cur = page_c.next_cursor or cur
                    if not page_c.has_more:
                        return
            except CursorExpired:
                resyncs += 1
                if resyncs > 1:
                    raise
                cur = None

    # ---- user sessions ----

    def session(
        self,
        tokens: TokenSet | None = None,
        *,
        store: TokenStore | None = None,
        on_session_expired: Callable[[Exception], Any] | None = None,
        on_profile_changed: Callable[[dict[str, Any]], Any] | None = None,
        on_tokens_changed: Callable[[TokenSet], Any] | None = None,
    ) -> UserSession:
        """Wrap a login in a token manager with single-flight refresh and the account API."""
        return UserSession(
            self,
            tokens,
            store=store,
            on_session_expired=on_session_expired,
            on_profile_changed=on_profile_changed,
            on_tokens_changed=on_tokens_changed,
        )


def register_client(
    issuer: str,
    initial_access_token: str,
    metadata: Mapping[str, Any],
    *,
    http_client: httpx.Client | None = None,
    user_agent: str | None = None,
) -> ClientRegistration:
    """Dynamic client registration (RFC 7591).

    ``metadata`` uses RFC 7591 names: ``client_name``, ``redirect_uris``,
    ``token_endpoint_auth_method``, ``application_type``, ``scope``,
    ``grant_types``, ``backchannel_logout_uri``, ``webhook_url`` …
    """
    from ._util import USER_AGENT
    from .discovery import normalize_issuer

    iss = normalize_issuer(issuer)
    own = http_client is None
    http = http_client or httpx.Client(timeout=DEFAULT_TIMEOUT, follow_redirects=False)
    try:
        try:
            disc = Discovery(iss, http).get()
            endpoint = disc.registration_endpoint or iss + "/oauth/register"
            resp = http.post(
                endpoint,
                json=dict(metadata),
                headers={
                    "Authorization": f"Bearer {initial_access_token}",
                    "Accept": "application/json",
                    "User-Agent": user_agent or USER_AGENT,
                },
            )
        except httpx.HTTPError as exc:
            raise network_error(exc) from exc
        return _ClientBase._registration(resp)
    finally:
        if own:
            http.close()


def unregister_client(
    registration: ClientRegistration,
    *,
    http_client: httpx.Client | None = None,
    user_agent: str | None = None,
) -> None:
    """Delete a dynamically registered client (RFC 7592) with its registration access token."""
    from ._util import USER_AGENT

    if not registration.registration_client_uri or not registration.registration_access_token:
        raise ValueError("registration lacks registration_client_uri or registration_access_token")
    own = http_client is None
    http = http_client or httpx.Client(timeout=DEFAULT_TIMEOUT, follow_redirects=False)
    try:
        try:
            resp = http.delete(
                registration.registration_client_uri,
                headers={
                    "Authorization": f"Bearer {registration.registration_access_token}",
                    "User-Agent": user_agent or USER_AGENT,
                },
            )
        except httpx.HTTPError as exc:
            raise network_error(exc) from exc
        if resp.status_code not in (200, 204, 404):
            raise error_from_response(resp)
    finally:
        if own:
            http.close()

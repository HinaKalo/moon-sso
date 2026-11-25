"""asyncio client: :class:`AsyncMoonSSO` and :class:`AsyncUserSession`."""

from __future__ import annotations

import asyncio
import inspect
import logging
from typing import Any, AsyncIterator, Awaitable, BinaryIO, Callable, Iterable, Mapping, NoReturn, Union
from urllib.parse import quote

import httpx

from ._base import DEFAULT_SCOPE, _ClientBase, needs_refresh
from ._util import DEFAULT_TIMEOUT, RETRY_STATUSES, USER_AGENT, error_from_response, expect_json, json_body, network_error
from .discovery import AsyncDiscovery, AsyncJWKS, normalize_issuer
from .dpop import DPoPKey
from .errors import CursorExpired, LogoutTokenError, MoonSSOError, OtpRequired, SessionExpired, TokenValidationError
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
from .session import SSE_TIMEOUT, _ProfileMixin, _Reconnect, detect_image_type
from .sse import SESSION_EVENTS, ReconnectPolicy, SSEEvent, SSEParser
from .store import AsyncTokenStore, MemoryTokenStore, TokenStore

__all__ = ["AsyncMoonSSO", "AsyncUserSession", "async_register_client", "async_unregister_client"]

log = logging.getLogger("moon_sso")

Callback = Callable[..., Union[Any, Awaitable[Any]]]


async def _acall(cb: Callback | None, *args: Any) -> None:
    if cb is None:
        return
    try:
        res = cb(*args)
        if inspect.isawaitable(res):
            await res
    except Exception:
        log.exception("moon_sso callback %r failed", getattr(cb, "__name__", cb))


async def _maybe(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value


class AsyncMoonSSO(_ClientBase):
    """asyncio twin of :class:`moon_sso.MoonSSO` (same parameters, awaitable methods)."""

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
        http_client: httpx.AsyncClient | None = None,
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
        self.http = http_client or httpx.AsyncClient(
            timeout=timeout if timeout is not None else DEFAULT_TIMEOUT,
            follow_redirects=False,
            headers=self._default_headers(),
        )
        self.discovery = AsyncDiscovery(self.issuer, self.http)

        async def _jwks_uri() -> str:
            return (await self.metadata()).jwks_uri

        self.jwks = AsyncJWKS(self.http, _jwks_uri)
        self._acc_lock = asyncio.Lock()

    async def aclose(self) -> None:
        if self._owns_http:
            await self.http.aclose()

    async def __aenter__(self) -> "AsyncMoonSSO":
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def metadata(self, force: bool = False) -> ProviderMetadata:
        return await self.discovery.get(force)

    # ---- low-level HTTP ----

    async def _post_form(
        self,
        url: str,
        data: Mapping[str, str],
        *,
        authenticate: bool = True,
        use_dpop: bool = False,
        retry_transient: bool = False,
        htu: str | None = None,
    ) -> httpx.Response:
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
                resp = await self.http.post(url, data=form, headers=h)
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

    async def _token_request(self, data: Mapping[str, str], *, refreshing: bool = False) -> TokenSet:
        meta = await self.metadata()
        resp = await self._post_form(meta.token_endpoint, data, use_dpop=self.dpop_key is not None, retry_transient=True)
        return self._tokens_from(resp, refreshing)

    # ---- authorization code flow ----

    async def authorization_request(
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
        return self._build_authorization_request(
            await self.metadata(),
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

    async def handle_callback(
        self, callback: str | Mapping[str, Any], request: AuthorizationRequest, *, max_age: float = 600.0
    ) -> TokenSet:
        code = self._validate_callback(await self.metadata(), callback, request, max_age)
        return await self.exchange_code(code, request.code_verifier, redirect_uri=request.redirect_uri, nonce=request.nonce)

    async def exchange_code(
        self, code: str, code_verifier: str, *, redirect_uri: str | None = None, nonce: str | None = None
    ) -> TokenSet:
        data = {"grant_type": "authorization_code", "code": code, "code_verifier": code_verifier}
        if redirect_uri:
            data["redirect_uri"] = redirect_uri
        tokens = await self._token_request(data)
        if tokens.id_token:
            tokens.id_claims = await self.verify_id_token(tokens.id_token, nonce=nonce, access_token=tokens.access_token)
        return tokens

    async def refresh_tokens(
        self, refresh_token: str, *, scope: str | None = None, expected_sub: str | None = None
    ) -> TokenSet:
        data = {"grant_type": "refresh_token", "refresh_token": refresh_token}
        if scope:
            data["scope"] = scope
        tokens = await self._token_request(data, refreshing=True)
        if tokens.id_token:
            tokens.id_claims = await self.verify_id_token(
                tokens.id_token, access_token=tokens.access_token, expected_sub=expected_sub
            )
        return tokens

    async def revoke(self, token: str, token_type_hint: str | None = "refresh_token") -> None:
        meta = await self.metadata()
        if not meta.revocation_endpoint:
            return
        data = {"token": token}
        if token_type_hint:
            data["token_type_hint"] = token_type_hint
        resp = await self._post_form(meta.revocation_endpoint, data, retry_transient=True)
        if resp.status_code != 200:
            raise error_from_response(resp)

    async def introspect(self, token: str) -> dict[str, Any]:
        meta = await self.metadata()
        if not meta.introspection_endpoint:
            raise MoonSSOError("unsupported", "server has no introspection endpoint")
        return expect_json(await self._post_form(meta.introspection_endpoint, {"token": token}, retry_transient=True))

    async def end_session_url(
        self, id_token_hint: str | None = None, *, post_logout_redirect_uri: str | None = None, state: str | None = None
    ) -> str | None:
        return self._end_session_url(await self.metadata(), id_token_hint, post_logout_redirect_uri, state)

    # ---- token validation ----

    async def verify_id_token(
        self, id_token: str, *, nonce: str | None = None, access_token: str | None = None, expected_sub: str | None = None
    ) -> dict[str, Any]:
        header = unverified_header(id_token)
        key = await self.jwks.get_key(header.get("kid"), header["alg"])
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

    async def verify_access_token(
        self, token: str, *, audience: str | Iterable[str] | None = None, required_scopes: Iterable[str] = ()
    ) -> AccessTokenClaims:
        header = unverified_header(token)
        key = await self.jwks.get_key(header.get("kid"), header["alg"])
        claims = verify_signature(token, key, header["alg"])
        auds = self.audiences if audience is None else ([audience] if isinstance(audience, str) else list(audience))
        return validate_access_token(
            header, claims, issuer=self.issuer, audiences=auds, required_scopes=tuple(required_scopes), leeway=self.leeway
        )

    async def verify_logout_token(self, logout_token: str) -> LogoutToken:
        try:
            header = unverified_header(logout_token)
            key = await self.jwks.get_key(header.get("kid"), header["alg"])
            claims = verify_signature(logout_token, key, header["alg"])
        except TokenValidationError as exc:
            raise LogoutTokenError(exc.error_description or "invalid logout token") from exc
        token = validate_logout_token(header, claims, issuer=self.issuer, client_id=self.client_id, leeway=self.leeway)
        return self._check_logout_replay(token)

    # ---- first-party login ----

    async def _challenge_endpoint(self) -> str:
        meta = await self.metadata()
        return meta.authorization_challenge_endpoint or (self.issuer + "/oauth/authorize-challenge")

    async def login_with_password(self, username: str, password: str, *, scope: str | None = None) -> TokenSet:
        sc = scope or self.scope
        pkce = PKCE.generate()
        form = self._challenge_form(pkce, sc, username=username, password=password)
        resp = await self._post_form(await self._challenge_endpoint(), form, use_dpop=self.dpop_key is not None)
        code = self._challenge_result(resp, pkce, sc, "challenge")
        return await self.exchange_code(code, pkce.verifier)

    async def submit_otp(self, pending: PendingChallenge | OtpRequired, otp: str) -> TokenSet:
        p = pending.pending if isinstance(pending, OtpRequired) else pending
        pkce = PKCE(verifier=p.code_verifier, challenge=p.code_challenge)
        form = self._challenge_form(pkce, p.scope, auth_session=p.auth_session, otp=otp)
        resp = await self._post_form(await self._challenge_endpoint(), form, use_dpop=self.dpop_key is not None)
        code = self._challenge_result(resp, pkce, p.scope, p.endpoint)
        return await self.exchange_code(code, pkce.verifier)

    async def native_register(
        self, username: str, password: str, *, display_name: str | None = None, scope: str | None = None
    ) -> TokenSet:
        sc = scope or self.scope
        pkce = PKCE.generate()
        form = self._challenge_form(pkce, sc, username=username, password=password, display_name=display_name)
        url = self.api_base + "/native/register"
        use_dpop = self.dpop_key is not None
        resp = await self._post_form(url, form, use_dpop=use_dpop)
        if use_dpop and self._dpop_htu_mismatch(resp):
            resp = await self._post_form(url, form, use_dpop=True, htu=await self._challenge_endpoint())
        code = self._challenge_result(resp, pkce, sc, "native_register")
        return await self.exchange_code(code, pkce.verifier)

    # ---- registration ----

    async def registration_info(self) -> dict[str, Any]:
        try:
            resp = await self.http.get(self.api_base + "/registration", headers={"User-Agent": self.user_agent})
        except httpx.HTTPError as exc:
            raise network_error(exc) from exc
        return expect_json(resp)

    async def register_user(self, username: str, password: str, *, display_name: str | None = None) -> dict[str, Any]:
        body: dict[str, str] = {"username": username, "password": password}
        if display_name:
            body["display_name"] = display_name
        headers = {"Accept": "application/json", "User-Agent": self.user_agent}
        try:
            if self.token_endpoint_auth_method == "client_secret_basic":
                _, _, auth_headers = self._client_auth({})
                resp = await self.http.post(self.api_base + "/register", json=body, headers={**headers, **auth_headers})
            else:
                form, _, auth_headers = self._client_auth(body)
                resp = await self.http.post(self.api_base + "/register", data=form, headers={**headers, **auth_headers})
        except httpx.HTTPError as exc:
            raise network_error(exc) from exc
        return expect_json(resp)

    async def register_client(self, initial_access_token: str, metadata: Mapping[str, Any]) -> ClientRegistration:
        return await async_register_client(
            self.issuer, initial_access_token, metadata, http_client=self.http, user_agent=self.user_agent
        )

    # ---- client credentials / feed ----

    async def client_credentials(self, scope: str = "users:sync", *, force: bool = False) -> TokenSet:
        if not force:
            cached = self._cc_get(scope)
            if cached is not None:
                return cached
        async with self._acc_lock:
            if not force:
                cached = self._cc_get(scope)
                if cached is not None:
                    return cached
            tokens = await self._token_request({"grant_type": "client_credentials", "scope": scope})
            self._cc_tokens[scope] = tokens
            return tokens

    async def client_credentials_token(self, scope: str = "users:sync") -> str:
        return (await self.client_credentials(scope)).access_token

    async def _client_api(self, method: str, path: str, *, scope: str = "users:sync", **kwargs: Any) -> httpx.Response:
        url = path if path.startswith("http") else self.api_base + path
        token = (await self.client_credentials(scope)).access_token
        for attempt in (0, 1):
            headers = {"Authorization": f"Bearer {token}", "Accept": "application/json", "User-Agent": self.user_agent}
            try:
                resp = await self.http.request(method, url, headers=headers, **kwargs)
            except httpx.HTTPError as exc:
                raise network_error(exc) from exc
            if resp.status_code == 401 and attempt == 0:
                token = (await self.client_credentials(scope, force=True)).access_token
                continue
            return resp
        raise AssertionError("unreachable")  # pragma: no cover

    async def sync_changes(self, cursor: str | int | None = None, *, limit: int = 100) -> ChangesPage:
        params: dict[str, str] = {"limit": str(limit)}
        if cursor not in (None, ""):
            params["cursor"] = str(cursor)
        return self._changes_page(expect_json(await self._client_api("GET", "/users/changes", params=params)))

    async def list_users(self, cursor: str | None = None, *, limit: int = 200) -> UsersPage:
        params: dict[str, str] = {"limit": str(limit)}
        if cursor:
            params["cursor"] = cursor
        return self._users_page(expect_json(await self._client_api("GET", "/users", params=params)))

    async def full_sync(self, *, limit: int = 200) -> AsyncIterator[UsersPage]:
        cursor: str | None = None
        while True:
            page = await self.list_users(cursor, limit=limit)
            yield page
            if not page.has_more or not page.next_cursor:
                return
            cursor = page.next_cursor

    async def get_user(self, sub: str) -> dict[str, Any]:
        return expect_json(await self._client_api("GET", "/users/" + quote(sub, safe="")))

    async def iter_changes(self, cursor: str | int | None, *, limit: int = 100) -> AsyncIterator[SyncBatch]:
        """See :meth:`moon_sso.MoonSSO.iter_changes`."""
        resyncs = 0
        cur: str | None = None if cursor in (None, "") else str(cursor)
        while True:
            if cur is None:
                watermark: str | None = None
                async for page in self.full_sync(limit=max(limit, 1)):
                    if watermark is None:
                        watermark = page.watermark
                    yield SyncBatch(events=[], users=page.users, cursor=None if page.has_more else watermark,
                                    full_sync=True, has_more=True)
                cur = watermark or "0"
            try:
                while True:
                    page_c = await self.sync_changes(cur, limit=limit)
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

    # ---- sessions ----

    def session(
        self,
        tokens: TokenSet | None = None,
        *,
        store: TokenStore | AsyncTokenStore | None = None,
        on_session_expired: Callback | None = None,
        on_profile_changed: Callback | None = None,
        on_tokens_changed: Callback | None = None,
    ) -> "AsyncUserSession":
        return AsyncUserSession(
            self,
            tokens,
            store=store,
            on_session_expired=on_session_expired,
            on_profile_changed=on_profile_changed,
            on_tokens_changed=on_tokens_changed,
        )


class AsyncUserSession(_ProfileMixin):
    """asyncio twin of :class:`moon_sso.UserSession` (single-flight with ``asyncio.Lock``).

    Accepts a sync :class:`TokenStore` or an :class:`AsyncTokenStore`. When
    constructed with ``tokens`` and an async store, call :meth:`initialize`
    (or any token method, which awaits the pending save first).
    """

    def __init__(
        self,
        client: AsyncMoonSSO,
        tokens: TokenSet | None = None,
        *,
        store: TokenStore | AsyncTokenStore | None = None,
        on_session_expired: Callback | None = None,
        on_profile_changed: Callback | None = None,
        on_tokens_changed: Callback | None = None,
    ) -> None:
        self.client = client
        self.store: Any = store if store is not None else MemoryTokenStore()
        self._initial = tokens
        self.on_session_expired = on_session_expired
        self.on_profile_changed = on_profile_changed  # type: ignore[assignment]
        self.on_tokens_changed = on_tokens_changed
        self._lock = asyncio.Lock()
        self._profile = None
        self._etag = None
        self._sse_response: httpx.Response | None = None
        self._sse_stop = asyncio.Event()
        self.refresh_count = 0

    async def initialize(self) -> None:
        if self._initial is not None:
            tokens, self._initial = self._initial, None
            await _maybe(self.store.save(tokens))

    async def _load(self) -> TokenSet | None:
        await self.initialize()
        return await _maybe(self.store.load())

    async def tokens(self) -> TokenSet | None:
        return await self._load()

    async def _require(self) -> TokenSet:
        ts = await self._load()
        if ts is None:
            raise SessionExpired("not signed in", status=None)
        return ts

    async def get_access_token(self, *, force_refresh: bool = False, stale_token: str | None = None) -> str:
        ts = await self._require()
        if not force_refresh and not needs_refresh(ts, self.client.refresh_skew):
            return ts.access_token
        stale = stale_token if stale_token is not None else ts.access_token
        async with self._lock:
            ts = await self._require()
            if force_refresh:
                if ts.access_token != stale:
                    return ts.access_token
            elif not needs_refresh(ts, self.client.refresh_skew):
                return ts.access_token
            return (await self._refresh_locked(ts)).access_token

    async def refresh(self) -> TokenSet:
        await self.get_access_token(force_refresh=True)
        return await self._require()

    async def _refresh_locked(self, ts: TokenSet) -> TokenSet:
        if not ts.refresh_token:
            await self._expire(SessionExpired("no refresh token", status=None))
        try:
            assert ts.refresh_token is not None
            new = await self.client.refresh_tokens(ts.refresh_token, expected_sub=ts.sub)
        except SessionExpired as exc:
            await self._expire(exc)
        merged = self.client._merge_refreshed(ts, new)
        await _maybe(self.store.save(merged))
        self.refresh_count += 1
        await _acall(self.on_tokens_changed, merged)
        return merged

    async def _expire(self, exc: SessionExpired) -> NoReturn:
        try:
            await _maybe(self.store.clear())
        finally:
            await _acall(self.on_session_expired, exc)
        raise exc

    # ---- resource requests ----

    async def request(
        self,
        method: str,
        url: str,
        *,
        params: Mapping[str, str] | None = None,
        json: Any = None,
        content: bytes | None = None,
        headers: Mapping[str, str] | None = None,
        timeout: httpx.Timeout | float | None = None,
    ) -> httpx.Response:
        full = url if url.startswith(("http://", "https://")) else self.client.api_base + url
        token = await self.get_access_token()
        resp = await self._send(method, full, token, params, json, content, headers, timeout)
        if resp.status_code == 401:
            token = await self.get_access_token(force_refresh=True, stale_token=token)
            resp = await self._send(method, full, token, params, json, content, headers, timeout)
        return resp

    async def _send(
        self,
        method: str,
        url: str,
        token: str,
        params: Mapping[str, str] | None,
        json: Any,
        content: bytes | None,
        headers: Mapping[str, str] | None,
        timeout: httpx.Timeout | float | None,
    ) -> httpx.Response:
        h = {"Accept": "application/json", "User-Agent": self.client.user_agent}
        if headers:
            h.update(headers)
        h["Authorization"] = f"Bearer {token}"
        kwargs: dict[str, Any] = {"params": params, "headers": h}
        if json is not None:
            kwargs["json"] = json
        if content is not None:
            kwargs["content"] = content
        if timeout is not None:
            kwargs["timeout"] = timeout
        try:
            return await self.client.http.request(method, url, **kwargs)
        except httpx.HTTPError as exc:
            raise network_error(exc) from exc

    # ---- account API ----

    async def get_me(self, *, use_cache: bool = True) -> dict[str, Any]:
        headers = {"If-None-Match": self._etag} if use_cache and self._etag and self._profile is not None else None
        resp = await self.request("GET", "/me", headers=headers)
        if resp.status_code == 304 and self._profile is not None:
            return dict(self._profile)
        data = expect_json(resp)
        if self._set_profile(data, resp.headers.get("ETag")):
            await _acall(self.on_profile_changed, dict(data))
        return data

    async def _profile_result(self, resp: httpx.Response) -> dict[str, Any]:
        data = expect_json(resp)
        self._set_profile(data, resp.headers.get("ETag"))
        await _acall(self.on_profile_changed, dict(data))
        return data

    async def update_profile(
        self, *, username: str | None = None, display_name: str | None = None, if_match: bool | str = False
    ) -> dict[str, Any]:
        body: dict[str, str] = {}
        if username is not None:
            body["username"] = username
        if display_name is not None:
            body["display_name"] = display_name
        if not body:
            raise ValueError("nothing to update")
        headers: dict[str, str] = {}
        if if_match is True:
            if not self._etag:
                await self.get_me()
            if self._etag:
                headers["If-Match"] = self._etag
        elif isinstance(if_match, str) and if_match:
            headers["If-Match"] = if_match
        return await self._profile_result(await self.request("PATCH", "/me", json=body, headers=headers))

    async def upload_avatar(self, image: bytes | BinaryIO, content_type: str | None = None) -> dict[str, Any]:
        data = bytes(image if isinstance(image, (bytes, bytearray)) else image.read())
        if len(data) > 5 * 1024 * 1024:
            raise MoonSSOError("avatar_too_large", "avatar must not exceed 5 MB", 413)
        ctype = content_type or detect_image_type(data)
        if not ctype:
            raise ValueError("unknown image type; pass content_type")
        return await self._profile_result(await self.request("PUT", "/me/avatar", content=data, headers={"Content-Type": ctype}))

    async def delete_avatar(self) -> dict[str, Any]:
        return await self._profile_result(await self.request("DELETE", "/me/avatar"))

    async def change_password(
        self, current_password: str, new_password: str, *, keep_this_device: bool = True
    ) -> dict[str, Any]:
        body = {"current_password": current_password, "new_password": new_password, "keep_this_device": keep_this_device}
        return expect_json(await self.request("POST", "/me/password", json=body))

    async def userinfo(self) -> dict[str, Any]:
        meta = await self.client.metadata()
        return expect_json(await self.request("GET", meta.userinfo_endpoint or self.client.issuer + "/oauth/userinfo"))

    async def logout(self, *, post_logout_redirect_uri: str | None = None, state: str | None = None) -> str | None:
        ts = await self._load()
        await _maybe(self.store.clear())
        await self.stop_events()
        if ts is None:
            return None
        if ts.refresh_token:
            try:
                await self.client.revoke(ts.refresh_token, "refresh_token")
            except MoonSSOError as exc:
                log.info("refresh token revocation failed: %s", exc.error)
        try:
            return await self.client.end_session_url(
                ts.id_token, post_logout_redirect_uri=post_logout_redirect_uri, state=state
            )
        except MoonSSOError:
            return None

    # ---- live events ----

    async def stop_events(self) -> None:
        self._sse_stop.set()
        resp = self._sse_response
        if resp is not None:
            try:
                await resp.aclose()
            except Exception:  # pragma: no cover
                pass

    async def _safe_get_me(self) -> None:
        try:
            await self.get_me(use_cache=False)
        except SessionExpired:
            raise
        except MoonSSOError as exc:
            log.info("profile refetch failed: %s", exc.error)

    async def _handle_event(self, ev: SSEEvent) -> None:
        if ev.event == "user.updated":
            try:
                payload = ev.json()
            except ValueError:
                payload = {}
            data = payload.get("data") if isinstance(payload, dict) else None
            if isinstance(data, dict) and data:
                if self._merge_event(data) and self._profile is not None:
                    await _acall(self.on_profile_changed, dict(self._profile))
            else:
                await self._safe_get_me()
        elif ev.event in SESSION_EVENTS:
            await self.get_access_token(force_refresh=True)
            await self._safe_get_me()
        elif ev.event == "resync":
            await self._safe_get_me()

    async def events(
        self, *, last_event_id: str | None = None, reconnect: bool = True, stop: asyncio.Event | None = None
    ) -> AsyncIterator[SSEEvent]:
        """Async iterator of live profile events (see :meth:`moon_sso.UserSession.events`)."""
        self._sse_stop = stop or asyncio.Event()
        stop_ev = self._sse_stop
        policy = ReconnectPolicy()
        last_id = last_event_id
        retry_ms: int | None = None
        unauthorized = 0
        meta = await self.client.metadata()
        url = meta.events_endpoint or self.client.api_base + "/me/events"
        while not stop_ev.is_set():
            immediate = False
            try:
                token = await self.get_access_token()
                headers = {
                    "Authorization": f"Bearer {token}",
                    "Accept": "text/event-stream",
                    "Cache-Control": "no-cache",
                    "User-Agent": self.client.user_agent,
                }
                if last_id:
                    headers["Last-Event-ID"] = last_id
                async with self.client.http.stream("GET", url, headers=headers, timeout=SSE_TIMEOUT) as resp:
                    self._sse_response = resp
                    if resp.status_code == 401:
                        unauthorized += 1
                        if unauthorized > 2:
                            await resp.aread()
                            raise error_from_response(resp)
                        await self.get_access_token(force_refresh=True, stale_token=token)
                        continue
                    if resp.status_code != 200:
                        await resp.aread()
                        err = error_from_response(resp)
                        if not err.retryable:
                            raise err
                        raise _Reconnect(err)
                    unauthorized = 0
                    policy.success()
                    parser = SSEParser()
                    async for text in resp.aiter_text():
                        for ev in parser.feed(text):
                            if ev.id:
                                last_id = ev.id
                            if ev.event == "token_expired":
                                immediate = True
                                break
                            await self._handle_event(ev)
                            yield ev
                            if stop_ev.is_set():
                                return
                        if immediate:
                            break
                    if parser.retry is not None:
                        retry_ms = parser.retry
            except SessionExpired:
                raise
            except _Reconnect:
                policy.failure()
            except MoonSSOError as exc:
                if not exc.retryable:
                    raise
                policy.failure()
            except httpx.HTTPError:
                if stop_ev.is_set():
                    return
                policy.failure()
            finally:
                self._sse_response = None
            if stop_ev.is_set() or not reconnect:
                return
            if immediate:
                await self.get_access_token(force_refresh=True)
                continue
            try:
                await asyncio.wait_for(stop_ev.wait(), timeout=policy.delay(retry_ms))
            except asyncio.TimeoutError:
                pass


async def async_register_client(
    issuer: str,
    initial_access_token: str,
    metadata: Mapping[str, Any],
    *,
    http_client: httpx.AsyncClient | None = None,
    user_agent: str | None = None,
) -> ClientRegistration:
    """asyncio version of :func:`moon_sso.register_client`."""
    iss = normalize_issuer(issuer)
    own = http_client is None
    http = http_client or httpx.AsyncClient(timeout=DEFAULT_TIMEOUT, follow_redirects=False)
    try:
        try:
            disc = await AsyncDiscovery(iss, http).get()
            endpoint = disc.registration_endpoint or iss + "/oauth/register"
            resp = await http.post(
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
            await http.aclose()


async def async_unregister_client(
    registration: ClientRegistration,
    *,
    http_client: httpx.AsyncClient | None = None,
    user_agent: str | None = None,
) -> None:
    """asyncio version of :func:`moon_sso.unregister_client` (RFC 7592 delete)."""
    if not registration.registration_client_uri or not registration.registration_access_token:
        raise ValueError("registration lacks registration_client_uri or registration_access_token")
    own = http_client is None
    http = http_client or httpx.AsyncClient(timeout=DEFAULT_TIMEOUT, follow_redirects=False)
    try:
        try:
            resp = await http.delete(
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
            await http.aclose()

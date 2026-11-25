"""Synchronous per-login token manager and account API."""

from __future__ import annotations

import logging
import threading
from typing import TYPE_CHECKING, Any, BinaryIO, Callable, Iterator, Mapping, NoReturn

import httpx

from ._base import needs_refresh
from ._util import error_from_response, expect_json, network_error
from .errors import MoonSSOError, SessionExpired
from .models import TokenSet
from .sse import SESSION_EVENTS, ReconnectPolicy, SSEEvent, SSEParser
from .store import MemoryTokenStore, TokenStore

if TYPE_CHECKING:
    from .client import MoonSSO

__all__ = ["UserSession", "detect_image_type"]

log = logging.getLogger("moon_sso")

SSE_TIMEOUT = httpx.Timeout(connect=10.0, read=65.0, write=10.0, pool=10.0)
_PROFILE_KEYS = ("sub", "preferred_username", "name", "nickname", "picture", "updated_at", "profile_version")


def detect_image_type(data: bytes) -> str | None:
    """Content-Type from magic bytes for the formats the server accepts."""
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if data[:6] in (b"GIF87a", b"GIF89a"):
        return "image/gif"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    return None


def _call(cb: Callable[..., Any] | None, *args: Any) -> None:
    if cb is None:
        return
    try:
        cb(*args)
    except Exception:  # a broken callback must not break token handling
        log.exception("moon_sso callback %r failed", getattr(cb, "__name__", cb))


class _ProfileMixin:
    """Profile cache shared by the sync and async sessions."""

    _profile: dict[str, Any] | None
    _etag: str | None
    on_profile_changed: Callable[[dict[str, Any]], Any] | None

    @property
    def profile(self) -> dict[str, Any] | None:
        """Last known profile (from ``get_me``, account calls or SSE)."""
        return dict(self._profile) if self._profile is not None else None

    @property
    def profile_version(self) -> int | None:
        if self._profile is None:
            return None
        v = self._profile.get("profile_version")
        return int(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else None

    def _set_profile(self, profile: Mapping[str, Any], etag: str | None) -> bool:
        changed = self._profile != dict(profile)
        self._profile = dict(profile)
        if etag:
            self._etag = etag
        elif "profile_version" in profile:
            self._etag = f'"pv-{profile["profile_version"]}"'
        return changed

    def _merge_event(self, data: Mapping[str, Any]) -> bool:
        """Apply a ``user.updated`` payload; returns True when it was newer."""
        pv = data.get("profile_version")
        cur = self.profile_version
        if isinstance(pv, (int, float)) and cur is not None and pv <= cur:
            return False
        merged = dict(self._profile or {})
        for k in _PROFILE_KEYS:
            if k in data:
                merged[k] = data[k]
        if "picture" not in data and "picture" in merged and data.get("status") == "deleted":
            merged["picture"] = None
        self._set_profile(merged, None)
        return True


class UserSession(_ProfileMixin):
    """One user's login: automatic refresh, single-flight, account API and live events.

    * The access token is refreshed when less than 120 seconds remain.
    * Concurrent callers share one refresh (``threading.Lock``).
    * ``invalid_grant`` clears the store, calls ``on_session_expired`` and
      raises :class:`SessionExpired`; network errors, 429 and 5xx never log
      the user out.
    """

    def __init__(
        self,
        client: "MoonSSO",
        tokens: TokenSet | None = None,
        *,
        store: TokenStore | None = None,
        on_session_expired: Callable[[Exception], Any] | None = None,
        on_profile_changed: Callable[[dict[str, Any]], Any] | None = None,
        on_tokens_changed: Callable[[TokenSet], Any] | None = None,
    ) -> None:
        self.client = client
        self.store: TokenStore = store if store is not None else MemoryTokenStore()
        if tokens is not None:
            self.store.save(tokens)
        self.on_session_expired = on_session_expired
        self.on_profile_changed = on_profile_changed
        self.on_tokens_changed = on_tokens_changed
        self._lock = threading.Lock()
        self._profile = None
        self._etag = None
        self._sse_response: httpx.Response | None = None
        self._sse_stop = threading.Event()
        self.refresh_count = 0

    # ---- tokens ----

    @property
    def tokens(self) -> TokenSet | None:
        return self.store.load()

    @property
    def is_authenticated(self) -> bool:
        return self.store.load() is not None

    def _require(self) -> TokenSet:
        ts = self.store.load()
        if ts is None:
            raise SessionExpired("not signed in", status=None)
        return ts

    def get_access_token(self, *, force_refresh: bool = False, stale_token: str | None = None) -> str:
        """A valid access token, refreshing first when needed.

        With ``force_refresh`` the token is refreshed unless another caller
        already replaced ``stale_token`` (default: the token current at call
        time) — so a burst of 401s results in one refresh.
        """
        ts = self._require()
        if not force_refresh and not needs_refresh(ts, self.client.refresh_skew):
            return ts.access_token
        stale = stale_token if stale_token is not None else ts.access_token
        with self._lock:
            ts = self._require()
            if force_refresh:
                if ts.access_token != stale:
                    return ts.access_token
            elif not needs_refresh(ts, self.client.refresh_skew):
                return ts.access_token
            return self._refresh_locked(ts).access_token

    def refresh(self) -> TokenSet:
        """Force a refresh now (single-flight)."""
        self.get_access_token(force_refresh=True)
        return self._require()

    def _refresh_locked(self, ts: TokenSet) -> TokenSet:
        if not ts.refresh_token:
            self._expire(SessionExpired("no refresh token", status=None))
        try:
            assert ts.refresh_token is not None
            new = self.client.refresh_tokens(ts.refresh_token, expected_sub=ts.sub)
        except SessionExpired as exc:
            self._expire(exc)
        merged = self.client._merge_refreshed(ts, new)
        self.store.save(merged)
        self.refresh_count += 1
        _call(self.on_tokens_changed, merged)
        return merged

    def _expire(self, exc: SessionExpired) -> NoReturn:
        try:
            self.store.clear()
        finally:
            _call(self.on_session_expired, exc)
        raise exc

    # ---- resource requests ----

    def request(
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
        """Authenticated request. A 401 forces one refresh and one replay."""
        full = url if url.startswith(("http://", "https://")) else self.client.api_base + url
        token = self.get_access_token()
        resp = self._send(method, full, token, params, json, content, headers, timeout)
        if resp.status_code == 401:
            token = self.get_access_token(force_refresh=True, stale_token=token)
            resp = self._send(method, full, token, params, json, content, headers, timeout)
        return resp

    def _send(
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
            return self.client.http.request(method, url, **kwargs)
        except httpx.HTTPError as exc:
            raise network_error(exc) from exc

    # ---- account API ----

    def get_me(self, *, use_cache: bool = True) -> dict[str, Any]:
        """``GET /api/v1/me`` (conditional with the cached ETag)."""
        headers = {"If-None-Match": self._etag} if use_cache and self._etag and self._profile is not None else None
        resp = self.request("GET", "/me", headers=headers)
        if resp.status_code == 304 and self._profile is not None:
            return dict(self._profile)
        data = expect_json(resp)
        if self._set_profile(data, resp.headers.get("ETag")):
            _call(self.on_profile_changed, dict(data))
        return data

    def _profile_result(self, resp: httpx.Response) -> dict[str, Any]:
        data = expect_json(resp)
        self._set_profile(data, resp.headers.get("ETag"))
        _call(self.on_profile_changed, dict(data))
        return data

    def update_profile(
        self,
        *,
        username: str | None = None,
        display_name: str | None = None,
        if_match: bool | str = False,
    ) -> dict[str, Any]:
        """``PATCH /api/v1/me``. ``if_match=True`` sends the cached ETag (412 on conflict)."""
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
                self.get_me()
            if self._etag:
                headers["If-Match"] = self._etag
        elif isinstance(if_match, str) and if_match:
            headers["If-Match"] = if_match
        return self._profile_result(self.request("PATCH", "/me", json=body, headers=headers))

    def upload_avatar(self, image: bytes | BinaryIO, content_type: str | None = None) -> dict[str, Any]:
        """``PUT /api/v1/me/avatar`` with the raw image (PNG, JPEG, GIF or WebP; ≤ 5 MB)."""
        data = image if isinstance(image, (bytes, bytearray)) else image.read()
        data = bytes(data)
        if len(data) > 5 * 1024 * 1024:
            raise MoonSSOError("avatar_too_large", "avatar must not exceed 5 MB", 413)
        ctype = content_type or detect_image_type(data)
        if not ctype:
            raise ValueError("unknown image type; pass content_type")
        return self._profile_result(self.request("PUT", "/me/avatar", content=data, headers={"Content-Type": ctype}))

    def delete_avatar(self) -> dict[str, Any]:
        """``DELETE /api/v1/me/avatar``."""
        return self._profile_result(self.request("DELETE", "/me/avatar"))

    def change_password(self, current_password: str, new_password: str, *, keep_this_device: bool = True) -> dict[str, Any]:
        """``POST /api/v1/me/password``; other devices are signed out."""
        body = {"current_password": current_password, "new_password": new_password, "keep_this_device": keep_this_device}
        return expect_json(self.request("POST", "/me/password", json=body))

    def userinfo(self) -> dict[str, Any]:
        """OIDC userinfo endpoint."""
        meta = self.client.metadata()
        url = meta.userinfo_endpoint or self.client.issuer + "/oauth/userinfo"
        return expect_json(self.request("GET", url))

    # ---- logout ----

    def logout(self, *, post_logout_redirect_uri: str | None = None, state: str | None = None) -> str | None:
        """Clear local tokens, revoke the refresh token (best effort) and return the end-session URL."""
        ts = self.store.load()
        self.store.clear()
        self.stop_events()
        if ts is None:
            return None
        if ts.refresh_token:
            try:
                self.client.revoke(ts.refresh_token, "refresh_token")
            except MoonSSOError as exc:
                log.info("refresh token revocation failed: %s", exc.error)
        try:
            return self.client.end_session_url(ts.id_token, post_logout_redirect_uri=post_logout_redirect_uri, state=state)
        except MoonSSOError:
            return None

    # ---- live events (SSE) ----

    def stop_events(self) -> None:
        """Ask a running :meth:`events` loop (possibly on another thread) to finish."""
        self._sse_stop.set()
        resp = self._sse_response
        if resp is not None:
            try:
                resp.close()
            except Exception:  # pragma: no cover - closing an already broken stream
                pass

    def _events_url(self) -> str:
        meta = self.client.metadata()
        return meta.events_endpoint or self.client.api_base + "/me/events"

    def _handle_event(self, ev: SSEEvent) -> None:
        if ev.event == "user.updated":
            try:
                payload = ev.json()
            except ValueError:
                payload = {}
            data = payload.get("data") if isinstance(payload, dict) else None
            if isinstance(data, dict) and data:
                if self._merge_event(data) and self._profile is not None:
                    _call(self.on_profile_changed, dict(self._profile))
            else:
                self._safe_get_me()
        elif ev.event in SESSION_EVENTS:
            # Raises SessionExpired (after clearing the store) when the login is gone.
            self.get_access_token(force_refresh=True)
            self._safe_get_me()
        elif ev.event == "resync":
            self._safe_get_me()

    def _safe_get_me(self) -> None:
        try:
            self.get_me(use_cache=False)
        except SessionExpired:
            raise
        except MoonSSOError as exc:
            log.info("profile refetch failed: %s", exc.error)

    def events(
        self,
        *,
        last_event_id: str | None = None,
        reconnect: bool = True,
        stop: threading.Event | None = None,
    ) -> Iterator[SSEEvent]:
        """Iterate live profile events from ``/api/v1/me/events``.

        Reconnects with ``Last-Event-ID`` after ``retry:`` ms (3–8 s by
        default) plus jitter, refreshing the token first when needed.
        Raises :class:`SessionExpired` when the login ended. Stop with
        :meth:`stop_events`, the ``stop`` event, or by closing the generator.
        """
        self._sse_stop = stop or threading.Event()
        stop_ev = self._sse_stop
        policy = ReconnectPolicy()
        last_id = last_event_id
        retry_ms: int | None = None
        unauthorized = 0
        url = self._events_url()
        while not stop_ev.is_set():
            immediate = False
            try:
                token = self.get_access_token()
                headers = {
                    "Authorization": f"Bearer {token}",
                    "Accept": "text/event-stream",
                    "Cache-Control": "no-cache",
                    "User-Agent": self.client.user_agent,
                }
                if last_id:
                    headers["Last-Event-ID"] = last_id
                with self.client.http.stream("GET", url, headers=headers, timeout=SSE_TIMEOUT) as resp:
                    self._sse_response = resp
                    if resp.status_code == 401:
                        unauthorized += 1
                        if unauthorized > 2:
                            resp.read()
                            raise error_from_response(resp)
                        self.get_access_token(force_refresh=True, stale_token=token)
                        immediate = True
                        continue
                    if resp.status_code != 200:
                        resp.read()
                        err = error_from_response(resp)
                        if not err.retryable:
                            raise err
                        raise _Reconnect(err)
                    unauthorized = 0
                    policy.success()
                    parser = SSEParser()
                    for text in resp.iter_text():
                        for ev in parser.feed(text):
                            if ev.id:
                                last_id = ev.id
                            if ev.event == "token_expired":
                                immediate = True
                                break
                            self._handle_event(ev)
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
                # token_expired: reconnect at once with a fresh token.
                self.get_access_token(force_refresh=True)
                continue
            stop_ev.wait(policy.delay(retry_ms))


class _Reconnect(Exception):
    def __init__(self, cause: MoonSSOError) -> None:
        super().__init__(str(cause))
        self.cause = cause

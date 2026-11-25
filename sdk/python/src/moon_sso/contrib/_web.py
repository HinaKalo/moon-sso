"""Framework-neutral pieces of the web adapters.

Web adapters keep tokens in a **server-side** session store keyed by an
opaque random cookie, never in the cookie itself, so refresh tokens do not
leave the server.
"""

from __future__ import annotations

import secrets
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Generic, Mapping, Protocol, TypeVar, runtime_checkable
from urllib.parse import urlsplit

from ..models import AuthorizationRequest, TokenSet

__all__ = [
    "MemorySessionStore",
    "SessionStore",
    "WebUser",
    "is_htmx",
    "new_session_id",
    "safe_return_to",
]

SESSION_TOKENS = "tokens"
SESSION_AUTH_REQUEST = "auth_request"


def new_session_id() -> str:
    return secrets.token_urlsafe(32)


def is_htmx(headers: Mapping[str, Any]) -> bool:
    """True for HTMX requests (``HX-Request: true``)."""
    for k, v in headers.items():
        if isinstance(k, str) and k.lower() == "hx-request":
            return str(v).lower() == "true"
    getter = getattr(headers, "get", None)
    if getter is not None:
        v = getter("HX-Request")
        return v is not None and str(v).lower() == "true"
    return False


def wants_html(accept: str | None) -> bool:
    """Browsers navigating pages send ``text/html``; API clients usually do not."""
    if not accept:
        return False
    return "text/html" in accept or "application/xhtml+xml" in accept


def safe_return_to(target: str | None, default: str = "/") -> str:
    """Allow only same-site relative paths (prevents open redirects)."""
    if not target:
        return default
    t = target.strip()
    if not t.startswith("/") or t.startswith("//") or t.startswith("/\\") or "\r" in t or "\n" in t:
        return default
    parts = urlsplit(t)
    if parts.scheme or parts.netloc:
        return default
    return t


@runtime_checkable
class SessionStore(Protocol):
    """Server-side storage for web sessions.

    ``delete_matching`` must remove every session whose stored ``sso_sid``
    equals ``sid`` (when given) or whose ``sub`` equals ``sub`` (when only
    ``sub`` is given); it powers back-channel logout.
    """

    def get(self, session_id: str) -> dict[str, Any] | None: ...

    def set(self, session_id: str, data: dict[str, Any]) -> None: ...

    def delete(self, session_id: str) -> None: ...

    def delete_matching(self, *, sub: str | None = None, sid: str | None = None) -> int: ...


class MemorySessionStore:
    """Thread-safe in-process session store with idle expiry and a size bound.

    Suitable for a single process. Use a shared store (Redis, database) for
    several workers by implementing :class:`SessionStore`.
    """

    def __init__(self, ttl: float = 14 * 24 * 3600, max_sessions: int = 100_000) -> None:
        self.ttl = ttl
        self.max_sessions = max_sessions
        self._data: OrderedDict[str, tuple[float, dict[str, Any]]] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, session_id: str) -> dict[str, Any] | None:
        now = time.monotonic()
        with self._lock:
            item = self._data.get(session_id)
            if item is None:
                return None
            exp, data = item
            if exp <= now:
                del self._data[session_id]
                return None
            self._data[session_id] = (now + self.ttl, data)
            self._data.move_to_end(session_id)
            return dict(data)

    def set(self, session_id: str, data: dict[str, Any]) -> None:
        with self._lock:
            self._data[session_id] = (time.monotonic() + self.ttl, dict(data))
            self._data.move_to_end(session_id)
            while len(self._data) > self.max_sessions:
                self._data.popitem(last=False)

    def delete(self, session_id: str) -> None:
        with self._lock:
            self._data.pop(session_id, None)

    def delete_matching(self, *, sub: str | None = None, sid: str | None = None) -> int:
        with self._lock:
            victims = []
            for key, (_, data) in self._data.items():
                if sid is not None:
                    if data.get("sso_sid") == sid:
                        victims.append(key)
                elif sub is not None and data.get("sub") == sub:
                    victims.append(key)
            for key in victims:
                del self._data[key]
            return len(victims)


class StoreTokenAdapter:
    """Exposes the ``tokens`` entry of one web session as a :class:`~moon_sso.TokenStore`."""

    def __init__(self, store: SessionStore, session_id: str) -> None:
        self._store = store
        self._sid = session_id

    def load(self) -> TokenSet | None:
        data = self._store.get(self._sid)
        if not data or not data.get(SESSION_TOKENS):
            return None
        try:
            return TokenSet.from_dict(data[SESSION_TOKENS])
        except (KeyError, TypeError, ValueError):
            return None

    def save(self, tokens: TokenSet) -> None:
        data = self._store.get(self._sid) or {}
        data[SESSION_TOKENS] = tokens.to_dict()
        claims = tokens.id_claims or {}
        if claims.get("sub"):
            data["sub"] = claims["sub"]
        if claims.get("sid"):
            data["sso_sid"] = claims["sid"]
        self._store.set(self._sid, data)

    def clear(self) -> None:
        data = self._store.get(self._sid)
        if data is None:
            return
        data.pop(SESSION_TOKENS, None)
        self._store.set(self._sid, data)


S = TypeVar("S")


@dataclass
class WebUser(Generic[S]):
    """The signed-in user of a web request."""

    sub: str
    claims: dict[str, Any]
    session: S
    profile: dict[str, Any] | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def username(self) -> str | None:
        v = (self.profile or self.claims).get("preferred_username")
        return v if isinstance(v, str) else None

    @property
    def name(self) -> str | None:
        v = (self.profile or self.claims).get("name")
        return v if isinstance(v, str) else None


def auth_request_from(data: Mapping[str, Any] | None) -> AuthorizationRequest | None:
    if not data or not data.get(SESSION_AUTH_REQUEST):
        return None
    try:
        return AuthorizationRequest.from_dict(data[SESSION_AUTH_REQUEST])
    except (KeyError, TypeError, ValueError):
        return None


class LRU(Generic[S]):
    """Small thread-safe LRU used to share session objects (and their refresh locks) across requests."""

    def __init__(self, size: int = 10_000) -> None:
        self.size = size
        self._d: OrderedDict[str, S] = OrderedDict()
        self._lock = threading.Lock()

    def get_or_create(self, key: str, factory: Any) -> S:
        with self._lock:
            v = self._d.get(key)
            if v is None:
                v = factory()
                self._d[key] = v
                while len(self._d) > self.size:
                    self._d.popitem(last=False)
            else:
                self._d.move_to_end(key)
            return v

    def pop(self, key: str) -> None:
        with self._lock:
            self._d.pop(key, None)

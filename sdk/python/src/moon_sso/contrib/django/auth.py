"""Per-request login state on top of ``request.session``.

Tokens live in the (server-side) Django session and are mirrored in the
cache so concurrent requests of one browser always see the newest rotated
refresh token, whichever request saves the session last.
"""

from __future__ import annotations

import threading
from importlib import import_module
from typing import Any

from django.conf import settings
from django.core.cache import caches
from django.http import HttpRequest

from ...errors import SessionExpired
from ...models import TokenSet
from ...session import UserSession
from .._web import LRU, WebUser
from .conf import get_client, get_setting

__all__ = ["DjangoSessionTokenStore", "end_sessions", "get_user", "index_session", "user_session"]

K_TOKENS = "moon_sso.tokens"
K_AUTH_REQUEST = "moon_sso.auth_request"
K_SUB = "moon_sso.sub"
K_SID = "moon_sso.sid"

_locks: LRU[Any] = LRU(20_000)


def _cache() -> Any:
    return caches[get_setting("CACHE_ALIAS")]


def _ensure_key(request: HttpRequest) -> str:
    if not request.session.session_key:
        request.session.save()
    return str(request.session.session_key)


class DjangoSessionTokenStore:
    """:class:`~moon_sso.TokenStore` over ``request.session`` plus a cache mirror."""

    def __init__(self, request: HttpRequest) -> None:
        self.request = request

    def _cache_key(self) -> str | None:
        key = self.request.session.session_key
        return f"moon_sso:tokens:{key}" if key else None

    def load(self) -> TokenSet | None:
        candidates: list[TokenSet] = []
        raw = self.request.session.get(K_TOKENS)
        if raw:
            try:
                candidates.append(TokenSet.from_dict(raw))
            except (KeyError, TypeError, ValueError):
                pass
        ck = self._cache_key()
        if ck and raw:
            cached = _cache().get(ck)
            if cached:
                try:
                    candidates.append(TokenSet.from_dict(cached))
                except (KeyError, TypeError, ValueError):
                    pass
        if not candidates:
            return None
        return max(candidates, key=lambda t: t.issued_at)

    def save(self, tokens: TokenSet) -> None:
        data = tokens.to_dict()
        self.request.session[K_TOKENS] = data
        claims = tokens.id_claims or {}
        if claims.get("sub"):
            self.request.session[K_SUB] = claims["sub"]
        if claims.get("sid"):
            self.request.session[K_SID] = claims["sid"]
        key = _ensure_key(self.request)
        _cache().set(f"moon_sso:tokens:{key}", data, get_setting("SESSION_INDEX_TTL"))

    def clear(self) -> None:
        ck = self._cache_key()
        for k in (K_TOKENS, K_SUB, K_SID):
            self.request.session.pop(k, None)
        if ck:
            _cache().delete(ck)


def user_session(request: HttpRequest) -> UserSession:
    """Token manager for this request's login (refreshes are single-flight per browser session)."""
    us = get_client().session(store=DjangoSessionTokenStore(request))
    key = request.session.session_key
    if key:
        us._lock = _locks.get_or_create(key, threading.Lock)
    return us


def get_user(request: HttpRequest) -> WebUser[UserSession] | None:
    if not request.session.get(K_TOKENS):
        return None
    us = user_session(request)
    try:
        us.get_access_token()
    except SessionExpired:
        return None
    tokens = us.tokens
    if tokens is None:
        return None
    claims = dict(tokens.id_claims or {})
    sub = str(claims.get("sub") or request.session.get(K_SUB) or "")
    if not sub:
        return None
    return WebUser(sub=sub, claims=claims, session=us, profile=us.profile)


def index_session(request: HttpRequest, tokens: TokenSet) -> None:
    """Remember which Django session belongs to which SSO ``sid`` / ``sub`` (for back-channel logout)."""
    key = _ensure_key(request)
    ttl = get_setting("SESSION_INDEX_TTL")
    cache = _cache()
    claims = tokens.id_claims or {}
    for kind in ("sid", "sub"):
        value = claims.get(kind)
        if not value:
            continue
        ck = f"moon_sso:bcl:{kind}:{value}"
        keys = set(cache.get(ck) or ())
        keys.add(key)
        cache.set(ck, sorted(keys), ttl)


def end_sessions(sub: str | None, sid: str | None) -> int:
    """Delete the Django sessions of an SSO session (``sid``) or, without ``sid``, of a user."""
    cache = _cache()
    kind, value = ("sid", sid) if sid else ("sub", sub)
    if not value:
        return 0
    ck = f"moon_sso:bcl:{kind}:{value}"
    keys = list(cache.get(ck) or ())
    engine = import_module(settings.SESSION_ENGINE)
    for key in keys:
        engine.SessionStore(session_key=key).delete()
        cache.delete(f"moon_sso:tokens:{key}")
    cache.delete(ck)
    return len(keys)

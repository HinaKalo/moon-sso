"""``settings.MOON_SSO`` handling and the shared client instance."""

from __future__ import annotations

import threading
from typing import Any, Callable

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.core.signals import setting_changed
from django.utils.module_loading import import_string

from ...client import MoonSSO

__all__ = ["get_client", "get_setting", "reset_client"]

DEFAULTS: dict[str, Any] = {
    "ISSUER": None,
    "CLIENT_ID": None,
    "CLIENT_SECRET": None,
    "REDIRECT_URI": None,
    "SCOPE": "openid profile offline_access",
    "AUDIENCE": None,
    "AFTER_LOGIN": "/",
    "AFTER_LOGOUT": "/",
    "POST_LOGOUT_REDIRECT_URI": None,
    "LOGIN_URL": None,  # default: reverse("moon_sso:login")
    "WEBHOOK_SECRET": None,
    "WEBHOOK_HANDLER": None,  # callable(event) or dotted path
    "LOGOUT_HANDLER": None,  # callable(sub, sid) or dotted path
    "LOGIN_HANDLER": None,  # callable(request, tokens) or dotted path
    "CACHE_ALIAS": "default",
    "SESSION_INDEX_TTL": 14 * 24 * 3600,
}

_lock = threading.Lock()
_client: MoonSSO | None = None


def get_setting(name: str) -> Any:
    conf = getattr(settings, "MOON_SSO", None)
    if conf is None:
        raise ImproperlyConfigured("settings.MOON_SSO is not defined")
    if name not in DEFAULTS:
        raise KeyError(name)
    return conf.get(name, DEFAULTS[name])


def get_handler(name: str) -> Callable[..., Any] | None:
    value = get_setting(name)
    if value is None:
        return None
    if isinstance(value, str):
        return import_string(value)  # type: ignore[no-any-return]
    if callable(value):
        return value  # type: ignore[no-any-return]
    raise ImproperlyConfigured(f"MOON_SSO[{name!r}] must be a callable or a dotted path")


def get_client() -> MoonSSO:
    """The process-wide :class:`MoonSSO` built from ``settings.MOON_SSO``."""
    global _client
    c = _client
    if c is not None:
        return c
    with _lock:
        if _client is None:
            issuer = get_setting("ISSUER")
            client_id = get_setting("CLIENT_ID")
            if not issuer or not client_id:
                raise ImproperlyConfigured("MOON_SSO needs ISSUER and CLIENT_ID")
            _client = MoonSSO(
                issuer,
                client_id,
                get_setting("CLIENT_SECRET"),
                redirect_uri=get_setting("REDIRECT_URI"),
                scope=get_setting("SCOPE"),
                audience=get_setting("AUDIENCE"),
            )
        return _client


def reset_client() -> None:
    global _client
    with _lock:
        if _client is not None:
            _client.close()
        _client = None


def _on_setting_changed(*, setting: str, **kwargs: Any) -> None:
    if setting == "MOON_SSO":
        reset_client()


setting_changed.connect(_on_setting_changed)

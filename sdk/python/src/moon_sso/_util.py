"""Internal helpers: HTTP error mapping, replay caches, misc."""

from __future__ import annotations

import json
import threading
import time
from typing import Any, Mapping

import httpx

from ._version import __version__
from .errors import CursorExpired, MoonSSOError, PasswordChangeRequired

USER_AGENT = f"moon-sso-sdk-python/{__version__}"

#: Token-endpoint statuses that are retried once with identical parameters.
RETRY_STATUSES = frozenset({502, 503, 504})

DEFAULT_TIMEOUT = httpx.Timeout(10.0, connect=5.0)


def network_error(exc: BaseException) -> MoonSSOError:
    kind = type(exc).__name__
    return MoonSSOError("network", f"{kind}: {exc}" if str(exc) else kind)


def json_body(resp: httpx.Response) -> dict[str, Any]:
    """Parse a JSON object body, or return ``{}`` when the body is not one."""
    try:
        data = resp.json()
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def error_from_response(resp: httpx.Response) -> MoonSSOError:
    """Map a non-2xx response to the SDK error model."""
    body = json_body(resp)
    code = body.get("error")
    desc = body.get("error_description")
    if not isinstance(code, str) or not code:
        code = "invalid_response" if 200 <= resp.status_code < 300 else _status_code_name(resp.status_code)
        if desc is None:
            text = resp.text[:200] if resp.content else ""
            desc = text or None
    if code == "password_change_required":
        return PasswordChangeRequired(body.get("change_url"), desc, body=body)
    if resp.status_code == 410:
        return CursorExpired(desc, body=body)
    field = body.get("field")
    return MoonSSOError(code, desc if isinstance(desc, str) else None, resp.status_code, field if isinstance(field, str) else None, body)


def _status_code_name(status: int) -> str:
    return {
        400: "invalid_request",
        401: "invalid_token",
        403: "access_denied",
        404: "not_found",
        409: "conflict",
        410: "cursor_expired",
        412: "version_conflict",
        413: "payload_too_large",
        415: "unsupported_media_type",
        422: "validation_failed",
        429: "rate_limited",
        500: "server_error",
        502: "bad_gateway",
        503: "temporarily_unavailable",
        504: "gateway_timeout",
    }.get(status, "http_error")


def expect_json(resp: httpx.Response) -> dict[str, Any]:
    """Return the JSON object of a 2xx response or raise the mapped error."""
    if not 200 <= resp.status_code < 300:
        raise error_from_response(resp)
    try:
        data = resp.json()
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise MoonSSOError("invalid_response", "response is not JSON", resp.status_code) from exc
    if not isinstance(data, dict):
        raise MoonSSOError("invalid_response", "response is not a JSON object", resp.status_code)
    return data


def header_get(headers: Mapping[str, Any], name: str) -> str | None:
    """Case-insensitive header lookup over any mapping."""
    if isinstance(headers, httpx.Headers):
        return headers.get(name)
    lname = name.lower()
    for k, v in headers.items():
        if isinstance(k, str) and k.lower() == lname:
            if isinstance(v, (list, tuple)):
                return str(v[0]) if v else None
            return v if isinstance(v, str) else str(v)
    getter = getattr(headers, "get", None)
    if getter is not None:  # e.g. werkzeug/django headers with their own case folding
        try:
            v = getter(name)
        except Exception:  # pragma: no cover - exotic mapping types
            v = None
        if v is not None:
            return str(v)
    return None


class ReplayCache:
    """Thread-safe set of recently seen identifiers with a fixed lifetime.

    ``add(key)`` returns ``False`` when ``key`` was already seen within the
    window. Memory is bounded by ``max_entries`` (oldest entries evicted).
    """

    def __init__(self, ttl: float = 300.0, max_entries: int = 100_000) -> None:
        self.ttl = ttl
        self.max_entries = max_entries
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()

    def add(self, key: str, *, ttl: float | None = None) -> bool:
        now = time.monotonic()
        expires = now + (self.ttl if ttl is None else ttl)
        with self._lock:
            exp = self._seen.get(key)
            if exp is not None and exp > now:
                return False
            self._seen[key] = expires
            if len(self._seen) > self.max_entries:
                self._evict(now)
            return True

    def __contains__(self, key: object) -> bool:
        with self._lock:
            exp = self._seen.get(key) if isinstance(key, str) else None
            return exp is not None and exp > time.monotonic()

    def _evict(self, now: float) -> None:
        for k in [k for k, e in self._seen.items() if e <= now]:
            del self._seen[k]
        while len(self._seen) > self.max_entries:
            del self._seen[next(iter(self._seen))]

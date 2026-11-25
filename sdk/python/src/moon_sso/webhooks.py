"""Standard Webhooks signature verification for Moon SSO events."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from typing import Any, Mapping

from ._util import ReplayCache, header_get
from .errors import WebhookVerificationError

__all__ = ["WebhookEvent", "WebhookVerifier", "sign_webhook"]

DEFAULT_TOLERANCE = 300  # seconds


def _decode_secret(secret: str | bytes) -> bytes:
    if isinstance(secret, bytes):
        return secret
    s = secret.strip()
    if s.startswith("whsec_"):
        s = s[len("whsec_") :]
    try:
        return base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("webhook secret must be 'whsec_' followed by base64") from exc


def sign_webhook(secret: str | bytes, msg_id: str, timestamp: int, body: bytes | str) -> str:
    """Compute the ``v1,<base64>`` signature (useful for tests and replays)."""
    key = _decode_secret(secret)
    payload = body.encode("utf-8") if isinstance(body, str) else body
    mac = hmac.new(key, f"{msg_id}.{timestamp}.".encode("utf-8") + payload, hashlib.sha256).digest()
    return "v1," + base64.b64encode(mac).decode("ascii")


@dataclass(frozen=True)
class WebhookEvent:
    """A verified webhook delivery."""

    webhook_id: str
    timestamp: int
    id: str
    type: str
    seq: int | None
    occurred_at: str | None
    data: dict[str, Any]
    duplicate: bool = False
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False)

    @property
    def sub(self) -> str | None:
        v = self.data.get("sub")
        return v if isinstance(v, str) else None

    @property
    def profile_version(self) -> int | None:
        v = self.data.get("profile_version")
        return int(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else None

    def is_stale(self, known_profile_version: int | None) -> bool:
        """True when the receiver already holds this or a newer profile version."""
        pv = self.profile_version
        return known_profile_version is not None and pv is not None and pv <= known_profile_version


class WebhookVerifier:
    """Verifies ``webhook-id`` / ``webhook-timestamp`` / ``webhook-signature``.

    >>> v = WebhookVerifier("whsec_...")
    >>> event = v.verify(request_body_bytes, request_headers)

    The body must be the exact raw bytes received. Any of the space-separated
    ``v1,`` signatures may match; comparison is constant time. Timestamps more
    than ``tolerance`` seconds away from now are rejected. With
    ``dedupe=True`` (default) repeated ``webhook-id`` values are reported
    through :attr:`WebhookEvent.duplicate` instead of being processed twice.
    """

    def __init__(self, secret: str | bytes, *, tolerance: int = DEFAULT_TOLERANCE, dedupe: bool = True) -> None:
        self._key = _decode_secret(secret)
        if len(self._key) < 16:
            raise ValueError("webhook secret is too short")
        self.tolerance = tolerance
        self._seen = ReplayCache(ttl=max(tolerance * 2, 600)) if dedupe else None

    def verify_signature(self, body: bytes | str, headers: Mapping[str, Any], *, now: float | None = None) -> tuple[str, int]:
        """Check headers and signature only; returns ``(webhook_id, timestamp)``."""
        msg_id = header_get(headers, "webhook-id")
        ts_raw = header_get(headers, "webhook-timestamp")
        sig_header = header_get(headers, "webhook-signature")
        if not msg_id or not ts_raw or not sig_header:
            raise WebhookVerificationError("missing webhook-id, webhook-timestamp or webhook-signature header")
        try:
            ts = int(ts_raw.strip())
        except ValueError as exc:
            raise WebhookVerificationError("invalid webhook-timestamp") from exc
        current = time.time() if now is None else now
        if abs(current - ts) > self.tolerance:
            raise WebhookVerificationError("webhook timestamp outside the tolerance window")
        payload = body.encode("utf-8") if isinstance(body, str) else bytes(body)
        expected = hmac.new(self._key, f"{msg_id}.{ts}.".encode("utf-8") + payload, hashlib.sha256).digest()
        for candidate in sig_header.split():
            version, _, value = candidate.partition(",")
            if version != "v1" or not value:
                continue
            try:
                got = base64.b64decode(value, validate=True)
            except (binascii.Error, ValueError):
                continue
            if hmac.compare_digest(got, expected):
                return msg_id, ts
        raise WebhookVerificationError("no matching webhook signature")

    def verify(self, body: bytes | str, headers: Mapping[str, Any], *, now: float | None = None) -> WebhookEvent:
        """Verify and parse a delivery. Raises :class:`WebhookVerificationError`."""
        msg_id, ts = self.verify_signature(body, headers, now=now)
        try:
            data = json.loads(body)
        except (ValueError, UnicodeDecodeError) as exc:
            raise WebhookVerificationError("webhook body is not JSON") from exc
        if not isinstance(data, dict):
            raise WebhookVerificationError("webhook body is not a JSON object")
        duplicate = False
        if self._seen is not None:
            duplicate = not self._seen.add(msg_id)
        seq = data.get("seq")
        ev_data = data.get("data")
        return WebhookEvent(
            webhook_id=msg_id,
            timestamp=ts,
            id=str(data.get("id") or msg_id),
            type=str(data.get("type") or ""),
            seq=int(seq) if isinstance(seq, (int, float)) and not isinstance(seq, bool) else None,
            occurred_at=data.get("occurred_at") if isinstance(data.get("occurred_at"), str) else None,
            data=dict(ev_data) if isinstance(ev_data, dict) else {},
            duplicate=duplicate,
            raw=data,
        )

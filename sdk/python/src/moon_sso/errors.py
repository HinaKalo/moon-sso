"""Exception hierarchy shared by every part of the SDK.

All server and transport failures surface as :class:`MoonSSOError` (or a
subclass) carrying the fields required by the SDK contract: ``error``,
``error_description``, ``status`` and, for 422 validation errors, ``field``.
"""

from __future__ import annotations

from typing import Any, Mapping

__all__ = [
    "MoonSSOError",
    "SessionExpired",
    "OtpRequired",
    "PasswordChangeRequired",
    "InsufficientScope",
    "CursorExpired",
    "TokenValidationError",
    "WebhookVerificationError",
    "LogoutTokenError",
    "AuthorizationResponseError",
]


class MoonSSOError(Exception):
    """Base error.

    ``error`` is an OAuth error code (``invalid_grant``, ``invalid_client`` ...)
    or one of the SDK codes ``network`` / ``invalid_response``.
    """

    def __init__(
        self,
        error: str,
        error_description: str | None = None,
        status: int | None = None,
        field: str | None = None,
        body: Mapping[str, Any] | None = None,
    ) -> None:
        self.error = error
        self.error_description = error_description
        self.status = status
        self.field = field
        self.body: dict[str, Any] = dict(body or {})
        super().__init__(self._message())

    def _message(self) -> str:
        parts = [self.error]
        if self.status is not None:
            parts.insert(0, f"HTTP {self.status}")
        msg = ": ".join(parts)
        if self.error_description:
            msg += f" ({self.error_description})"
        if self.field:
            msg += f" [field={self.field}]"
        return msg

    @property
    def is_network(self) -> bool:
        return self.error == "network"

    @property
    def retryable(self) -> bool:
        """True for failures that never invalidate a login (network, 429, 5xx)."""
        return self.error == "network" or (self.status is not None and (self.status == 429 or self.status >= 500))


class SessionExpired(MoonSSOError):
    """The refresh token was rejected with ``invalid_grant``: the login is gone for good."""

    def __init__(self, error_description: str | None = None, status: int | None = 400, body: Mapping[str, Any] | None = None) -> None:
        super().__init__("invalid_grant", error_description, status, body=body)


class OtpRequired(MoonSSOError):
    """First-party login needs a second factor.

    Pass this exception (or its :attr:`pending` challenge) together with the
    user's one-time code to ``submit_otp``; the SDK keeps the PKCE verifier and
    DPoP binding of the first step.
    """

    def __init__(self, pending: Any, error_description: str | None = None, body: Mapping[str, Any] | None = None) -> None:
        self.pending = pending
        super().__init__("insufficient_authorization", error_description, 400, body=body)

    @property
    def auth_session(self) -> str:
        return str(self.pending.auth_session)

    @property
    def required(self) -> str:
        return str(getattr(self.pending, "required", "otp"))


class PasswordChangeRequired(MoonSSOError):
    """An administrator reset the password; the user must change it in the browser at :attr:`change_url`."""

    def __init__(self, change_url: str | None, error_description: str | None = None, body: Mapping[str, Any] | None = None) -> None:
        self.change_url = change_url
        super().__init__("password_change_required", error_description, 400, body=body)


class InsufficientScope(MoonSSOError):
    """A verified token lacks a scope required by the resource."""

    def __init__(self, required: list[str], error_description: str | None = None) -> None:
        self.required = required
        super().__init__("insufficient_scope", error_description or "missing scope: " + " ".join(required), 403)


class CursorExpired(MoonSSOError):
    """The change-feed cursor is older than the retention window (HTTP 410)."""

    def __init__(self, error_description: str | None = None, body: Mapping[str, Any] | None = None) -> None:
        super().__init__("cursor_expired", error_description, 410, body=body)


class TokenValidationError(MoonSSOError):
    """A JWT (ID token, access token) failed signature or claim validation."""

    def __init__(self, error_description: str, error: str = "invalid_token") -> None:
        super().__init__(error, error_description, 401)


class LogoutTokenError(TokenValidationError):
    """A back-channel logout token is invalid or replayed."""

    def __init__(self, error_description: str) -> None:
        MoonSSOError.__init__(self, "invalid_request", error_description, 400)


class WebhookVerificationError(MoonSSOError):
    """A webhook request has a missing/invalid signature or a stale timestamp."""

    def __init__(self, error_description: str) -> None:
        super().__init__("invalid_signature", error_description, 400)


class AuthorizationResponseError(MoonSSOError):
    """The authorization callback was rejected (error parameter, state or iss mismatch)."""

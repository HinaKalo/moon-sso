"""Plain data objects returned and accepted by the SDK."""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from typing import Any, Mapping

__all__ = [
    "AccessTokenClaims",
    "AuthorizationRequest",
    "ChangesPage",
    "ClientRegistration",
    "LogoutToken",
    "PendingChallenge",
    "ProviderMetadata",
    "SyncBatch",
    "TokenSet",
    "UsersPage",
]


@dataclass(frozen=True)
class ProviderMetadata:
    """The subset of ``/.well-known/openid-configuration`` the SDK uses (``raw`` has everything)."""

    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    userinfo_endpoint: str | None = None
    revocation_endpoint: str | None = None
    introspection_endpoint: str | None = None
    end_session_endpoint: str | None = None
    registration_endpoint: str | None = None
    authorization_challenge_endpoint: str | None = None
    events_endpoint: str | None = None
    api_audience: str | None = None
    iss_parameter_supported: bool = False
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "ProviderMetadata":
        def s(key: str) -> str | None:
            v = d.get(key)
            return v if isinstance(v, str) and v else None

        missing = [k for k in ("issuer", "authorization_endpoint", "token_endpoint", "jwks_uri") if not s(k)]
        if missing:
            from .errors import MoonSSOError

            raise MoonSSOError("invalid_response", "discovery document lacks " + ", ".join(missing))
        return cls(
            issuer=str(d["issuer"]),
            authorization_endpoint=str(d["authorization_endpoint"]),
            token_endpoint=str(d["token_endpoint"]),
            jwks_uri=str(d["jwks_uri"]),
            userinfo_endpoint=s("userinfo_endpoint"),
            revocation_endpoint=s("revocation_endpoint"),
            introspection_endpoint=s("introspection_endpoint"),
            end_session_endpoint=s("end_session_endpoint"),
            registration_endpoint=s("registration_endpoint"),
            authorization_challenge_endpoint=s("authorization_challenge_endpoint"),
            events_endpoint=s("moon_events_endpoint"),
            api_audience=s("moon_api_audience"),
            iss_parameter_supported=bool(d.get("authorization_response_iss_parameter_supported")),
            raw=dict(d),
        )


@dataclass
class TokenSet:
    """Tokens of one login. ``expires_at`` is a Unix timestamp (seconds)."""

    access_token: str
    expires_at: float
    token_type: str = "Bearer"
    refresh_token: str | None = None
    id_token: str | None = None
    scope: str | None = None
    issued_at: float = field(default_factory=time.time)
    id_claims: dict[str, Any] | None = None

    @classmethod
    def from_response(cls, data: Mapping[str, Any], now: float | None = None) -> "TokenSet":
        from .errors import MoonSSOError

        at = data.get("access_token")
        if not isinstance(at, str) or not at:
            raise MoonSSOError("invalid_response", "token response lacks access_token")
        now = time.time() if now is None else now
        try:
            expires_in = float(data.get("expires_in", 3600))
        except (TypeError, ValueError) as exc:
            raise MoonSSOError("invalid_response", "expires_in is not a number") from exc
        rt = data.get("refresh_token")
        it = data.get("id_token")
        sc = data.get("scope")
        tt = data.get("token_type")
        return cls(
            access_token=at,
            expires_at=now + max(expires_in, 0.0),
            token_type=tt if isinstance(tt, str) and tt else "Bearer",
            refresh_token=rt if isinstance(rt, str) and rt else None,
            id_token=it if isinstance(it, str) and it else None,
            scope=sc if isinstance(sc, str) else None,
            issued_at=now,
        )

    @property
    def scopes(self) -> list[str]:
        return self.scope.split() if self.scope else []

    @property
    def lifetime(self) -> float:
        return max(self.expires_at - self.issued_at, 0.0)

    def expires_in(self, now: float | None = None) -> float:
        return self.expires_at - (time.time() if now is None else now)

    @property
    def sub(self) -> str | None:
        return str(self.id_claims["sub"]) if self.id_claims and "sub" in self.id_claims else None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "TokenSet":
        return cls(
            access_token=str(d["access_token"]),
            expires_at=float(d["expires_at"]),
            token_type=str(d.get("token_type") or "Bearer"),
            refresh_token=d.get("refresh_token"),
            id_token=d.get("id_token"),
            scope=d.get("scope"),
            issued_at=float(d.get("issued_at") or time.time()),
            id_claims=dict(d["id_claims"]) if d.get("id_claims") else None,
        )

    def __repr__(self) -> str:  # never print token values
        return (
            f"TokenSet(token_type={self.token_type!r}, expires_at={self.expires_at:.0f}, scope={self.scope!r}, "
            f"refresh_token={'yes' if self.refresh_token else 'no'}, id_token={'yes' if self.id_token else 'no'})"
        )


@dataclass
class AuthorizationRequest:
    """State of an authorization request; persist it (e.g. in the session) until the callback."""

    url: str
    state: str
    nonce: str | None
    code_verifier: str
    redirect_uri: str
    scope: str
    created_at: float = field(default_factory=time.time)
    return_to: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "AuthorizationRequest":
        return cls(
            url=str(d["url"]),
            state=str(d["state"]),
            nonce=d.get("nonce"),
            code_verifier=str(d["code_verifier"]),
            redirect_uri=str(d["redirect_uri"]),
            scope=str(d["scope"]),
            created_at=float(d.get("created_at") or time.time()),
            return_to=d.get("return_to"),
        )

    def __repr__(self) -> str:
        return f"AuthorizationRequest(redirect_uri={self.redirect_uri!r}, scope={self.scope!r})"


@dataclass
class PendingChallenge:
    """A first-party login waiting for a second factor (keeps the PKCE verifier)."""

    auth_session: str
    code_verifier: str
    code_challenge: str
    scope: str
    required: str = "otp"
    endpoint: str = "challenge"

    def __repr__(self) -> str:
        return f"PendingChallenge(required={self.required!r}, scope={self.scope!r})"


@dataclass(frozen=True)
class AccessTokenClaims:
    """Validated claims of an RFC 9068 access token."""

    sub: str
    client_id: str | None
    scopes: tuple[str, ...]
    audience: tuple[str, ...]
    issuer: str
    expires_at: int
    issued_at: int | None
    sid: str | None
    jti: str | None
    raw: Mapping[str, Any] = field(repr=False)

    @property
    def is_client_token(self) -> bool:
        """True for ``client_credentials`` tokens (subject is the client itself)."""
        return self.client_id is not None and self.sub == self.client_id and not self.sid and not self.raw.get("auth_time")

    def has_scope(self, *scopes: str) -> bool:
        return all(s in self.scopes for s in scopes)


@dataclass(frozen=True)
class LogoutToken:
    """A verified back-channel logout token."""

    sub: str | None
    sid: str | None
    jti: str
    issuer: str
    issued_at: int
    raw: Mapping[str, Any] = field(repr=False)


@dataclass(frozen=True)
class ChangesPage:
    """One page of ``GET /api/v1/users/changes``."""

    events: list[dict[str, Any]]
    next_cursor: str
    has_more: bool


@dataclass(frozen=True)
class UsersPage:
    """One page of the ``GET /api/v1/users`` snapshot."""

    users: list[dict[str, Any]]
    watermark: str
    has_more: bool
    next_cursor: str | None


@dataclass(frozen=True)
class SyncBatch:
    """A unit of work produced by ``iter_changes``.

    Apply ``users`` (full-sync snapshot rows) and ``events`` in order, then
    persist ``cursor`` when it is not ``None``. During a full sync only the
    last snapshot page carries a cursor (the watermark), so a crash midway
    restarts the snapshot instead of skipping users.
    """

    events: list[dict[str, Any]]
    users: list[dict[str, Any]]
    cursor: str | None
    full_sync: bool
    has_more: bool


@dataclass(frozen=True)
class ClientRegistration:
    """Result of dynamic client registration (RFC 7591)."""

    client_id: str
    client_secret: str | None
    registration_access_token: str | None
    registration_client_uri: str | None
    status: str
    webhook_secret: str | None
    raw: Mapping[str, Any] = field(repr=False)

    def __repr__(self) -> str:
        return f"ClientRegistration(client_id={self.client_id!r}, status={self.status!r})"

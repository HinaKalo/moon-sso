"""JWT signature and claim validation (pure functions, no I/O).

Signatures are verified with PyJWT / cryptography; this module only adds the
claim rules of the Moon SSO SDK contract (ID tokens, RFC 9068 access tokens
and OIDC back-channel logout tokens).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any, Iterable, Mapping, Sequence

import jwt
from jwt import PyJWK

from .errors import LogoutTokenError, TokenValidationError
from .models import AccessTokenClaims, LogoutToken
from .pkce import b64url

__all__ = [
    "BACKCHANNEL_EVENT",
    "KeySet",
    "unverified_header",
    "verify_signature",
    "validate_access_token",
    "validate_id_token",
    "validate_logout_token",
]

BACKCHANNEL_EVENT = "http://schemas.openid.net/event/backchannel-logout"

#: Algorithms accepted for anything the server signs. Never "none" or HMAC.
SUPPORTED_ALGS = frozenset({"RS256", "ES256"})

_MAX_TOKEN_LEN = 16 * 1024


class KeySet:
    """Parsed JWKS: ``kid`` → :class:`jwt.PyJWK` (signature keys only)."""

    def __init__(self, jwks: Mapping[str, Any]) -> None:
        self.keys: dict[str, PyJWK] = {}
        self.unkeyed: list[PyJWK] = []
        for raw in jwks.get("keys") or []:
            if not isinstance(raw, Mapping):
                continue
            if raw.get("use") not in (None, "sig"):
                continue
            if raw.get("alg") is not None and raw.get("alg") not in SUPPORTED_ALGS:
                continue
            try:
                key = PyJWK(dict(raw))
            except Exception:  # unsupported/malformed key: skip it, keep the others
                continue
            kid = raw.get("kid")
            if isinstance(kid, str) and kid:
                self.keys[kid] = key
            else:
                self.unkeyed.append(key)

    def find(self, kid: str | None, alg: str) -> PyJWK | None:
        if kid:
            key = self.keys.get(kid)
            return key if key is not None and _alg_matches(key, alg) else None
        for key in list(self.keys.values()) + self.unkeyed:
            if _alg_matches(key, alg):
                return key
        return None

    def __len__(self) -> int:
        return len(self.keys) + len(self.unkeyed)


def _alg_matches(key: PyJWK, alg: str) -> bool:
    name = getattr(key, "algorithm_name", None)
    return name is None or name == alg


def unverified_header(token: str) -> dict[str, Any]:
    if not isinstance(token, str) or not token or len(token) > _MAX_TOKEN_LEN or token.count(".") != 2:
        raise TokenValidationError("malformed JWT")
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as exc:
        raise TokenValidationError("malformed JWT header") from exc
    alg = header.get("alg")
    if alg not in SUPPORTED_ALGS:
        raise TokenValidationError(f"unsupported JWT alg {alg!r}")
    return header


def verify_signature(token: str, key: PyJWK, alg: str) -> dict[str, Any]:
    """Verify the JWS signature with ``key`` and return the decoded claims."""
    try:
        decoded = jwt.PyJWS().decode_complete(token, key=key.key, algorithms=[alg])
    except jwt.PyJWTError as exc:
        raise TokenValidationError("invalid JWT signature") from exc
    try:
        claims = json.loads(decoded["payload"])
    except (ValueError, UnicodeDecodeError) as exc:
        raise TokenValidationError("JWT payload is not JSON") from exc
    if not isinstance(claims, dict):
        raise TokenValidationError("JWT payload is not an object")
    return claims


def _typ_is(header: Mapping[str, Any], expected: str) -> bool:
    typ = header.get("typ")
    if not isinstance(typ, str):
        return False
    t = typ.lower()
    return t == expected or t == "application/" + expected


def _aud_list(aud: Any) -> list[str]:
    if isinstance(aud, str):
        return [aud]
    if isinstance(aud, (list, tuple)):
        return [a for a in aud if isinstance(a, str)]
    return []


def _num(claims: Mapping[str, Any], name: str, required: bool) -> int | None:
    v = claims.get(name)
    if v is None:
        if required:
            raise TokenValidationError(f"missing {name}")
        return None
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        raise TokenValidationError(f"{name} is not a number")
    return int(v)


def _at_hash(access_token: str, alg: str) -> str:
    # RS256 / ES256 both use SHA-256: left-most half of the digest.
    digest = hashlib.sha256(access_token.encode("ascii")).digest()
    return b64url(digest[: len(digest) // 2])


def validate_id_token(
    header: Mapping[str, Any],
    claims: Mapping[str, Any],
    *,
    issuer: str,
    client_id: str,
    nonce: str | None = None,
    access_token: str | None = None,
    expected_sub: str | None = None,
    leeway: float = 60.0,
    now: float | None = None,
) -> dict[str, Any]:
    """OIDC Core §3.1.3.7 checks for a signature-verified ID token."""
    now = time.time() if now is None else now
    if header.get("alg") not in SUPPORTED_ALGS:
        raise TokenValidationError("unsupported ID token alg")
    if claims.get("iss") != issuer:
        raise TokenValidationError("ID token iss mismatch")
    auds = _aud_list(claims.get("aud"))
    if client_id not in auds:
        raise TokenValidationError("ID token aud does not contain client_id")
    azp = claims.get("azp")
    if (len(auds) > 1 or azp is not None) and azp != client_id:
        raise TokenValidationError("ID token azp mismatch")
    if not isinstance(claims.get("sub"), str) or not claims["sub"]:
        raise TokenValidationError("ID token lacks sub")
    exp = _num(claims, "exp", True)
    iat = _num(claims, "iat", True)
    assert exp is not None and iat is not None
    if now > exp + leeway:
        raise TokenValidationError("ID token expired")
    if iat > now + leeway:
        raise TokenValidationError("ID token issued in the future")
    if nonce is not None:
        got = claims.get("nonce")
        if not isinstance(got, str) or not hmac.compare_digest(got.encode(), nonce.encode()):
            raise TokenValidationError("ID token nonce mismatch")
    if access_token is not None and "at_hash" in claims:
        expected = _at_hash(access_token, str(header.get("alg")))
        got_hash = claims.get("at_hash")
        if not isinstance(got_hash, str) or not hmac.compare_digest(got_hash.encode(), expected.encode()):
            raise TokenValidationError("ID token at_hash mismatch")
    if expected_sub is not None and claims["sub"] != expected_sub:
        raise TokenValidationError("ID token sub changed")
    return dict(claims)


def validate_access_token(
    header: Mapping[str, Any],
    claims: Mapping[str, Any],
    *,
    issuer: str,
    audiences: Iterable[str],
    required_scopes: Sequence[str] = (),
    leeway: float = 60.0,
    now: float | None = None,
) -> AccessTokenClaims:
    """RFC 9068 checks: ``typ``, ``iss``, ``exp``, ``nbf`` and audience."""
    now = time.time() if now is None else now
    if not _typ_is(header, "at+jwt"):
        raise TokenValidationError("access token typ must be at+jwt")
    if claims.get("iss") != issuer:
        raise TokenValidationError("access token iss mismatch")
    exp = _num(claims, "exp", True)
    nbf = _num(claims, "nbf", False)
    iat = _num(claims, "iat", False)
    assert exp is not None
    if now >= exp + leeway:
        raise TokenValidationError("access token expired")
    if nbf is not None and nbf > now + leeway:
        raise TokenValidationError("access token not yet valid")
    auds = _aud_list(claims.get("aud"))
    wanted = [a for a in audiences if a]
    if not wanted:
        raise TokenValidationError("no expected audience configured")
    if not any(a in auds for a in wanted):
        raise TokenValidationError("access token audience mismatch")
    sub = claims.get("sub")
    if not isinstance(sub, str) or not sub:
        raise TokenValidationError("access token lacks sub")
    scope = claims.get("scope")
    scopes = tuple(scope.split()) if isinstance(scope, str) else ()
    missing = [s for s in required_scopes if s not in scopes]
    if missing:
        from .errors import InsufficientScope

        raise InsufficientScope(missing)
    cid = claims.get("client_id")
    sid = claims.get("sid")
    jti = claims.get("jti")
    return AccessTokenClaims(
        sub=sub,
        client_id=cid if isinstance(cid, str) else None,
        scopes=scopes,
        audience=tuple(auds),
        issuer=issuer,
        expires_at=exp,
        issued_at=iat,
        sid=sid if isinstance(sid, str) and sid else None,
        jti=jti if isinstance(jti, str) else None,
        raw=dict(claims),
    )


def validate_logout_token(
    header: Mapping[str, Any],
    claims: Mapping[str, Any],
    *,
    issuer: str,
    client_id: str,
    leeway: float = 60.0,
    now: float | None = None,
) -> LogoutToken:
    """OIDC Back-Channel Logout §2.6 checks (replay is checked by the caller)."""
    now = time.time() if now is None else now
    if not _typ_is(header, "logout+jwt"):
        raise LogoutTokenError("logout token typ must be logout+jwt")
    if claims.get("iss") != issuer:
        raise LogoutTokenError("logout token iss mismatch")
    if client_id not in _aud_list(claims.get("aud")):
        raise LogoutTokenError("logout token aud does not contain client_id")
    try:
        iat = _num(claims, "iat", True)
        exp = _num(claims, "exp", True)
    except TokenValidationError as exc:
        raise LogoutTokenError(str(exc.error_description)) from exc
    assert iat is not None and exp is not None
    if iat > now + leeway:
        raise LogoutTokenError("logout token issued in the future")
    if now >= exp + leeway:
        raise LogoutTokenError("logout token expired")
    events = claims.get("events")
    if not isinstance(events, Mapping) or BACKCHANNEL_EVENT not in events:
        raise LogoutTokenError("logout token lacks the back-channel logout event")
    if not isinstance(events.get(BACKCHANNEL_EVENT), Mapping):
        raise LogoutTokenError("back-channel logout event must be a JSON object")
    sub = claims.get("sub")
    sid = claims.get("sid")
    sub = sub if isinstance(sub, str) and sub else None
    sid = sid if isinstance(sid, str) and sid else None
    if sub is None and sid is None:
        raise LogoutTokenError("logout token needs sub or sid")
    if "nonce" in claims:
        raise LogoutTokenError("logout token must not contain nonce")
    jti = claims.get("jti")
    if not isinstance(jti, str) or not jti:
        raise LogoutTokenError("logout token lacks jti")
    return LogoutToken(sub=sub, sid=sid, jti=jti, issuer=issuer, issued_at=iat, raw=dict(claims))

"""Unit tests: access-token, ID-token and logout-token validation with locally generated keys."""

from __future__ import annotations

import time
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from moon_sso import InsufficientScope, LogoutTokenError, MoonSSO, TokenValidationError
from moon_sso.jose import BACKCHANNEL_EVENT
from tests.mockserver import ISSUER, FakeServer


@pytest.fixture
def server() -> FakeServer:
    return FakeServer()


@pytest.fixture
def sso(server: FakeServer) -> MoonSSO:
    return MoonSSO(ISSUER, "app", "secret", http_client=server.client(), audience=["app"])


def test_access_token_valid(server: FakeServer, sso: MoonSSO) -> None:
    claims = sso.verify_access_token(server.access_token(sid="s1", auth_time=1), required_scopes=["profile"])
    assert claims.sub == "user-1" and claims.client_id == "app" and claims.sid == "s1"
    assert claims.has_scope("openid", "profile") and not claims.is_client_token
    # custom audience (resource server for the Moon API)
    sso.verify_access_token(server.access_token(), audience=ISSUER + "/api")


def test_access_token_client_credentials_detection(server: FakeServer, sso: MoonSSO) -> None:
    c = sso.verify_access_token(server.access_token(sub="app", scope="users:sync"))
    assert c.is_client_token


@pytest.mark.parametrize(
    "kwargs,message",
    [
        ({"aud": ["other"]}, "audience"),
        ({"ttl": -120}, "expired"),
        ({"iss": "https://evil.test"}, "iss"),
        ({"nbf": int(time.time()) + 600}, "not yet valid"),
    ],
)
def test_access_token_claim_failures(server: FakeServer, sso: MoonSSO, kwargs: dict[str, Any], message: str) -> None:
    token = server.access_token(**kwargs)
    with pytest.raises(TokenValidationError) as ei:
        sso.verify_access_token(token)
    assert message in str(ei.value.error_description)


def test_access_token_wrong_typ(server: FakeServer, sso: MoonSSO) -> None:
    now = int(time.time())
    tok = server.keys.sign_es({"iss": ISSUER, "sub": "u", "aud": "app", "exp": now + 60}, "JWT")
    with pytest.raises(TokenValidationError, match="typ"):
        sso.verify_access_token(tok)
    # application/at+jwt is accepted
    ok = server.keys.sign_es({"iss": ISSUER, "sub": "u", "aud": "app", "exp": now + 60}, "application/at+jwt")
    sso.verify_access_token(ok)


def test_access_token_bad_signature_and_alg(server: FakeServer, sso: MoonSSO) -> None:
    other = ec.generate_private_key(ec.SECP256R1())
    now = int(time.time())
    forged = jwt.encode({"iss": ISSUER, "sub": "u", "aud": "app", "exp": now + 60}, other, algorithm="ES256",
                        headers={"typ": "at+jwt", "kid": server.keys.ec_kid})
    with pytest.raises(TokenValidationError, match="signature"):
        sso.verify_access_token(forged)
    hs = jwt.encode({"iss": ISSUER, "sub": "u", "aud": "app", "exp": now + 60}, "k" * 32, algorithm="HS256",
                    headers={"typ": "at+jwt", "kid": server.keys.ec_kid})
    with pytest.raises(TokenValidationError, match="alg"):
        sso.verify_access_token(hs)
    with pytest.raises(TokenValidationError):
        sso.verify_access_token("not-a-jwt")


def test_insufficient_scope(server: FakeServer, sso: MoonSSO) -> None:
    with pytest.raises(InsufficientScope) as ei:
        sso.verify_access_token(server.access_token(), required_scopes=["admin"])
    assert ei.value.required == ["admin"] and ei.value.status == 403


def test_jwks_unknown_kid_refetch_is_rate_limited(server: FakeServer, sso: MoonSSO) -> None:
    sso.verify_access_token(server.access_token())
    assert server.jwks_hits == 1
    sso.jwks._st.last_attempt -= 31  # the initial fetch was more than 30 s ago
    # Rotate: a new key appears under a new kid -> one forced refetch.
    server.keys.ec = ec.generate_private_key(ec.SECP256R1())
    server.keys.ec_kid = "ec-2"
    sso.verify_access_token(server.access_token())
    assert server.jwks_hits == 2
    # Unknown kid again within 30 s: no further fetch.
    bad = server.keys.sign_es({"iss": ISSUER, "sub": "u", "aud": "app", "exp": int(time.time()) + 60}, "at+jwt", kid="nope")
    with pytest.raises(TokenValidationError, match="kid"):
        sso.verify_access_token(bad)
    assert server.jwks_hits == 2
    # After the interval a refetch is allowed again.
    sso.jwks._st.last_attempt -= 31
    with pytest.raises(TokenValidationError):
        sso.verify_access_token(bad)
    assert server.jwks_hits == 3


def test_jwks_stale_cache_survives_outage(server: FakeServer, sso: MoonSSO) -> None:
    sso.verify_access_token(server.access_token())
    import httpx

    server.route("GET", "/.well-known/jwks.json", lambda r: httpx.Response(503))
    sso.jwks._st.fetched -= 7200  # expired
    sso.jwks._st.last_attempt -= 60
    sso.verify_access_token(server.access_token())  # stale keys still used


def test_id_token_validation(server: FakeServer, sso: MoonSSO) -> None:
    at = server.access_token()
    tok = server.id_token(nonce="n-1", at=at)
    claims = sso.verify_id_token(tok, nonce="n-1", access_token=at)
    assert claims["sub"] == "user-1"
    with pytest.raises(TokenValidationError, match="nonce"):
        sso.verify_id_token(tok, nonce="n-2")
    with pytest.raises(TokenValidationError, match="at_hash"):
        sso.verify_id_token(tok, nonce="n-1", access_token=server.access_token(sub="x"))
    with pytest.raises(TokenValidationError, match="aud"):
        sso.verify_id_token(server.id_token(aud="other", azp="other"))
    with pytest.raises(TokenValidationError, match="expired"):
        sso.verify_id_token(server.id_token(exp=int(time.time()) - 120))
    with pytest.raises(TokenValidationError, match="future"):
        sso.verify_id_token(server.id_token(iat=int(time.time()) + 300))
    with pytest.raises(TokenValidationError, match="sub changed"):
        sso.verify_id_token(server.id_token(), expected_sub="someone-else")
    # 60 s clock skew allowed
    sso.verify_id_token(server.id_token(exp=int(time.time()) - 30, iat=int(time.time()) + 30))


def _logout_claims(**over: Any) -> dict[str, Any]:
    now = int(time.time())
    c: dict[str, Any] = {"iss": ISSUER, "aud": "app", "iat": now, "exp": now + 120, "jti": "jti-" + str(time.time_ns()),
                         "sub": "user-1", "sid": "sid-1", "events": {BACKCHANNEL_EVENT: {}}}
    c.update(over)
    return {k: v for k, v in c.items() if v is not None}


def test_logout_token_valid_and_replay(server: FakeServer, sso: MoonSSO) -> None:
    tok = server.keys.sign_rs(_logout_claims(), "logout+jwt")
    lt = sso.verify_logout_token(tok)
    assert (lt.sub, lt.sid) == ("user-1", "sid-1")
    with pytest.raises(LogoutTokenError, match="replay"):
        sso.verify_logout_token(tok)
    # ES256 and sid-only tokens work too
    sso.verify_logout_token(server.keys.sign_es(_logout_claims(sub=None), "logout+jwt"))


@pytest.mark.parametrize(
    "over,typ,message",
    [
        ({}, "JWT", "typ"),
        ({"iss": "https://evil"}, "logout+jwt", "iss"),
        ({"aud": "other"}, "logout+jwt", "aud"),
        ({"iat": int(time.time()) + 600}, "logout+jwt", "future"),
        ({"exp": int(time.time()) - 600}, "logout+jwt", "expired"),
        ({"events": {"other": {}}}, "logout+jwt", "event"),
        ({"sub": None, "sid": None}, "logout+jwt", "sub or sid"),
        ({"nonce": "n"}, "logout+jwt", "nonce"),
        ({"jti": None}, "logout+jwt", "jti"),
        ({"exp": None}, "logout+jwt", "exp"),
    ],
)
def test_logout_token_rejections(server: FakeServer, sso: MoonSSO, over: dict[str, Any], typ: str, message: str) -> None:
    tok = server.keys.sign_rs(_logout_claims(**over), typ)
    with pytest.raises(LogoutTokenError) as ei:
        sso.verify_logout_token(tok)
    assert message in str(ei.value.error_description)
    assert ei.value.status == 400


def test_logout_token_bad_signature(server: FakeServer, sso: MoonSSO) -> None:
    other = ec.generate_private_key(ec.SECP256R1())
    tok = jwt.encode(_logout_claims(), other, algorithm="ES256", headers={"typ": "logout+jwt", "kid": server.keys.ec_kid})
    with pytest.raises(LogoutTokenError):
        sso.verify_logout_token(tok)

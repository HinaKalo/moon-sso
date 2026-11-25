"""An in-process fake authorization server for unit tests (httpx.MockTransport)."""

from __future__ import annotations

import json
import threading
import time
from typing import Any, Callable
from urllib.parse import parse_qsl

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from moon_sso.pkce import b64url

ISSUER = "https://sso.test"


def _int_b64(n: int) -> str:
    return b64url(n.to_bytes((n.bit_length() + 7) // 8, "big"))


class Keys:
    def __init__(self) -> None:
        self.ec = ec.generate_private_key(ec.SECP256R1())
        self.rsa = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.ec_kid = "ec-1"
        self.rsa_kid = "rsa-1"

    def jwks(self) -> dict[str, Any]:
        en = self.ec.public_key().public_numbers()
        rn = self.rsa.public_key().public_numbers()
        return {
            "keys": [
                {"kty": "EC", "crv": "P-256", "kid": self.ec_kid, "alg": "ES256", "use": "sig",
                 "x": b64url(en.x.to_bytes(32, "big")), "y": b64url(en.y.to_bytes(32, "big"))},
                {"kty": "RSA", "kid": self.rsa_kid, "alg": "RS256", "use": "sig", "n": _int_b64(rn.n), "e": _int_b64(rn.e)},
            ]
        }

    def sign_es(self, claims: dict[str, Any], typ: str, kid: str | None = None) -> str:
        return jwt.encode(claims, self.ec, algorithm="ES256", headers={"typ": typ, "kid": kid or self.ec_kid})

    def sign_rs(self, claims: dict[str, Any], typ: str = "JWT", kid: str | None = None) -> str:
        return jwt.encode(claims, self.rsa, algorithm="RS256", headers={"typ": typ, "kid": kid or self.rsa_kid})


def discovery() -> dict[str, Any]:
    return {
        "issuer": ISSUER,
        "authorization_endpoint": ISSUER + "/oauth/authorize",
        "token_endpoint": ISSUER + "/oauth/token",
        "jwks_uri": ISSUER + "/.well-known/jwks.json",
        "revocation_endpoint": ISSUER + "/oauth/revoke",
        "end_session_endpoint": ISSUER + "/oauth/end_session",
        "registration_endpoint": ISSUER + "/oauth/register",
        "authorization_challenge_endpoint": ISSUER + "/oauth/authorize-challenge",
        "moon_events_endpoint": ISSUER + "/api/v1/me/events",
        "authorization_response_iss_parameter_supported": True,
    }


class FakeServer:
    """Routes requests to overridable handlers and records them."""

    def __init__(self) -> None:
        self.keys = Keys()
        self.requests: list[httpx.Request] = []
        self.routes: dict[tuple[str, str], Callable[[httpx.Request], httpx.Response]] = {}
        self.jwks_hits = 0
        self.lock = threading.Lock()
        self.route("GET", "/.well-known/openid-configuration", lambda r: httpx.Response(200, json=discovery()))
        self.route("GET", "/.well-known/jwks.json", self._jwks)

    def _jwks(self, r: httpx.Request) -> httpx.Response:
        self.jwks_hits += 1
        return httpx.Response(200, json=self.keys.jwks())

    def route(self, method: str, path: str, fn: Callable[[httpx.Request], httpx.Response]) -> None:
        self.routes[(method, path)] = fn

    def handler(self, request: httpx.Request) -> httpx.Response:
        with self.lock:
            self.requests.append(request)
        fn = self.routes.get((request.method, request.url.path))
        if fn is None:
            return httpx.Response(404, json={"error": "not_found"})
        return fn(request)

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handler)

    def client(self) -> httpx.Client:
        return httpx.Client(transport=self.transport())

    def async_client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(self.handler))

    def calls(self, path: str) -> list[httpx.Request]:
        return [r for r in self.requests if r.url.path == path]

    # ---- token helpers ----

    def access_token(self, sub: str = "user-1", aud: Any = None, ttl: int = 600, **extra: Any) -> str:
        now = int(time.time())
        claims = {"iss": ISSUER, "sub": sub, "aud": aud if aud is not None else ["app", ISSUER + "/api"],
                  "exp": now + ttl, "iat": now, "nbf": now - 5, "jti": "j" + str(now), "client_id": "app",
                  "scope": "openid profile", **extra}
        return self.keys.sign_es(claims, "at+jwt")

    def id_token(self, sub: str = "user-1", nonce: str | None = None, at: str | None = None, **extra: Any) -> str:
        now = int(time.time())
        claims: dict[str, Any] = {"iss": ISSUER, "sub": sub, "aud": "app", "azp": "app", "exp": now + 300, "iat": now, **extra}
        if nonce:
            claims["nonce"] = nonce
        if at:
            import hashlib

            claims["at_hash"] = b64url(hashlib.sha256(at.encode()).digest()[:16])
        return self.keys.sign_rs(claims)


def form(request: httpx.Request) -> dict[str, str]:
    return dict(parse_qsl(request.content.decode()))


def token_json(at: str, rt: str | None = "rt-1", id_token: str | None = None, expires_in: int = 600) -> dict[str, Any]:
    out: dict[str, Any] = {"access_token": at, "token_type": "Bearer", "expires_in": expires_in, "scope": "openid profile offline_access"}
    if rt:
        out["refresh_token"] = rt
    if id_token:
        out["id_token"] = id_token
    return out


def dumps(o: Any) -> bytes:
    return json.dumps(o).encode()

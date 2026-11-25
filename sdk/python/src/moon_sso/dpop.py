"""DPoP (RFC 9449) proofs with an ES256 / P-256 key.

The SDK only composes primitives from ``cryptography`` and PyJWT: key
generation, ECDSA signing and SHA-256 come from those libraries.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .pkce import b64url, random_token

__all__ = ["DPoPKey", "htu_of"]


def _int_to_b64(n: int, length: int = 32) -> str:
    return b64url(n.to_bytes(length, "big"))


def htu_of(url: str) -> str:
    """The ``htu`` claim for ``url``: scheme, host and path without query or fragment."""
    p = urlsplit(url)
    return urlunsplit((p.scheme, p.netloc, p.path, "", ""))


class DPoPKey:
    """A long-lived P-256 key pair that signs DPoP proofs.

    Keep one key per installation and persist it with :meth:`to_pem` in secure
    storage; refresh tokens of public clients are bound to its thumbprint.
    The latest ``DPoP-Nonce`` the server sent is tracked on the key object.
    """

    def __init__(self, private_key: ec.EllipticCurvePrivateKey) -> None:
        if not isinstance(private_key, ec.EllipticCurvePrivateKey) or not isinstance(private_key.curve, ec.SECP256R1):
            raise ValueError("DPoP key must be an EC P-256 private key")
        self._key = private_key
        nums = private_key.public_key().public_numbers()
        self._jwk = {"kty": "EC", "crv": "P-256", "x": _int_to_b64(nums.x), "y": _int_to_b64(nums.y)}
        canonical = json.dumps(
            {"crv": "P-256", "kty": "EC", "x": self._jwk["x"], "y": self._jwk["y"]}, separators=(",", ":"), sort_keys=True
        )
        self._thumbprint = b64url(hashlib.sha256(canonical.encode("ascii")).digest())
        self._nonce: str | None = None
        self._lock = threading.Lock()

    # ---- construction / persistence ----

    @classmethod
    def generate(cls) -> "DPoPKey":
        return cls(ec.generate_private_key(ec.SECP256R1()))

    @classmethod
    def from_pem(cls, pem: bytes | str, password: bytes | None = None) -> "DPoPKey":
        data = pem.encode("ascii") if isinstance(pem, str) else pem
        key = serialization.load_pem_private_key(data, password=password)
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise ValueError("PEM does not contain an EC private key")
        return cls(key)

    def to_pem(self, password: bytes | None = None) -> bytes:
        enc: serialization.KeySerializationEncryption = (
            serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
        )
        return self._key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc)

    # ---- public data ----

    @property
    def public_jwk(self) -> dict[str, str]:
        """Public JWK with only ``kty``, ``crv``, ``x`` and ``y``."""
        return dict(self._jwk)

    @property
    def thumbprint(self) -> str:
        """base64url(SHA-256 JWK thumbprint, RFC 7638) — the ``dpop_jkt`` value."""
        return self._thumbprint

    @property
    def nonce(self) -> str | None:
        return self._nonce

    def update_nonce(self, nonce: str | None) -> None:
        if nonce:
            with self._lock:
                self._nonce = nonce

    # ---- proofs ----

    def proof(self, htm: str, url: str, *, nonce: str | None = None, access_token: str | None = None) -> str:
        """Create a fresh proof for one request (new ``jti`` every call)."""
        claims: dict[str, Any] = {
            "jti": random_token(24),
            "htm": htm.upper(),
            "htu": htu_of(url),
            "iat": int(time.time()),
        }
        n = nonce if nonce is not None else self._nonce
        if n:
            claims["nonce"] = n
        if access_token:
            claims["ath"] = b64url(hashlib.sha256(access_token.encode("ascii")).digest())
        headers = {"typ": "dpop+jwt", "alg": "ES256", "jwk": self.public_jwk}
        return jwt.encode(claims, self._key, algorithm="ES256", headers=headers)

    def __repr__(self) -> str:  # never print key material
        return f"DPoPKey(jkt={self._thumbprint!r})"

"""PKCE (RFC 7636, S256 only) and random value helpers."""

from __future__ import annotations

import base64
import hashlib
import re
import secrets
from dataclasses import dataclass

__all__ = ["PKCE", "b64url", "b64url_decode", "code_challenge", "generate_code_verifier", "random_token"]

_VERIFIER_RE = re.compile(r"^[A-Za-z0-9\-._~]{43,128}$")


def b64url(data: bytes) -> str:
    """Unpadded base64url encoding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def random_token(nbytes: int = 32) -> str:
    """URL-safe random string with ``nbytes`` bytes of entropy (default 256 bits)."""
    if nbytes < 16:
        raise ValueError("random values must carry at least 128 bits")
    return b64url(secrets.token_bytes(nbytes))


def generate_code_verifier(nbytes: int = 48) -> str:
    """A 43–128 character base64url verifier (default 64 characters)."""
    if not 32 <= nbytes <= 96:
        raise ValueError("nbytes must be between 32 and 96")
    return b64url(secrets.token_bytes(nbytes))


def code_challenge(verifier: str) -> str:
    """S256 challenge of ``verifier``."""
    if not _VERIFIER_RE.match(verifier):
        raise ValueError("code_verifier must be 43-128 characters of [A-Za-z0-9-._~]")
    return b64url(hashlib.sha256(verifier.encode("ascii")).digest())


@dataclass(frozen=True)
class PKCE:
    """A verifier and its S256 challenge."""

    verifier: str
    challenge: str
    method: str = "S256"

    @classmethod
    def generate(cls) -> "PKCE":
        v = generate_code_verifier()
        return cls(verifier=v, challenge=code_challenge(v))

    @classmethod
    def from_verifier(cls, verifier: str) -> "PKCE":
        return cls(verifier=verifier, challenge=code_challenge(verifier))

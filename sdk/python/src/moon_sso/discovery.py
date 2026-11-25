"""Discovery document and JWKS caches (sync and async).

* Discovery is cached for one hour; when a refresh fails the expired copy is
  used.
* JWKS is cached for one hour; an unknown ``kid`` forces a refetch, at most
  once every 30 seconds.
"""

from __future__ import annotations

import asyncio
import threading
import time
from typing import Any, Awaitable, Callable

import httpx
from jwt import PyJWK

from ._util import expect_json, network_error
from .errors import MoonSSOError, TokenValidationError
from .jose import KeySet
from .models import ProviderMetadata

__all__ = ["AsyncDiscovery", "AsyncJWKS", "Discovery", "JWKS", "normalize_issuer"]

DISCOVERY_TTL = 3600.0
JWKS_TTL = 3600.0
JWKS_MIN_REFETCH = 30.0


def normalize_issuer(issuer: str) -> str:
    issuer = issuer.strip()
    if not issuer.startswith(("https://", "http://")):
        raise ValueError("issuer must be an absolute http(s) URL")
    return issuer.rstrip("/")


def _parse_discovery(issuer: str, data: dict[str, Any]) -> ProviderMetadata:
    meta = ProviderMetadata.from_dict(data)
    if meta.issuer.rstrip("/") != issuer:
        raise MoonSSOError("invalid_response", f"discovery issuer {meta.issuer!r} does not match {issuer!r}")
    return meta


class Discovery:
    """Thread-safe cached discovery document."""

    def __init__(self, issuer: str, http: httpx.Client, ttl: float = DISCOVERY_TTL) -> None:
        self.issuer = normalize_issuer(issuer)
        self.url = self.issuer + "/.well-known/openid-configuration"
        self._http = http
        self._ttl = ttl
        self._meta: ProviderMetadata | None = None
        self._fetched = 0.0
        self._lock = threading.Lock()

    def get(self, force: bool = False) -> ProviderMetadata:
        meta = self._meta
        if meta is not None and not force and time.monotonic() - self._fetched < self._ttl:
            return meta
        with self._lock:
            meta = self._meta
            if meta is not None and not force and time.monotonic() - self._fetched < self._ttl:
                return meta
            try:
                resp = self._http.get(self.url, headers={"Accept": "application/json"})
                fresh = _parse_discovery(self.issuer, expect_json(resp))
            except (httpx.HTTPError, MoonSSOError) as exc:
                if meta is not None:
                    return meta  # stale copy beats an outage
                raise network_error(exc) if isinstance(exc, httpx.HTTPError) else exc
            self._meta, self._fetched = fresh, time.monotonic()
            return fresh


class AsyncDiscovery:
    """Cached discovery document for asyncio applications."""

    def __init__(self, issuer: str, http: httpx.AsyncClient, ttl: float = DISCOVERY_TTL) -> None:
        self.issuer = normalize_issuer(issuer)
        self.url = self.issuer + "/.well-known/openid-configuration"
        self._http = http
        self._ttl = ttl
        self._meta: ProviderMetadata | None = None
        self._fetched = 0.0
        self._lock = asyncio.Lock()

    async def get(self, force: bool = False) -> ProviderMetadata:
        meta = self._meta
        if meta is not None and not force and time.monotonic() - self._fetched < self._ttl:
            return meta
        async with self._lock:
            meta = self._meta
            if meta is not None and not force and time.monotonic() - self._fetched < self._ttl:
                return meta
            try:
                resp = await self._http.get(self.url, headers={"Accept": "application/json"})
                fresh = _parse_discovery(self.issuer, expect_json(resp))
            except (httpx.HTTPError, MoonSSOError) as exc:
                if meta is not None:
                    return meta
                raise network_error(exc) if isinstance(exc, httpx.HTTPError) else exc
            self._meta, self._fetched = fresh, time.monotonic()
            return fresh


class _JWKSState:
    def __init__(self, ttl: float, min_refetch: float) -> None:
        self.ttl = ttl
        self.min_refetch = min_refetch
        self.keys: KeySet | None = None
        self.fetched = 0.0
        self.last_attempt = -1e18

    def fresh(self) -> bool:
        return self.keys is not None and time.monotonic() - self.fetched < self.ttl

    def may_refetch(self) -> bool:
        return time.monotonic() - self.last_attempt >= self.min_refetch

    def store(self, data: dict[str, Any]) -> None:
        self.keys = KeySet(data)
        self.fetched = time.monotonic()


class JWKS:
    """Thread-safe JWKS cache with rate-limited refetch on unknown ``kid``."""

    def __init__(
        self,
        http: httpx.Client,
        uri: str | Callable[[], str],
        ttl: float = JWKS_TTL,
        min_refetch_interval: float = JWKS_MIN_REFETCH,
    ) -> None:
        self._http = http
        self._uri = uri
        self._st = _JWKSState(ttl, min_refetch_interval)
        self._lock = threading.Lock()

    def _fetch(self) -> None:
        self._st.last_attempt = time.monotonic()
        uri = self._uri() if callable(self._uri) else self._uri
        try:
            resp = self._http.get(uri, headers={"Accept": "application/jwk-set+json, application/json"})
            data = expect_json(resp)
        except httpx.HTTPError as exc:
            if self._st.keys is None:
                raise network_error(exc) from exc
            return
        except MoonSSOError:
            if self._st.keys is None:
                raise
            return
        self._st.store(data)

    def get_key(self, kid: str | None, alg: str) -> PyJWK:
        with self._lock:
            if not self._st.fresh() and self._st.may_refetch():
                self._fetch()
            keys = self._st.keys
            key = keys.find(kid, alg) if keys is not None else None
            if key is None and self._st.may_refetch():
                self._fetch()
                keys = self._st.keys
                key = keys.find(kid, alg) if keys is not None else None
        if key is None:
            raise TokenValidationError(f"no signing key for kid {kid!r}")
        return key

    def refresh(self) -> None:
        with self._lock:
            self._fetch()


class AsyncJWKS:
    """asyncio JWKS cache with rate-limited refetch on unknown ``kid``."""

    def __init__(
        self,
        http: httpx.AsyncClient,
        uri: str | Callable[[], Awaitable[str]],
        ttl: float = JWKS_TTL,
        min_refetch_interval: float = JWKS_MIN_REFETCH,
    ) -> None:
        self._http = http
        self._uri = uri
        self._st = _JWKSState(ttl, min_refetch_interval)
        self._lock = asyncio.Lock()

    async def _fetch(self) -> None:
        self._st.last_attempt = time.monotonic()
        uri = await self._uri() if callable(self._uri) else self._uri
        try:
            resp = await self._http.get(uri, headers={"Accept": "application/jwk-set+json, application/json"})
            data = expect_json(resp)
        except httpx.HTTPError as exc:
            if self._st.keys is None:
                raise network_error(exc) from exc
            return
        except MoonSSOError:
            if self._st.keys is None:
                raise
            return
        self._st.store(data)

    async def get_key(self, kid: str | None, alg: str) -> PyJWK:
        async with self._lock:
            if not self._st.fresh() and self._st.may_refetch():
                await self._fetch()
            keys = self._st.keys
            key = keys.find(kid, alg) if keys is not None else None
            if key is None and self._st.may_refetch():
                await self._fetch()
                keys = self._st.keys
                key = keys.find(kid, alg) if keys is not None else None
        if key is None:
            raise TokenValidationError(f"no signing key for kid {kid!r}")
        return key

    async def refresh(self) -> None:
        async with self._lock:
            await self._fetch()

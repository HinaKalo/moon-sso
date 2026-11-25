from __future__ import annotations

import os
import queue
import re
import secrets
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Iterator
from urllib.parse import parse_qsl, urlencode, urlsplit

import httpx
import pytest

TESTBED = os.environ.get("MOON_SSO_TESTBED", "http://127.0.0.1:18601").rstrip("/")
WEB_ID = "test-web"
WEB_SECRET = "test-web-secret-0123456789abcdef"
WEB_REDIRECT = "http://127.0.0.1:18700/callback"
BOB_TOTP = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
ALICE = ("alice", "Wonderland-Pass-1")
BOB = ("bob", "Builder-Pass-22")

_reachable: bool | None = None


def testbed_reachable() -> bool:
    global _reachable
    if _reachable is None:
        try:
            _reachable = httpx.get(TESTBED + "/.well-known/openid-configuration", timeout=3).status_code == 200
        except httpx.HTTPError:
            _reachable = False
    return _reachable


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    skip = pytest.mark.skip(reason=f"Moon SSO testbed not reachable at {TESTBED}")
    for item in items:
        if "integration" in item.keywords and not testbed_reachable():
            item.add_marker(skip)


class Testbed:
    """Helpers for the /__test endpoints."""

    __test__ = False
    url = TESTBED

    def __init__(self) -> None:
        self.http = httpx.Client(base_url=TESTBED, timeout=20)

    def create_user(self, password: str = "Sdk-Py-Pass-123456") -> tuple[str, str]:
        username = "t_" + secrets.token_hex(4)
        r = self.http.post("/__test/users", json={"username": username, "password": password})
        assert r.status_code == 200, r.text
        return username, password

    def authorize(self, auth_url: str, username: str, password: str) -> dict[str, str]:
        """Complete an authorization request as a browser would; returns {"redirect", "session_token"}."""
        params = dict(parse_qsl(urlsplit(auth_url).query))
        params.update(username=username, password=password)
        r = self.http.post("/__test/authorize", data=params)
        assert r.status_code == 200, r.text
        return r.json()

    def totp(self, secret: str = BOB_TOTP) -> str:
        r = self.http.post("/__test/totp", params={"secret": secret})
        assert r.status_code == 200, r.text
        return str(r.json()["code"])

    def set_display_name(self, username: str, display_name: str) -> None:
        r = self.http.post(f"/__test/users/{username}/profile", json={"display_name": display_name})
        assert r.status_code == 200, r.text

    def iat(self) -> str:
        r = self.http.post("/__test/iat")
        assert r.status_code == 200, r.text
        return str(r.json()["token"])

    def developer_iat(self) -> str:
        """An initial access token from the developer portal of a fresh user.

        Fallback for when alice's DCR quota (max_clients_per_developer) is used
        up by the SDK suites sharing this testbed.
        """
        username, password = self.create_user()
        params = {
            "response_type": "code", "client_id": WEB_ID, "redirect_uri": WEB_REDIRECT, "scope": "openid",
            "state": secrets.token_urlsafe(16), "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            "code_challenge_method": "S256",
        }
        out = self.authorize("?" + urlencode(params), username, password)
        with httpx.Client(base_url=TESTBED, timeout=20, cookies={"sso_sid": out["session_token"]}) as browser:
            page = browser.get("/developer")
            m = re.search(r'name="_csrf"\s+value="([^"]+)"', page.text) or re.search(r'value="([^"]+)"\s+name="_csrf"', page.text)
            assert page.status_code == 200 and m, "developer portal page lacks a CSRF token"
            r = browser.post("/developer/tokens", data={"_csrf": m.group(1)}, headers={"Origin": TESTBED})
            found = re.findall(r"iat_[A-Za-z0-9_\-]+", r.text)
            assert r.status_code == 200 and found, r.text[:300]
            return found[0]

    def trust(self, client_id: str) -> None:
        r = self.http.post(f"/__test/clients/{client_id}/trust")
        assert r.status_code == 200, r.text

    def set_webhook(self, client_id: str, url: str) -> str:
        r = self.http.post(f"/__test/clients/{client_id}/webhook", json={"url": url})
        assert r.status_code == 200, r.text
        return str(r.json()["secret"])

    def set_backchannel(self, client_id: str, url: str) -> None:
        r = self.http.post(f"/__test/clients/{client_id}/backchannel", json={"url": url})
        assert r.status_code == 200, r.text

    def logout(self, session_token: str) -> None:
        r = self.http.post("/__test/logout", params={"session_token": session_token})
        assert r.status_code == 200, r.text


@pytest.fixture(scope="session")
def testbed() -> Iterator[Testbed]:
    if not testbed_reachable():
        pytest.skip(f"Moon SSO testbed not reachable at {TESTBED}")
    tb = Testbed()
    yield tb
    tb.http.close()


@pytest.fixture(scope="session")
def dcr_client(testbed: Testbed) -> Iterator[Any]:
    """One DCR-registered, trusted confidential client for this test session (deleted afterwards)."""
    from moon_sso import MoonSSOError, register_client, unregister_client

    meta = {
        "client_name": "moon-sso-sdk-python tests",
        "redirect_uris": [WEB_REDIRECT],
        "token_endpoint_auth_method": "client_secret_basic",
        "application_type": "web",
        "scope": "openid profile offline_access",
        "grant_types": ["authorization_code", "refresh_token"],
    }
    try:
        reg = register_client(TESTBED, testbed.iat(), meta)
    except MoonSSOError as exc:
        if exc.error != "access_denied":
            raise
        reg = register_client(TESTBED, testbed.developer_iat(), meta)
    testbed.trust(reg.client_id)
    yield reg
    try:
        unregister_client(reg)
    except MoonSSOError:
        pass


@dataclass
class Captured:
    method: str
    path: str
    headers: dict[str, str]
    body: bytes


class Receiver:
    """A tiny local HTTP server recording POSTs (webhooks, back-channel logout)."""

    def __init__(self, status: int = 200) -> None:
        self.requests: "queue.Queue[Captured]" = queue.Queue()
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n)
                outer.requests.put(Captured("POST", self.path, {k: v for k, v in self.headers.items()}, body))
                self.send_response(status)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *args: Any) -> None:
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.server.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def wait(self, predicate: Any = None, timeout: float = 30.0) -> Captured:
        deadline = time.monotonic() + timeout
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError("no matching request received")
            try:
                item = self.requests.get(timeout=left)
            except queue.Empty as exc:
                raise TimeoutError("no matching request received") from exc
            if predicate is None or predicate(item):
                return item

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def receiver() -> Iterator[Receiver]:
    r = Receiver()
    yield r
    r.close()

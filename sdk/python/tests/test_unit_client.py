"""Unit tests of client behaviour against an in-process fake server."""

from __future__ import annotations

import asyncio
import threading
import time
from typing import Any
from urllib.parse import parse_qsl, urlsplit

import httpx
import jwt
import pytest

from moon_sso import (
    AsyncMoonSSO,
    AuthorizationResponseError,
    MoonSSO,
    MoonSSOError,
    OtpRequired,
    PasswordChangeRequired,
    SessionExpired,
    TokenSet,
)
from tests.mockserver import ISSUER, FakeServer, form, token_json


@pytest.fixture
def server() -> FakeServer:
    return FakeServer()


def make(server: FakeServer, **kw: Any) -> MoonSSO:
    kw.setdefault("redirect_uri", "https://app.test/cb")
    return MoonSSO(ISSUER, "app", "secret", http_client=server.client(), **kw)


def expired_tokens(rt: str = "rt-0") -> TokenSet:
    now = time.time()
    return TokenSet(access_token="old-at", expires_at=now - 1, refresh_token=rt, issued_at=now - 600)


# ---- authorization request / callback ----


def test_authorization_url_and_callback(server: FakeServer) -> None:
    sso = make(server)
    req = sso.authorization_request(login_hint="alice", extra={"ui_locales": "zh-CN"})
    q = dict(parse_qsl(urlsplit(req.url).query))
    assert q["response_type"] == "code" and q["client_id"] == "app" and q["code_challenge_method"] == "S256"
    assert q["redirect_uri"] == "https://app.test/cb" and q["state"] == req.state and q["nonce"] == req.nonce
    assert q["login_hint"] == "alice" and q["ui_locales"] == "zh-CN" and "dpop_jkt" not in q
    assert len(req.state) >= 22 and len(req.nonce or "") >= 22

    seen: dict[str, Any] = {}

    def token(r: httpx.Request) -> httpx.Response:
        seen.update(form(r))
        seen["auth"] = r.headers.get("authorization")
        at = server.access_token()
        return httpx.Response(200, json=token_json(at, id_token=server.id_token(nonce=req.nonce, at=at)))

    server.route("POST", "/oauth/token", token)
    cb = f"https://app.test/cb?code=c1&state={req.state}&iss={ISSUER}"
    ts = sso.handle_callback(cb, req)
    assert ts.refresh_token == "rt-1" and ts.id_claims and ts.id_claims["sub"] == "user-1"
    assert seen["code_verifier"] == req.code_verifier and seen["redirect_uri"] == req.redirect_uri
    assert seen["auth"].startswith("Basic ") and "client_secret" not in seen


@pytest.mark.parametrize(
    "query,error",
    [
        ("code=c&state=WRONG&iss=" + ISSUER, "invalid_state"),
        ("code=c&state={s}&iss=https://evil.test", "invalid_issuer"),
        ("code=c&state={s}", "invalid_issuer"),  # server advertises RFC 9207 support
        ("error=access_denied&state={s}&iss=" + ISSUER, "access_denied"),
        ("state={s}&iss=" + ISSUER, "invalid_request"),
    ],
)
def test_callback_rejections(server: FakeServer, query: str, error: str) -> None:
    sso = make(server)
    req = sso.authorization_request()
    with pytest.raises(AuthorizationResponseError) as ei:
        sso.handle_callback(query.replace("{s}", req.state), req)
    assert ei.value.error == error
    assert not server.calls("/oauth/token")


def test_nonce_mismatch_rejected(server: FakeServer) -> None:
    sso = make(server)
    req = sso.authorization_request()
    server.route("POST", "/oauth/token", lambda r: httpx.Response(200, json=token_json(server.access_token(), id_token=server.id_token(nonce="other"))))
    with pytest.raises(MoonSSOError, match="nonce"):
        sso.handle_callback({"code": "c", "state": req.state, "iss": ISSUER}, req)


# ---- token endpoint retry rules ----


def test_token_retry_once_on_503_then_success(server: FakeServer) -> None:
    calls: list[dict[str, str]] = []

    def token(r: httpx.Request) -> httpx.Response:
        calls.append(form(r))
        if len(calls) == 1:
            return httpx.Response(503, json={"error": "temporarily_unavailable"})
        return httpx.Response(200, json=token_json(server.access_token(), rt="rt-2"))

    server.route("POST", "/oauth/token", token)
    ts = make(server).refresh_tokens("rt-1")
    assert ts.refresh_token == "rt-2" and len(calls) == 2 and calls[0] == calls[1]


def test_token_retry_on_network_error(server: FakeServer) -> None:
    n = {"i": 0}

    def token(r: httpx.Request) -> httpx.Response:
        n["i"] += 1
        if n["i"] == 1:
            raise httpx.ConnectError("connection reset")
        return httpx.Response(200, json=token_json(server.access_token()))

    server.route("POST", "/oauth/token", token)
    make(server).refresh_tokens("rt")
    assert n["i"] == 2


def test_token_gives_up_after_one_retry(server: FakeServer) -> None:
    server.route("POST", "/oauth/token", lambda r: httpx.Response(502, text="bad gateway"))
    with pytest.raises(MoonSSOError) as ei:
        make(server).refresh_tokens("rt")
    assert ei.value.status == 502 and ei.value.retryable and not isinstance(ei.value, SessionExpired)
    assert len(server.calls("/oauth/token")) == 2


def test_no_retry_on_invalid_client_and_429(server: FakeServer) -> None:
    server.route("POST", "/oauth/token", lambda r: httpx.Response(401, json={"error": "invalid_client", "error_description": "bad"}))
    with pytest.raises(MoonSSOError) as ei:
        make(server).refresh_tokens("rt")
    assert ei.value.error == "invalid_client" and len(server.calls("/oauth/token")) == 1
    server.requests.clear()
    server.route("POST", "/oauth/token", lambda r: httpx.Response(429, json={"error": "slow_down"}))
    with pytest.raises(MoonSSOError) as ei2:
        make(server).refresh_tokens("rt")
    assert ei2.value.status == 429 and len(server.calls("/oauth/token")) == 1


def test_invalid_grant_is_session_expired_and_clears_store(server: FakeServer) -> None:
    server.route("POST", "/oauth/token", lambda r: httpx.Response(400, json={"error": "invalid_grant", "error_description": "revoked"}))
    expired: list[Exception] = []
    s = make(server).session(expired_tokens(), on_session_expired=expired.append)
    with pytest.raises(SessionExpired):
        s.get_access_token()
    assert s.tokens is None and len(expired) == 1 and expired[0].error == "invalid_grant"  # type: ignore[attr-defined]


def test_network_error_keeps_session(server: FakeServer) -> None:
    def boom(r: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down")

    server.route("POST", "/oauth/token", boom)
    expired: list[Exception] = []
    s = make(server).session(expired_tokens(), on_session_expired=expired.append)
    with pytest.raises(MoonSSOError) as ei:
        s.get_access_token()
    assert ei.value.error == "network" and s.tokens is not None and not expired


def test_single_flight_threads(server: FakeServer) -> None:
    gate = threading.Event()
    count = {"n": 0}

    def token(r: httpx.Request) -> httpx.Response:
        count["n"] += 1
        gate.wait(2)
        return httpx.Response(200, json=token_json(server.access_token(), rt=f"rt-{count['n']}"))

    server.route("POST", "/oauth/token", token)
    s = make(server).session(expired_tokens())
    results: list[str] = []

    def worker() -> None:
        results.append(s.get_access_token())

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for t in threads:
        t.start()
    time.sleep(0.2)
    gate.set()
    for t in threads:
        t.join()
    assert count["n"] == 1 and len(set(results)) == 1 and s.tokens and s.tokens.refresh_token == "rt-1"


def test_resource_401_refreshes_once_and_replays(server: FakeServer) -> None:
    server.route("POST", "/oauth/token", lambda r: httpx.Response(200, json=token_json("fresh-at", rt="rt-9")))
    seen: list[str] = []

    def me(r: httpx.Request) -> httpx.Response:
        seen.append(r.headers["authorization"])
        if r.headers["authorization"] == "Bearer valid-but-revoked":
            return httpx.Response(401, json={"error": "invalid_token"})
        return httpx.Response(200, json={"sub": "u", "profile_version": 3}, headers={"ETag": '"pv-3"'})

    server.route("GET", "/api/v1/me", me)
    now = time.time()
    s = make(server).session(TokenSet(access_token="valid-but-revoked", expires_at=now + 500, refresh_token="rt-0", issued_at=now))
    assert s.get_me()["profile_version"] == 3
    assert seen == ["Bearer valid-but-revoked", "Bearer fresh-at"]
    assert len(server.calls("/oauth/token")) == 1


def test_resource_second_401_is_returned_without_logout(server: FakeServer) -> None:
    server.route("POST", "/oauth/token", lambda r: httpx.Response(200, json=token_json("fresh", rt="rt-2")))
    server.route("GET", "/api/v1/me", lambda r: httpx.Response(401, json={"error": "invalid_token"}))
    now = time.time()
    s = make(server).session(TokenSet(access_token="a", expires_at=now + 500, refresh_token="rt-0", issued_at=now))
    with pytest.raises(MoonSSOError) as ei:
        s.get_me()
    assert ei.value.status == 401 and s.tokens is not None


def test_proactive_refresh_within_120s(server: FakeServer) -> None:
    server.route("POST", "/oauth/token", lambda r: httpx.Response(200, json=token_json("new", rt="rt-2")))
    now = time.time()
    s = make(server).session(TokenSet(access_token="old", expires_at=now + 100, refresh_token="rt-1", issued_at=now - 500))
    assert s.get_access_token() == "new"
    s2 = make(server).session(TokenSet(access_token="ok", expires_at=now + 300, refresh_token="rt-1", issued_at=now - 300))
    assert s2.get_access_token() == "ok"


# ---- DPoP ----


def test_dpop_nonce_retry_and_binding(server: FakeServer) -> None:
    proofs: list[dict[str, Any]] = []

    def token(r: httpx.Request) -> httpx.Response:
        claims = jwt.decode(r.headers["DPoP"], options={"verify_signature": False})
        proofs.append(claims)
        if "nonce" not in claims:
            return httpx.Response(400, json={"error": "use_dpop_nonce"}, headers={"DPoP-Nonce": "N1"})
        assert form(r)["client_id"] == "pub" and "client_secret" not in form(r)
        return httpx.Response(200, json=token_json(server.access_token()), headers={"DPoP-Nonce": "N2"})

    server.route("POST", "/oauth/token", token)
    sso = MoonSSO(ISSUER, "pub", http_client=server.client(), redirect_uri="http://127.0.0.1/callback")
    assert sso.is_public and sso.dpop_key is not None
    req = sso.authorization_request()
    assert dict(parse_qsl(urlsplit(req.url).query))["dpop_jkt"] == sso.dpop_key.thumbprint
    sso.refresh_tokens("rt")
    assert len(proofs) == 2 and proofs[1]["nonce"] == "N1" and proofs[0]["jti"] != proofs[1]["jti"]
    assert proofs[1]["htu"] == ISSUER + "/oauth/token" and sso.dpop_key.nonce == "N2"


# ---- first-party challenge ----


def test_first_party_otp_flow(server: FakeServer) -> None:
    steps: list[dict[str, str]] = []

    def challenge(r: httpx.Request) -> httpx.Response:
        f = form(r)
        steps.append(f)
        if "auth_session" not in f:
            return httpx.Response(400, json={"error": "insufficient_authorization", "auth_session": "AS1", "required": "otp"})
        assert f["auth_session"] == "AS1" and f["otp"] == "123456"
        return httpx.Response(200, json={"authorization_code": "code-1"})

    token_forms: list[dict[str, str]] = []

    def token(r: httpx.Request) -> httpx.Response:
        token_forms.append(form(r))
        return httpx.Response(200, json=token_json(server.access_token()))

    server.route("POST", "/oauth/authorize-challenge", challenge)
    server.route("POST", "/oauth/token", token)
    sso = MoonSSO(ISSUER, "native", http_client=server.client(), dpop=False)
    with pytest.raises(OtpRequired) as ei:
        sso.login_with_password("bob", "pw")
    assert ei.value.auth_session == "AS1" and ei.value.required == "otp"
    sso.submit_otp(ei.value, "123456")
    assert steps[0]["code_challenge"] == steps[1]["code_challenge"] and steps[0]["code_challenge_method"] == "S256"
    assert "redirect_uri" not in token_forms[0] and token_forms[0]["client_id"] == "native"


def test_password_change_required(server: FakeServer) -> None:
    server.route("POST", "/oauth/authorize-challenge", lambda r: httpx.Response(
        400, json={"error": "password_change_required", "change_url": ISSUER + "/account/password/change"}))
    sso = MoonSSO(ISSUER, "native", http_client=server.client(), dpop=False)
    with pytest.raises(PasswordChangeRequired) as ei:
        sso.login_with_password("u", "p")
    assert ei.value.change_url.endswith("/account/password/change")  # type: ignore[union-attr]


# ---- client credentials and the changes feed ----


def test_client_credentials_cached(server: FakeServer) -> None:
    server.route("POST", "/oauth/token", lambda r: httpx.Response(200, json=token_json(server.access_token(sub="app"), rt=None)))
    sso = make(server)
    a = sso.client_credentials_token()
    b = sso.client_credentials_token()
    assert a == b and len(server.calls("/oauth/token")) == 1
    assert form(server.calls("/oauth/token")[0]) == {"grant_type": "client_credentials", "scope": "users:sync"}


def test_iter_changes_410_triggers_full_sync(server: FakeServer) -> None:
    server.route("POST", "/oauth/token", lambda r: httpx.Response(200, json=token_json(server.access_token(sub="app"), rt=None)))

    def changes(r: httpx.Request) -> httpx.Response:
        cur = r.url.params.get("cursor")
        if cur == "5":
            return httpx.Response(410, json={"error": "cursor_expired"})
        if cur == "100":
            return httpx.Response(200, json={"events": [{"id": "evt_101", "seq": 101}], "next_cursor": "101", "has_more": True})
        return httpx.Response(200, json={"events": [], "next_cursor": "101", "has_more": False})

    def users(r: httpx.Request) -> httpx.Response:
        if r.url.params.get("cursor") is None:
            return httpx.Response(200, json={"users": [{"sub": "a"}], "has_more": True, "next_cursor": "aa", "watermark": "100"})
        return httpx.Response(200, json={"users": [{"sub": "b"}], "has_more": False, "watermark": "100"})

    server.route("GET", "/api/v1/users/changes", changes)
    server.route("GET", "/api/v1/users", users)
    batches = list(make(server).iter_changes("5"))
    assert [b.full_sync for b in batches] == [True, True, False, False]
    assert [u["sub"] for b in batches for u in b.users] == ["a", "b"]
    assert batches[0].cursor is None and batches[1].cursor == "100"
    assert batches[2].events[0]["id"] == "evt_101" and batches[-1].cursor == "101"


# ---- async client ----


async def test_async_single_flight_and_callback(server: FakeServer) -> None:
    count = {"n": 0}

    def token(r: httpx.Request) -> httpx.Response:
        count["n"] += 1
        return httpx.Response(200, json=token_json(server.access_token(), rt=f"rt-{count['n']}"))

    server.route("POST", "/oauth/token", token)
    sso = AsyncMoonSSO(ISSUER, "app", "secret", http_client=server.async_client(), redirect_uri="https://app.test/cb")
    s = sso.session(expired_tokens())
    results = await asyncio.gather(*[s.get_access_token() for _ in range(20)])
    assert count["n"] == 1 and len(set(results)) == 1

    req = await sso.authorization_request()
    at = server.access_token()
    server.route("POST", "/oauth/token", lambda r: httpx.Response(200, json=token_json(at, id_token=server.id_token(nonce=req.nonce, at=at))))
    ts = await sso.handle_callback({"code": "c", "state": req.state, "iss": ISSUER}, req)
    assert ts.id_claims and ts.id_claims["sub"] == "user-1"
    claims = await sso.verify_access_token(at)
    assert claims.sub == "user-1"
    await sso.aclose()


async def test_async_invalid_grant(server: FakeServer) -> None:
    server.route("POST", "/oauth/token", lambda r: httpx.Response(400, json={"error": "invalid_grant"}))
    got: list[Exception] = []

    async def on_expired(exc: Exception) -> None:
        got.append(exc)

    sso = AsyncMoonSSO(ISSUER, "app", "secret", http_client=server.async_client())
    s = sso.session(expired_tokens(), on_session_expired=on_expired)
    with pytest.raises(SessionExpired):
        await s.get_access_token()
    assert await s.tokens() is None and len(got) == 1


# ---- SSE consumer ----


def test_sse_consumer_reconnect_last_event_id_and_session_end(server: FakeServer) -> None:
    connections: list[httpx.Request] = []
    refresh = {"n": 0}

    def token(r: httpx.Request) -> httpx.Response:
        refresh["n"] += 1
        if refresh["n"] == 1:
            return httpx.Response(200, json=token_json(f"at-{refresh['n']}", rt="rt-2"))
        return httpx.Response(400, json={"error": "invalid_grant"})

    def events(r: httpx.Request) -> httpx.Response:
        connections.append(r)
        if len(connections) == 1:
            body = (
                "retry: 10\n\n: ping\n\n"
                'id: 5\nevent: user.updated\ndata: {"id":"evt_5","type":"user.updated","data":{"sub":"u","nickname":"N","profile_version":7}}\n\n'
                "event: token_expired\ndata: {}\n\n"
            )
        else:
            body = 'id: 6\nevent: user.password_changed\ndata: {"id":"evt_6","data":{"sub":"u"}}\n\n'
        return httpx.Response(200, content=body.encode(), headers={"Content-Type": "text/event-stream"})

    server.route("POST", "/oauth/token", token)
    server.route("GET", "/api/v1/me/events", events)
    now = time.time()
    changed: list[dict[str, Any]] = []
    expired: list[Exception] = []
    s = make(server).session(
        TokenSet(access_token="at-0", expires_at=now + 500, refresh_token="rt-1", issued_at=now),
        on_profile_changed=changed.append,
        on_session_expired=expired.append,
    )
    got = []
    with pytest.raises(SessionExpired):
        for ev in s.events():
            got.append(ev)
    assert [e.event for e in got] == ["user.updated"]
    assert changed and changed[-1]["nickname"] == "N" and s.profile_version == 7
    first, second = connections
    assert first.headers["authorization"] == "Bearer at-0" and "last-event-id" not in first.headers
    assert first.headers["accept"] == "text/event-stream" and "access_token" not in str(first.url)
    # token_expired -> refreshed and reconnected immediately with Last-Event-ID
    assert second.headers["authorization"] == "Bearer at-1" and second.headers["last-event-id"] == "5"
    # password_changed -> refresh attempt -> invalid_grant -> SessionExpired, store cleared
    assert s.tokens is None and len(expired) == 1


async def test_async_sse_consumer(server: FakeServer) -> None:
    connections: list[httpx.Request] = []

    def events(r: httpx.Request) -> httpx.Response:
        connections.append(r)
        if len(connections) == 1:
            return httpx.Response(503, json={"error": "temporarily_unavailable"})
        body = 'retry: 5\n\nid: 9\nevent: resync\ndata: {}\n\nid: 10\nevent: user.updated\ndata: {"data":{"nickname":"Z","profile_version":2}}\n\n'
        return httpx.Response(200, content=body.encode())

    server.route("GET", "/api/v1/me/events", events)
    server.route("GET", "/api/v1/me", lambda r: httpx.Response(200, json={"sub": "u", "nickname": "Y", "profile_version": 1}))
    sso = AsyncMoonSSO(ISSUER, "app", "secret", http_client=server.async_client())
    now = time.time()
    s = sso.session(TokenSet(access_token="at", expires_at=now + 500, refresh_token="rt", issued_at=now))
    import moon_sso.sse as sse_mod

    orig = sse_mod.ReconnectPolicy.delay
    sse_mod.ReconnectPolicy.delay = lambda self, retry_ms: 0.01  # type: ignore[method-assign]
    try:
        got = []
        async for ev in s.events():
            got.append(ev.event)
            if ev.event == "user.updated":
                break
    finally:
        sse_mod.ReconnectPolicy.delay = orig  # type: ignore[method-assign]
    assert got == ["resync", "user.updated"] and len(connections) == 2
    assert s.profile and s.profile["nickname"] == "Z" and s.profile_version == 2

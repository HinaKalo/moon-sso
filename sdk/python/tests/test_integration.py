"""Integration tests against the local Moon SSO testbed (see docs/sdk-spec.md §8)."""

from __future__ import annotations

import secrets
import struct
import threading
import time
import zlib
from typing import Any
from urllib.parse import parse_qsl

import pytest

from moon_sso import (
    AsyncMoonSSO,
    LogoutTokenError,
    MoonSSO,
    MoonSSOError,
    OtpRequired,
    SessionExpired,
    UserSession,
    WebhookVerifier,
)
from tests.conftest import ALICE, BOB, BOB_TOTP, TESTBED, WEB_ID, WEB_REDIRECT, WEB_SECRET, Receiver, Testbed

pytestmark = pytest.mark.integration

WRITE_SCOPE = "openid profile offline_access profile:write password:write"


def png(size: int = 32, rgb: tuple[int, int, int] = (200, 30, 90)) -> bytes:
    raw = b"".join(b"\x00" + bytes(rgb) * size for _ in range(size))

    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", size, size, 8, 2, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b"")


def web_client(**kw: Any) -> MoonSSO:
    return MoonSSO(TESTBED, WEB_ID, WEB_SECRET, redirect_uri=WEB_REDIRECT, **kw)


def web_login(tb: Testbed, sso: MoonSSO, username: str, password: str, scope: str | None = None) -> tuple[Any, str]:
    req = sso.authorization_request(scope=scope)
    out = tb.authorize(req.url, username, password)
    tokens = sso.handle_callback(out["redirect"], req)
    return tokens, out["session_token"]


def otp_login(tb: Testbed, sso: MoonSSO, username: str, password: str, secret: str = BOB_TOTP) -> Any:
    """First-party login with OTP; tolerates other suites consuming the same TOTP step."""
    with pytest.raises(OtpRequired) as ei:
        sso.login_with_password(username, password)
    pending = ei.value
    assert pending.required == "otp" and pending.auth_session
    last_err: Exception | None = None
    for _ in range(5):
        try:
            return sso.submit_otp(pending, tb.totp(secret))
        except OtpRequired as exc:  # code already used in this 30 s step (replay protection)
            pending, last_err = exc, exc
        except MoonSSOError as exc:
            if exc.error != "slow_down":
                raise
            last_err = exc
        time.sleep(31 - (time.time() % 30))
    raise AssertionError(f"OTP step kept failing: {last_err}")


# ---- web login ----


def test_web_login_callback_get_me(testbed: Testbed) -> None:
    with web_client() as sso:
        meta = sso.metadata()
        assert meta.issuer == TESTBED and meta.iss_parameter_supported
        tokens, _ = web_login(testbed, sso, *ALICE)
        assert tokens.refresh_token and tokens.id_token and tokens.id_claims
        assert tokens.id_claims["preferred_username"] == "alice" and tokens.id_claims["aud"] == WEB_ID
        claims = sso.verify_access_token(tokens.access_token)
        assert claims.sub == tokens.sub and claims.client_id == WEB_ID and not claims.is_client_token
        session = sso.session(tokens)
        me = session.get_me()
        assert me["preferred_username"] == "alice" and me["sub"] == tokens.sub and "profile_version" in me
        assert session.get_me() == me  # 304 path with the cached ETag
        info = session.userinfo()
        assert info["sub"] == me["sub"]


def test_callback_replay_and_tamper_rejected(testbed: Testbed) -> None:
    with web_client() as sso:
        req = sso.authorization_request()
        out = testbed.authorize(req.url, *ALICE)
        params = dict(parse_qsl(out["redirect"].split("?", 1)[1]))
        bad = dict(params, state="x" * 43)
        with pytest.raises(MoonSSOError, match="state"):
            sso.handle_callback(bad, req)
        sso.handle_callback(params, req)
        with pytest.raises(MoonSSOError) as ei:  # code is single-use
            sso.handle_callback(params, req)
        assert ei.value.error == "invalid_grant"


# ---- refresh rotation ----


def test_refresh_rotation_and_grace(testbed: Testbed) -> None:
    with web_client() as sso:
        tokens, _ = web_login(testbed, sso, *ALICE)
        first = sso.refresh_tokens(tokens.refresh_token or "", expected_sub=tokens.sub)
        assert first.refresh_token and first.refresh_token != tokens.refresh_token
        # The server only re-issues an ID token on refresh when the profile
        # changed (spec §1.1); when present it must belong to the same user.
        assert first.id_claims is None or first.id_claims["sub"] == tokens.sub
        # Re-presenting the rotated token within 60 s returns the same successor.
        again = sso.refresh_tokens(tokens.refresh_token or "")
        assert again.refresh_token == first.refresh_token


def test_concurrent_refresh_converges(testbed: Testbed) -> None:
    with web_client() as sso:
        tokens, _ = web_login(testbed, sso, *ALICE)

        # (1) one session, many threads: single-flight -> exactly one refresh request
        shared = sso.session(tokens)
        start = threading.Barrier(8)
        results: list[str] = []

        def forced() -> None:
            stale = tokens.access_token
            start.wait()
            results.append(shared.get_access_token(force_refresh=True, stale_token=stale))

        threads = [threading.Thread(target=forced) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert shared.refresh_count == 1 and len(set(results)) == 1

        # (2) independent sessions (think: processes) refreshing the same token at once
        base = shared.tokens
        assert base is not None
        sessions: list[UserSession] = [sso.session(type(base).from_dict(base.to_dict())) for _ in range(6)]
        barrier = threading.Barrier(len(sessions))
        errors: list[BaseException] = []

        def refresh(s: UserSession) -> None:
            barrier.wait()
            try:
                s.refresh()
            except BaseException as exc:  # pragma: no cover - reported below
                errors.append(exc)

        threads = [threading.Thread(target=refresh, args=(s,)) for s in sessions]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors, errors
        rts = {s.tokens.refresh_token for s in sessions if s.tokens}
        assert len(rts) == 1 and base.refresh_token not in rts
        # The converged token is the live one.
        sessions[0].refresh()
        assert sessions[0].get_me()["sub"] == tokens.sub


def test_revoked_refresh_token_is_session_expired(testbed: Testbed) -> None:
    with web_client() as sso:
        tokens, _ = web_login(testbed, sso, *ALICE)
        expired: list[Exception] = []
        session = sso.session(tokens, on_session_expired=expired.append)
        end_url = session.logout(post_logout_redirect_uri="http://127.0.0.1:18700/")
        assert end_url and "id_token_hint=" in end_url
        assert session.tokens is None
        with pytest.raises(SessionExpired):
            sso.refresh_tokens(tokens.refresh_token or "")
        again = sso.session(tokens, on_session_expired=expired.append)
        with pytest.raises(SessionExpired):
            again.refresh()
        assert again.tokens is None and len(expired) == 1


# ---- client credentials + changes feed ----


def test_client_credentials_and_changes_feed(testbed: Testbed) -> None:
    with web_client() as sso:
        cc = sso.client_credentials()
        assert cc.access_token == sso.client_credentials_token() and "users:sync" in cc.scopes
        assert sso.verify_access_token(cc.access_token).is_client_token
        watermark = sso.list_users(limit=1).watermark
        username, password = testbed.create_user()
        tokens, _ = web_login(testbed, sso, username, password)
        new_name = "Feed " + secrets.token_hex(3)
        testbed.set_display_name(username, new_name)

        found: dict[str, Any] | None = None
        cursor = watermark
        deadline = time.monotonic() + 20
        while found is None and time.monotonic() < deadline:
            page = sso.sync_changes(cursor, limit=100)
            for ev in page.events:
                if ev["data"].get("sub") == tokens.sub and ev["type"] == "user.updated":
                    found = ev
            cursor = page.next_cursor or cursor
            if found is None and not page.has_more:
                time.sleep(0.5)
        assert found is not None, "user.updated not in the change feed"
        assert found["data"]["nickname"] == new_name and int(found["seq"]) > int(watermark)
        assert found["id"] == f"evt_{found['seq']}"

        # iter_changes from the watermark yields the same event and an advancing cursor
        seen = []
        for batch in sso.iter_changes(watermark, limit=200):
            assert not batch.full_sync and batch.cursor
            seen.extend(e["id"] for e in batch.events)
        assert found["id"] in seen
        assert sso.get_user(tokens.sub or "")["nickname"] == new_name


def test_full_sync_watermark(testbed: Testbed) -> None:
    with web_client() as sso:
        pages = list(sso.full_sync(limit=500))
        assert pages and pages[0].watermark.isdigit()
        assert all("sub" in u and "status" in u for p in pages for u in p.users)


# ---- DCR + webhook + back-channel logout ----


def test_dcr_registration_fields(dcr_client: Any) -> None:
    assert dcr_client.client_id and dcr_client.client_secret and dcr_client.registration_access_token
    assert dcr_client.status == "active" and dcr_client.registration_client_uri.endswith(dcr_client.client_id)
    assert dcr_client.raw["redirect_uris"] == [WEB_REDIRECT]
    assert "secret" not in repr(dcr_client)


def test_webhook_delivery_verified(testbed: Testbed, receiver: Receiver, dcr_client: Any) -> None:
    reg = dcr_client
    secret = testbed.set_webhook(reg.client_id, receiver.url + "/hook")
    verifier = WebhookVerifier(secret)
    with MoonSSO(TESTBED, reg.client_id, reg.client_secret, redirect_uri=WEB_REDIRECT) as sso:
        username, password = testbed.create_user()
        tokens, _ = web_login(testbed, sso, username, password)
        new_name = "Hook " + secrets.token_hex(3)
        testbed.set_display_name(username, new_name)

        def matches(c: Any) -> bool:
            ev = verifier.verify(c.body, c.headers)  # every delivery must verify
            return ev.type == "user.updated" and ev.sub == tokens.sub

        captured = receiver.wait(matches, timeout=30)
        assert captured.path == "/hook"
        ev = WebhookVerifier(secret).verify(captured.body, captured.headers)
        assert ev.data["nickname"] == new_name and ev.webhook_id == ev.id and ev.profile_version
        assert ev.data["status"] == "active" and ev.data.get("changed") == ["display_name"]
        with pytest.raises(MoonSSOError):
            WebhookVerifier("whsec_" + "A" * 32).verify(captured.body, captured.headers)


def test_backchannel_logout_token_verified(testbed: Testbed, receiver: Receiver, dcr_client: Any) -> None:
    reg = dcr_client
    testbed.set_backchannel(reg.client_id, receiver.url + "/bcl")
    with MoonSSO(TESTBED, reg.client_id, reg.client_secret, redirect_uri=WEB_REDIRECT) as sso:
        username, password = testbed.create_user()
        tokens, session_token = web_login(testbed, sso, username, password)
        testbed.logout(session_token)
        captured = receiver.wait(lambda c: c.path == "/bcl", timeout=30)
        form = dict(parse_qsl(captured.body.decode()))
        lt = sso.verify_logout_token(form["logout_token"])
        assert lt.sub == tokens.sub and lt.sid == (tokens.id_claims or {}).get("sid")
        with pytest.raises(LogoutTokenError, match="replay"):
            sso.verify_logout_token(form["logout_token"])
        other = MoonSSO(TESTBED, WEB_ID, WEB_SECRET)
        with pytest.raises(LogoutTokenError, match="aud"):
            other.verify_logout_token(form["logout_token"])
        other.close()


# ---- first-party login ----


def test_first_party_challenge_bob_otp_dpop(testbed: Testbed) -> None:
    with MoonSSO(TESTBED, "test-native-dpop") as sso:
        assert sso.dpop_key is not None
        tokens = otp_login(testbed, sso, *BOB)
        assert tokens.id_claims and tokens.id_claims["preferred_username"] == "bob"
        assert "otp" in tokens.id_claims.get("amr", [])
        session = sso.session(tokens)
        me = session.get_me()
        assert me["preferred_username"] == "bob" and me["totp_enabled"] is True
        before = tokens.refresh_token
        session.refresh()  # DPoP-bound refresh token, nonce handled transparently
        assert session.tokens and session.tokens.refresh_token != before
        # The refresh token is bound to this key: another key cannot use it.
        with MoonSSO(TESTBED, "test-native-dpop") as other:
            with pytest.raises(MoonSSOError) as ei:
                other.refresh_tokens(session.tokens.refresh_token or "")
            assert ei.value.error == "invalid_dpop_proof"


def test_first_party_without_otp_and_wrong_password(testbed: Testbed) -> None:
    with MoonSSO(TESTBED, "test-native") as sso:
        tokens = sso.login_with_password(*ALICE)
        assert tokens.id_claims and tokens.id_claims["preferred_username"] == "alice"
        with pytest.raises(MoonSSOError) as ei:
            sso.login_with_password("alice", "definitely-wrong-password")
        assert ei.value.error == "access_denied" and ei.value.status == 403


def test_native_and_server_registration(testbed: Testbed) -> None:
    with MoonSSO(TESTBED, "test-native") as sso:
        info = sso.registration_info()
        assert info["registration_open"] is True
        username = "t_" + secrets.token_hex(4)
        tokens = sso.native_register(username, "Native-Reg-Pass-123", display_name="Native")
        assert tokens.id_claims and tokens.id_claims["preferred_username"] == username
        with pytest.raises(MoonSSOError) as ei:
            sso.native_register("x", "short")
        assert ei.value.status == 422 and ei.value.field
    with web_client() as web:
        username = "t_" + secrets.token_hex(4)
        out = web.register_user(username, "Server-Reg-Pass-123", display_name="Server")
        assert out["created"] is True and out["login_hint"] == username
        with pytest.raises(MoonSSOError) as ei2:
            web.register_user(username, "Server-Reg-Pass-123")
        assert ei2.value.status == 422 and ei2.value.field == "username"


# ---- account API ----


def test_profile_avatar_password(testbed: Testbed) -> None:
    username, password = testbed.create_user()
    changes: list[dict[str, Any]] = []
    with web_client() as sso:
        tokens, _ = web_login(testbed, sso, username, password, scope=WRITE_SCOPE)
        session = sso.session(tokens, on_profile_changed=changes.append)
        before = session.get_me()
        name = "Py " + secrets.token_hex(3)
        updated = session.update_profile(display_name=name, if_match=True)
        assert updated["nickname"] == name and updated["profile_version"] > before["profile_version"]
        assert session.get_me(use_cache=False)["nickname"] == name
        assert changes and changes[-1]["nickname"] == name
        with pytest.raises(MoonSSOError) as ei:
            session.update_profile(display_name="stale", if_match=f'"pv-{before["profile_version"]}"')
        assert ei.value.status == 412 and ei.value.error == "version_conflict"

        with_pic = session.upload_avatar(png())
        assert with_pic["picture"] and with_pic["picture"].endswith(".jpg")
        assert session.delete_avatar()["picture"] is None

        new_password = "Changed-Pass-" + secrets.token_hex(4)
        assert session.change_password(password, new_password)["changed"] is True
        session.refresh()  # this device stays signed in
        assert session.get_me()["preferred_username"] == username
        with pytest.raises(MoonSSOError):
            session.change_password("wrong-current", "Another-Pass-123456")


def test_sse_profile_events(testbed: Testbed) -> None:
    username, password = testbed.create_user()
    with web_client() as sso:
        tokens, _ = web_login(testbed, sso, username, password)
        session = sso.session(tokens)
        session.get_me()
        got: list[Any] = []
        ready = threading.Event()

        def consume() -> None:
            try:
                for ev in session.events():
                    got.append(ev)
                    if ev.event == "user.updated":
                        session.stop_events()
                        return
            except Exception as exc:  # pragma: no cover - surfaced by the assertion below
                got.append(exc)

        t = threading.Thread(target=consume, daemon=True)
        t.start()
        time.sleep(1.0)  # let the stream connect
        ready.set()
        new_name = "Live " + secrets.token_hex(3)
        testbed.set_display_name(username, new_name)
        t.join(timeout=20)
        session.stop_events()
        events = [e for e in got if not isinstance(e, Exception)]
        assert events and events[-1].event == "user.updated", got
        assert events[-1].id and events[-1].json()["data"]["nickname"] == new_name
        assert session.profile and session.profile["nickname"] == new_name


# ---- async client ----


async def test_async_web_login_refresh_me(testbed: Testbed) -> None:
    async with AsyncMoonSSO(TESTBED, WEB_ID, WEB_SECRET, redirect_uri=WEB_REDIRECT) as sso:
        req = await sso.authorization_request()
        out = testbed.authorize(req.url, *ALICE)
        tokens = await sso.handle_callback(out["redirect"], req)
        session = sso.session(tokens)
        me = await session.get_me()
        assert me["preferred_username"] == "alice"
        import asyncio

        stale = tokens.access_token
        results = await asyncio.gather(*[session.get_access_token(force_refresh=True, stale_token=stale) for _ in range(6)])
        assert len(set(results)) == 1 and session.refresh_count == 1
        cc = await sso.client_credentials()
        page = await sso.sync_changes((await sso.list_users(limit=1)).watermark)
        assert cc.access_token and page.next_cursor

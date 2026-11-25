"""FastAPI adapter smoke tests (TestClient) against the testbed."""

from __future__ import annotations

import base64
import json
import time
from urllib.parse import parse_qsl, urlsplit

import pytest

pytest.importorskip("fastapi")

from fastapi import Depends, FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from moon_sso import AsyncMoonSSO, MoonSSO, sign_webhook  # noqa: E402
from moon_sso.contrib.fastapi import MoonSSOFastAPI  # noqa: E402
from tests.conftest import ALICE, TESTBED, WEB_ID, WEB_REDIRECT, WEB_SECRET, Testbed  # noqa: E402

pytestmark = pytest.mark.integration

SECRET = "whsec_" + base64.b64encode(b"f" * 32).decode()


def build() -> tuple[FastAPI, MoonSSOFastAPI, list]:
    sso = AsyncMoonSSO(TESTBED, WEB_ID, WEB_SECRET, redirect_uri=WEB_REDIRECT)
    received: list = []
    auth = MoonSSOFastAPI(sso, webhook_secret=SECRET, on_webhook=received.append)
    app = FastAPI()
    auth.init_app(app, prefix="/auth")

    @app.get("/private")
    async def private(user=Depends(auth.require_user)):  # type: ignore[no-untyped-def]
        me = await user.session.get_me()
        return {"sub": user.sub, "username": me["preferred_username"]}

    @app.get("/api/data")
    async def api(claims=Depends(auth.require_bearer(scopes=["profile"]))):  # type: ignore[no-untyped-def]
        return {"sub": claims.sub}

    @app.get("/api/admin")
    async def admin(claims=Depends(auth.require_bearer(scopes=["admin"]))):  # type: ignore[no-untyped-def]
        return {}

    return app, auth, received


def test_fastapi_login_redirects_and_htmx(testbed: Testbed) -> None:
    app, auth, _ = build()
    with TestClient(app, follow_redirects=False) as c:
        r = c.get("/private", headers={"Accept": "text/html"})
        assert r.status_code == 302 and r.headers["location"] == "/auth/login?return_to=%2Fprivate"
        r = c.get("/private", headers={"HX-Request": "true"})
        assert r.status_code == 200 and r.headers["HX-Redirect"].startswith("/auth/login")
        r = c.get("/private", headers={"Accept": "application/json"})
        assert r.status_code == 401 and r.json()["error"] == "login_required"

        r = c.get("/auth/login", params={"return_to": "/private"})
        assert r.status_code == 302 and r.headers["location"].startswith(TESTBED + "/oauth/authorize?")
        assert "moon_sso_session" in r.cookies or "moon_sso_session" in c.cookies
        r = c.get("/auth/login", headers={"HX-Request": "true"})
        assert r.status_code == 200 and r.headers["HX-Redirect"].startswith(TESTBED + "/oauth/authorize?")


def test_fastapi_full_login_and_logout(testbed: Testbed) -> None:
    app, auth, _ = build()
    with TestClient(app, follow_redirects=False) as c:
        r = c.get("/auth/login", params={"return_to": "/private"})
        out = testbed.authorize(r.headers["location"], *ALICE)
        query = urlsplit(out["redirect"]).query
        r = c.get("/auth/callback?" + query)
        assert r.status_code == 302 and r.headers["location"] == "/private", r.text
        r = c.get("/private")
        assert r.status_code == 200 and r.json()["username"] == "alice"
        # the callback cannot be replayed
        assert c.get("/auth/callback?" + query).status_code == 400
        r = c.post("/auth/logout", headers={"HX-Request": "true"})
        assert r.status_code == 200 and r.headers["HX-Redirect"] == "/"
        c.cookies.clear()
        assert c.get("/private", headers={"Accept": "application/json"}).status_code == 401


def test_fastapi_bearer_webhook_backchannel(testbed: Testbed) -> None:
    app, auth, received = build()
    with MoonSSO(TESTBED, WEB_ID, WEB_SECRET, redirect_uri=WEB_REDIRECT) as sync_sso:
        req = sync_sso.authorization_request()
        tokens = sync_sso.handle_callback(testbed.authorize(req.url, *ALICE)["redirect"], req)
    with TestClient(app) as c:
        assert c.get("/api/data").status_code == 401
        assert c.get("/api/data", headers={"Authorization": "Bearer junk"}).status_code == 401
        r = c.get("/api/data", headers={"Authorization": f"Bearer {tokens.access_token}"})
        assert r.status_code == 200 and r.json()["sub"] == tokens.sub
        r = c.get("/api/admin", headers={"Authorization": f"Bearer {tokens.access_token}"})
        assert r.status_code == 403 and "insufficient_scope" in r.headers["www-authenticate"]

        body = json.dumps({"id": "evt_1", "seq": 1, "type": "user.updated", "data": {"sub": "s"}})
        ts = int(time.time())
        headers = {"webhook-id": "evt_1", "webhook-timestamp": str(ts), "webhook-signature": sign_webhook(SECRET, "evt_1", ts, body)}
        assert c.post("/auth/webhook", content=body, headers=headers).status_code == 200
        assert c.post("/auth/webhook", content=body, headers=headers).status_code == 200  # duplicate ignored
        assert len(received) == 1 and received[0].type == "user.updated"
        bad = dict(headers, **{"webhook-signature": "v1,AAAA"})
        assert c.post("/auth/webhook", content=body, headers=bad).status_code == 400

        r = c.post("/auth/backchannel-logout", data={"logout_token": tokens.id_token or ""})
        assert r.status_code == 400 and r.headers["cache-control"] == "no-store"
        assert c.post("/auth/backchannel-logout", data={}).status_code == 400


def test_fastapi_callback_state_mismatch(testbed: Testbed) -> None:
    app, _, _ = build()
    with TestClient(app, follow_redirects=False) as c:
        r = c.get("/auth/login")
        q = dict(parse_qsl(urlsplit(r.headers["location"]).query))
        r = c.get("/auth/callback", params={"code": "x", "state": "wrong-" + q["state"], "iss": TESTBED})
        assert r.status_code == 400 and r.json()["error"] == "invalid_state"

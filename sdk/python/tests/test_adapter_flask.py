"""Flask adapter smoke tests (test client) against the testbed."""

from __future__ import annotations

import base64
import json
import time
from urllib.parse import urlsplit

import pytest

pytest.importorskip("flask")

from flask import Flask, jsonify  # noqa: E402

from moon_sso import MoonSSO, sign_webhook  # noqa: E402
from moon_sso.contrib.flask import MoonSSOFlask, current_user  # noqa: E402
from tests.conftest import ALICE, TESTBED, WEB_ID, WEB_REDIRECT, WEB_SECRET, Testbed  # noqa: E402

pytestmark = pytest.mark.integration

SECRET = "whsec_" + base64.b64encode(b"g" * 32).decode()


def build() -> tuple[Flask, MoonSSOFlask, list]:
    sso = MoonSSO(TESTBED, WEB_ID, WEB_SECRET, redirect_uri=WEB_REDIRECT)
    app = Flask(__name__)
    received: list = []
    auth = MoonSSOFlask(sso, app, url_prefix="/auth", webhook_secret=SECRET, on_webhook=received.append)

    @app.get("/private")
    @auth.login_required
    def private():  # type: ignore[no-untyped-def]
        user = current_user()
        assert user is not None
        return jsonify(sub=user.sub, username=user.session.get_me()["preferred_username"])

    @app.get("/api/data")
    @auth.bearer_required(scopes=["profile"])
    def api():  # type: ignore[no-untyped-def]
        return jsonify(sub=auth.bearer_claims().sub)

    @app.get("/api/admin")
    @auth.bearer_required(scopes=["admin"])
    def admin():  # type: ignore[no-untyped-def]
        return jsonify()

    return app, auth, received


def test_flask_login_redirect_htmx_and_full_flow(testbed: Testbed) -> None:
    app, _, _ = build()
    c = app.test_client()
    r = c.get("/private", headers={"Accept": "text/html"})
    assert r.status_code == 302 and r.headers["Location"].startswith("/auth/login?return_to=")
    r = c.get("/private", headers={"HX-Request": "true"})
    assert r.status_code == 200 and r.headers["HX-Redirect"].startswith("/auth/login")
    assert c.get("/private").status_code == 401

    r = c.get("/auth/login?return_to=/private")
    assert r.status_code == 302 and r.headers["Location"].startswith(TESTBED + "/oauth/authorize?")
    r2 = c.get("/auth/login", headers={"HX-Request": "true"})
    assert r2.status_code == 200 and r2.headers["HX-Redirect"].startswith(TESTBED)
    r = c.get("/auth/login?return_to=/private")
    out = testbed.authorize(r.headers["Location"], *ALICE)
    r = c.get("/auth/callback?" + urlsplit(out["redirect"]).query)
    assert r.status_code == 302 and r.headers["Location"].endswith("/private"), r.data
    r = c.get("/private")
    assert r.status_code == 200 and r.get_json()["username"] == "alice"
    r = c.post("/auth/logout")
    assert r.status_code == 302
    assert c.get("/private").status_code == 401


def test_flask_bearer_and_webhook(testbed: Testbed) -> None:
    app, auth, received = build()
    req = auth.sso.authorization_request()
    tokens = auth.sso.handle_callback(testbed.authorize(req.url, *ALICE)["redirect"], req)
    c = app.test_client()
    assert c.get("/api/data").status_code == 401
    r = c.get("/api/data", headers={"Authorization": f"Bearer {tokens.access_token}"})
    assert r.status_code == 200 and r.get_json()["sub"] == tokens.sub
    assert c.get("/api/admin", headers={"Authorization": f"Bearer {tokens.access_token}"}).status_code == 403

    body = json.dumps({"id": "evt_9", "seq": 9, "type": "user.updated", "data": {"sub": "s"}})
    ts = int(time.time())
    headers = {"webhook-id": "evt_9", "webhook-timestamp": str(ts), "webhook-signature": sign_webhook(SECRET, "evt_9", ts, body)}
    assert c.post("/auth/webhook", data=body, headers=headers).status_code == 200
    assert received and received[0].seq == 9
    assert c.post("/auth/webhook", data=body + " ", headers=headers).status_code == 400
    assert c.post("/auth/backchannel-logout", data={"logout_token": "a.b.c"}).status_code == 400

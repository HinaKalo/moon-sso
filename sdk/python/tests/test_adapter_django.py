"""Django adapter smoke tests (test client) against the testbed."""

from __future__ import annotations

import base64
import json
import time
from urllib.parse import urlsplit

import pytest

pytest.importorskip("django")

import django  # noqa: E402
from django.conf import settings  # noqa: E402

from tests.conftest import ALICE, TESTBED, WEB_ID, WEB_REDIRECT, WEB_SECRET, Testbed  # noqa: E402

SECRET = "whsec_" + base64.b64encode(b"d" * 32).decode()
RECEIVED: list = []

if not settings.configured:
    settings.configure(
        DEBUG=False,
        SECRET_KEY="moon-sso-sdk-tests-not-secret",
        ALLOWED_HOSTS=["testserver"],
        ROOT_URLCONF=__name__,
        INSTALLED_APPS=["django.contrib.contenttypes", "django.contrib.sessions"],
        MIDDLEWARE=[
            "django.contrib.sessions.middleware.SessionMiddleware",
            "moon_sso.contrib.django.middleware.MoonSSOMiddleware",
        ],
        SESSION_ENGINE="django.contrib.sessions.backends.cache",
        CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
        MOON_SSO={
            "ISSUER": TESTBED,
            "CLIENT_ID": WEB_ID,
            "CLIENT_SECRET": WEB_SECRET,
            "REDIRECT_URI": WEB_REDIRECT,
            "WEBHOOK_SECRET": SECRET,
            "WEBHOOK_HANDLER": RECEIVED.append,
        },
        USE_TZ=True,
    )
    django.setup()

from django.http import JsonResponse  # noqa: E402
from django.test import Client  # noqa: E402
from django.urls import include, path  # noqa: E402

from moon_sso import sign_webhook  # noqa: E402
from moon_sso.contrib.django.conf import get_client  # noqa: E402
from moon_sso.contrib.django.decorators import bearer_required, login_required  # noqa: E402

pytestmark = pytest.mark.integration


@login_required
def private(request):  # type: ignore[no-untyped-def]
    user = request.moon_sso_user
    return JsonResponse({"sub": user.sub, "username": user.session.get_me()["preferred_username"]})


@bearer_required(scopes=["profile"])
def api(request):  # type: ignore[no-untyped-def]
    return JsonResponse({"sub": request.moon_sso_claims.sub})


@bearer_required(scopes=["admin"])
def admin(request):  # type: ignore[no-untyped-def]
    return JsonResponse({})


urlpatterns = [
    path("auth/", include("moon_sso.contrib.django.urls")),
    path("private", private),
    path("api/data", api),
    path("api/admin", admin),
]


def test_django_login_redirect_htmx_and_full_flow(testbed: Testbed) -> None:
    c = Client()
    r = c.get("/private", HTTP_ACCEPT="text/html")
    assert r.status_code == 302 and r["Location"].startswith("/auth/login?return_to=")
    r = c.get("/private", HTTP_HX_REQUEST="true")
    assert r.status_code == 200 and r["HX-Redirect"].startswith("/auth/login")
    assert c.get("/private").status_code == 401

    r = c.get("/auth/login", {"return_to": "/private"}, HTTP_HX_REQUEST="true")
    assert r.status_code == 200 and r["HX-Redirect"].startswith(TESTBED + "/oauth/authorize?")
    r = c.get("/auth/login", {"return_to": "/private"})
    assert r.status_code == 302 and r["Location"].startswith(TESTBED + "/oauth/authorize?")
    out = testbed.authorize(r["Location"], *ALICE)
    r = c.get("/auth/callback?" + urlsplit(out["redirect"]).query)
    assert r.status_code == 302 and r["Location"] == "/private", r.content
    r = c.get("/private")
    assert r.status_code == 200 and r.json()["username"] == "alice"
    r = c.post("/auth/logout")
    assert r.status_code == 302 and r["Location"] == "/"
    assert c.get("/private").status_code == 401


def test_django_bearer_and_webhook(testbed: Testbed) -> None:
    sso = get_client()
    req = sso.authorization_request()
    tokens = sso.handle_callback(testbed.authorize(req.url, *ALICE)["redirect"], req)
    c = Client()
    assert c.get("/api/data").status_code == 401
    r = c.get("/api/data", HTTP_AUTHORIZATION=f"Bearer {tokens.access_token}")
    assert r.status_code == 200 and r.json()["sub"] == tokens.sub
    r = c.get("/api/admin", HTTP_AUTHORIZATION=f"Bearer {tokens.access_token}")
    assert r.status_code == 403 and "insufficient_scope" in r["WWW-Authenticate"]

    body = json.dumps({"id": "evt_5", "seq": 5, "type": "user.updated", "data": {"sub": "s"}})
    ts = int(time.time())
    sig = sign_webhook(SECRET, "evt_5", ts, body)
    r = c.post("/auth/webhook", body, content_type="application/json",
               HTTP_WEBHOOK_ID="evt_5", HTTP_WEBHOOK_TIMESTAMP=str(ts), HTTP_WEBHOOK_SIGNATURE=sig)
    assert r.status_code == 200 and RECEIVED and RECEIVED[-1].seq == 5
    r = c.post("/auth/webhook", body, content_type="application/json",
               HTTP_WEBHOOK_ID="evt_5", HTTP_WEBHOOK_TIMESTAMP=str(ts), HTTP_WEBHOOK_SIGNATURE="v1,AAAA")
    assert r.status_code == 400
    r = c.post("/auth/backchannel-logout", {"logout_token": "x.y.z"})
    assert r.status_code == 400 and r["Cache-Control"] == "no-store"

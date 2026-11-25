"""Django integration.

``settings.py``::

    INSTALLED_APPS += ["django.contrib.sessions"]
    MIDDLEWARE += ["moon_sso.contrib.django.middleware.MoonSSOMiddleware"]  # after SessionMiddleware
    MOON_SSO = {
        "ISSUER": "https://sso.moonl.cloud",
        "CLIENT_ID": "my-app",
        "CLIENT_SECRET": os.environ["MOON_SSO_SECRET"],
        "REDIRECT_URI": "https://app.example/auth/callback",
        "WEBHOOK_SECRET": os.environ.get("MOON_SSO_WEBHOOK_SECRET"),
        "WEBHOOK_HANDLER": "myapp.sso.on_webhook",
    }

``urls.py``::

    path("auth/", include("moon_sso.contrib.django.urls"))

Views::

    from moon_sso.contrib.django.decorators import login_required, bearer_required

Submodules import Django lazily, so importing :mod:`moon_sso` never needs Django.
"""

from __future__ import annotations

from typing import Any

__all__ = ["bearer_required", "get_client", "login_required"]


def __getattr__(name: str) -> Any:
    if name in ("bearer_required", "login_required"):
        from . import decorators

        return getattr(decorators, name)
    if name == "get_client":
        from .conf import get_client

        return get_client
    raise AttributeError(name)

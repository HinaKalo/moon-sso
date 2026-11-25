"""Middleware that sets ``request.moon_sso_user``."""

from __future__ import annotations

from typing import Callable

from django.core.exceptions import ImproperlyConfigured
from django.http import HttpRequest, HttpResponse

from .auth import K_TOKENS, get_user

__all__ = ["MoonSSOMiddleware"]


class MoonSSOMiddleware:
    """Add after ``django.contrib.sessions.middleware.SessionMiddleware``.

    ``request.moon_sso_user`` is a :class:`~moon_sso.contrib.WebUser` or
    ``None``. Anonymous requests cost nothing; signed-in requests refresh
    the access token transparently when it is about to expire.
    """

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        if not hasattr(request, "session"):
            raise ImproperlyConfigured("MoonSSOMiddleware requires SessionMiddleware before it")
        request.moon_sso_user = get_user(request) if request.session.get(K_TOKENS) else None  # type: ignore[attr-defined]
        return self.get_response(request)

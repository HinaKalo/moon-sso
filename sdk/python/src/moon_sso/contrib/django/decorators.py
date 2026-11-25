"""View decorators: browser login and bearer access tokens."""

from __future__ import annotations

import functools
from typing import Any, Callable, Iterable, TypeVar, cast
from urllib.parse import urlencode

from django.http import HttpRequest, HttpResponse, HttpResponseRedirect, JsonResponse
from django.urls import reverse

from ...errors import InsufficientScope, TokenValidationError
from .._web import is_htmx, safe_return_to, wants_html
from .auth import get_user
from .conf import get_client, get_setting

__all__ = ["bearer_required", "login_required", "login_url"]

F = TypeVar("F", bound=Callable[..., Any])


def login_url(return_to: str | None = None) -> str:
    base = get_setting("LOGIN_URL") or reverse("moon_sso:login")
    if return_to:
        return base + "?" + urlencode({"return_to": safe_return_to(return_to)})
    return str(base)


def login_required_response(request: HttpRequest) -> HttpResponse:
    url = login_url(request.get_full_path())
    if is_htmx(request.headers):
        resp = HttpResponse(status=200)
        resp["HX-Redirect"] = url
        return resp
    if wants_html(request.headers.get("Accept")):
        return HttpResponseRedirect(url)
    return JsonResponse({"error": "login_required", "error_description": "sign in first", "login_url": url}, status=401)


def login_required(view: F) -> F:
    """Require a browser login: 302 to login, ``HX-Redirect`` for HTMX, 401 JSON for APIs."""

    @functools.wraps(view)
    def wrapper(request: HttpRequest, *args: Any, **kwargs: Any) -> Any:
        user = getattr(request, "moon_sso_user", None)
        if user is None and not hasattr(request, "moon_sso_user"):
            user = get_user(request)
            request.moon_sso_user = user  # type: ignore[attr-defined]
        if user is None:
            return login_required_response(request)
        return view(request, *args, **kwargs)

    return cast(F, wrapper)


def _bearer_error(status: int, code: str, challenge: str) -> JsonResponse:
    resp = JsonResponse({"error": code}, status=status)
    resp["WWW-Authenticate"] = challenge
    return resp


def bearer_required(
    view: F | None = None, *, scopes: Iterable[str] = (), audience: str | Iterable[str] | None = None
) -> Any:
    """Require ``Authorization: Bearer <access token>``; claims in ``request.moon_sso_claims``."""
    required = tuple(scopes)

    def decorate(fn: F) -> F:
        @functools.wraps(fn)
        def wrapper(request: HttpRequest, *args: Any, **kwargs: Any) -> Any:
            header = request.headers.get("Authorization", "")
            if header[:7].lower() != "bearer " or not header[7:].strip():
                return _bearer_error(401, "invalid_request", 'Bearer realm="api"')
            try:
                claims = get_client().verify_access_token(header[7:].strip(), audience=audience, required_scopes=required)
            except InsufficientScope as exc:
                return _bearer_error(403, "insufficient_scope", f'Bearer error="insufficient_scope", scope="{" ".join(exc.required)}"')
            except TokenValidationError:
                return _bearer_error(401, "invalid_token", 'Bearer error="invalid_token"')
            request.moon_sso_claims = claims  # type: ignore[attr-defined]
            return fn(request, *args, **kwargs)

        return cast(F, wrapper)

    return decorate(view) if view is not None else decorate

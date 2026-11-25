"""Login, callback, logout, webhook and back-channel logout views."""

from __future__ import annotations

import logging
from typing import Any

from django.http import HttpRequest, HttpResponse, HttpResponseRedirect, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_http_methods, require_POST

from ...errors import AuthorizationResponseError, LogoutTokenError, MoonSSOError, TokenValidationError, WebhookVerificationError
from ...models import AuthorizationRequest
from ...webhooks import WebhookVerifier
from .._web import is_htmx, safe_return_to
from .auth import K_AUTH_REQUEST, DjangoSessionTokenStore, end_sessions, index_session, user_session
from .conf import get_client, get_handler, get_setting

__all__ = ["backchannel_logout", "callback", "login", "logout", "webhook"]

log = logging.getLogger("moon_sso")

_verifiers: dict[str, WebhookVerifier] = {}


def _redirect(request: HttpRequest, url: str) -> HttpResponse:
    if is_htmx(request.headers):
        resp = HttpResponse(status=200)
        resp["HX-Redirect"] = url
        return resp
    return HttpResponseRedirect(url)


@require_GET
def login(request: HttpRequest) -> HttpResponse:
    prompt = request.GET.get("prompt")
    req = get_client().authorization_request(
        prompt=prompt if prompt in ("login", "consent", "select_account", "none") else None,
        return_to=safe_return_to(request.GET.get("return_to"), get_setting("AFTER_LOGIN")),
    )
    request.session[K_AUTH_REQUEST] = req.to_dict()
    return _redirect(request, req.url)


@require_GET
def callback(request: HttpRequest) -> HttpResponse:
    raw = request.session.pop(K_AUTH_REQUEST, None)
    if not raw:
        return JsonResponse({"error": "invalid_request", "error_description": "no login in progress"}, status=400)
    try:
        auth_req = AuthorizationRequest.from_dict(raw)
        tokens = get_client().handle_callback(request.GET.dict(), auth_req)
    except AuthorizationResponseError as exc:
        return JsonResponse({"error": exc.error, "error_description": exc.error_description}, status=400)
    except MoonSSOError as exc:
        return JsonResponse({"error": exc.error, "error_description": exc.error_description}, status=502 if exc.retryable else 400)
    except (KeyError, TypeError, ValueError):
        return JsonResponse({"error": "invalid_request", "error_description": "corrupt login state"}, status=400)
    request.session.cycle_key()  # session fixation defence
    DjangoSessionTokenStore(request).save(tokens)
    index_session(request, tokens)
    handler = get_handler("LOGIN_HANDLER")
    if handler is not None:
        handler(request, tokens)
    return _redirect(request, safe_return_to(auth_req.return_to, get_setting("AFTER_LOGIN")))


@require_http_methods(["GET", "POST"])
def logout(request: HttpRequest) -> HttpResponse:
    target = get_setting("AFTER_LOGOUT")
    post_logout = get_setting("POST_LOGOUT_REDIRECT_URI")
    end_url = user_session(request).logout(post_logout_redirect_uri=post_logout)
    request.session.flush()
    if end_url and post_logout:
        target = end_url
    return _redirect(request, target)


@csrf_exempt
@require_POST
def webhook(request: HttpRequest) -> HttpResponse:
    secret = get_setting("WEBHOOK_SECRET")
    if not secret:
        return JsonResponse({"error": "not_configured"}, status=404)
    verifier = _verifiers.get(secret)
    if verifier is None:
        verifier = _verifiers.setdefault(secret, WebhookVerifier(secret))
    try:
        event = verifier.verify(request.body, request.headers)
    except WebhookVerificationError as exc:
        return JsonResponse({"error": exc.error, "error_description": exc.error_description}, status=400)
    handler = get_handler("WEBHOOK_HANDLER")
    if not event.duplicate and handler is not None:
        handler(event)
    return JsonResponse({"ok": True})


@csrf_exempt
@require_POST
def backchannel_logout(request: HttpRequest) -> HttpResponse:
    token = request.POST.get("logout_token")
    resp: Any
    if not token:
        resp = JsonResponse({"error": "invalid_request", "error_description": "missing logout_token"}, status=400)
    else:
        try:
            lt = get_client().verify_logout_token(token)
        except (LogoutTokenError, TokenValidationError) as exc:
            resp = JsonResponse({"error": "invalid_request", "error_description": exc.error_description}, status=400)
        except MoonSSOError as exc:
            resp = JsonResponse({"error": "temporarily_unavailable", "error_description": exc.error}, status=503)
        else:
            end_sessions(lt.sub, lt.sid)
            handler = get_handler("LOGOUT_HANDLER")
            if handler is not None:
                handler(lt.sub, lt.sid)
            resp = HttpResponse(status=200)
    resp["Cache-Control"] = "no-store"
    return resp  # type: ignore[no-any-return]

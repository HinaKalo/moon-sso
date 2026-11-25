"""Flask integration.

.. code-block:: python

    from flask import Flask
    from moon_sso import MoonSSO
    from moon_sso.contrib.flask import MoonSSOFlask, current_user

    sso = MoonSSO("https://sso.moonl.cloud", "my-app", "secret",
                  redirect_uri="https://app.example/auth/callback")
    app = Flask(__name__)
    auth = MoonSSOFlask(sso, app, url_prefix="/auth", webhook_secret="whsec_...")

    @app.get("/")
    @auth.login_required
    def home():
        return f"hello {current_user().name}"

    @app.get("/api/items")
    @auth.bearer_required(scopes=["items:read"])
    def items():
        claims = auth.bearer_claims()
"""

from __future__ import annotations

import functools
import logging
from typing import Any, Callable, Iterable, TypeVar, cast
from urllib.parse import urlencode

from flask import Blueprint, Flask, Response, current_app, g, jsonify, make_response, redirect, request

from ..client import MoonSSO
from ..errors import (
    AuthorizationResponseError,
    InsufficientScope,
    LogoutTokenError,
    MoonSSOError,
    SessionExpired,
    TokenValidationError,
    WebhookVerificationError,
)
from ..models import AccessTokenClaims
from ..session import UserSession
from ..webhooks import WebhookVerifier
from ._web import (
    LRU,
    SESSION_AUTH_REQUEST,
    MemorySessionStore,
    SessionStore,
    StoreTokenAdapter,
    WebUser,
    auth_request_from,
    is_htmx,
    new_session_id,
    safe_return_to,
    wants_html,
)

__all__ = ["MoonSSOFlask", "current_user"]

log = logging.getLogger("moon_sso")

F = TypeVar("F", bound=Callable[..., Any])

_EXT_KEY = "moon_sso"


def current_user() -> WebUser[UserSession] | None:
    """The signed-in user of the current request (``None`` when anonymous)."""
    ext = cast("MoonSSOFlask", current_app.extensions[_EXT_KEY])
    return ext.optional_user()


class MoonSSOFlask:
    """Flask extension: blueprint with login/callback/logout/webhook/back-channel routes and decorators."""

    def __init__(
        self,
        sso: MoonSSO,
        app: Flask | None = None,
        *,
        url_prefix: str = "/auth",
        session_store: SessionStore | None = None,
        cookie_name: str = "moon_sso_session",
        cookie_secure: bool | None = None,
        cookie_samesite: str = "Lax",
        cookie_domain: str | None = None,
        redirect_uri: str | None = None,
        scope: str | None = None,
        after_login: str = "/",
        after_logout: str = "/",
        post_logout_redirect_uri: str | None = None,
        webhook_secret: str | None = None,
        on_webhook: Callable[..., Any] | None = None,
        on_logout: Callable[[str | None, str | None], Any] | None = None,
        on_login: Callable[..., Any] | None = None,
    ) -> None:
        self.sso = sso
        self.url_prefix = url_prefix.rstrip("/")
        self.store: SessionStore = session_store if session_store is not None else MemorySessionStore()
        self.cookie_name = cookie_name
        ruri = redirect_uri or sso.redirect_uri
        self.redirect_uri = ruri
        self.cookie_secure = cookie_secure if cookie_secure is not None else bool(ruri and ruri.startswith("https://"))
        self.cookie_samesite = cookie_samesite
        self.cookie_domain = cookie_domain
        self.scope = scope
        self.after_login = after_login
        self.after_logout = after_logout
        self.post_logout_redirect_uri = post_logout_redirect_uri
        self.webhook = WebhookVerifier(webhook_secret) if webhook_secret else None
        self.on_webhook = on_webhook
        self.on_logout = on_logout
        self.on_login = on_login
        self._sessions: LRU[UserSession] = LRU()
        self.blueprint = self._build_blueprint()
        if app is not None:
            self.init_app(app)

    def init_app(self, app: Flask) -> None:
        app.extensions[_EXT_KEY] = self
        app.register_blueprint(self.blueprint, url_prefix=self.url_prefix)

    # ---- helpers ----

    @property
    def login_path(self) -> str:
        return self.url_prefix + "/login"

    def login_url(self, return_to: str | None = None) -> str:
        if return_to:
            return self.login_path + "?" + urlencode({"return_to": safe_return_to(return_to)})
        return self.login_path

    def _cookie_sid(self) -> str | None:
        sid = request.cookies.get(self.cookie_name)
        return sid if sid and len(sid) <= 128 else None

    def _set_cookie(self, resp: Response, sid: str) -> None:
        resp.set_cookie(
            self.cookie_name,
            sid,
            httponly=True,
            secure=self.cookie_secure,
            samesite=self.cookie_samesite,
            domain=self.cookie_domain,
            path="/",
        )

    def _redirect(self, url: str) -> Response:
        if is_htmx(request.headers):
            resp = make_response("", 200)
            resp.headers["HX-Redirect"] = url
            return resp
        return cast(Response, redirect(url, code=302))

    def user_session(self, session_id: str) -> UserSession:
        return self._sessions.get_or_create(
            session_id, lambda: self.sso.session(store=StoreTokenAdapter(self.store, session_id))
        )

    def optional_user(self) -> WebUser[UserSession] | None:
        if "moon_sso_user" in g:
            return cast("WebUser[UserSession] | None", g.moon_sso_user)
        user = self._load_user()
        g.moon_sso_user = user
        return user

    def _load_user(self) -> WebUser[UserSession] | None:
        sid = self._cookie_sid()
        if sid is None:
            return None
        data = self.store.get(sid)
        if not data or not data.get("tokens"):
            return None
        session = self.user_session(sid)
        try:
            session.get_access_token()
        except SessionExpired:
            self._sessions.pop(sid)
            return None
        tokens = session.tokens
        if tokens is None:
            return None
        claims = dict(tokens.id_claims or {})
        sub = str(claims.get("sub") or data.get("sub") or "")
        if not sub:
            return None
        return WebUser(sub=sub, claims=claims, session=session, profile=session.profile)

    def _login_required_response(self) -> Response:
        target = request.full_path if request.query_string else request.path
        url = self.login_url(target)
        if is_htmx(request.headers):
            resp = make_response("", 200)
            resp.headers["HX-Redirect"] = url
            return resp
        if wants_html(request.headers.get("Accept")):
            return cast(Response, redirect(url, code=302))
        resp = jsonify({"error": "login_required", "error_description": "sign in first", "login_url": url})
        resp.status_code = 401
        return resp

    # ---- decorators ----

    def login_required(self, view: F) -> F:
        """Require a browser login (302 to login, ``HX-Redirect`` for HTMX, 401 JSON for APIs)."""

        @functools.wraps(view)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            if self.optional_user() is None:
                return self._login_required_response()
            return view(*args, **kwargs)

        return cast(F, wrapper)

    def bearer_required(
        self, view: F | None = None, *, scopes: Iterable[str] = (), audience: str | Iterable[str] | None = None
    ) -> Any:
        """Require a valid ``Authorization: Bearer`` access token; claims via :meth:`bearer_claims`."""
        required = tuple(scopes)

        def decorate(fn: F) -> F:
            @functools.wraps(fn)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                header = request.headers.get("Authorization", "")
                if header[:7].lower() != "bearer " or not header[7:].strip():
                    return self._bearer_error(401, "invalid_request", 'Bearer realm="api"')
                try:
                    g.moon_sso_claims = self.sso.verify_access_token(
                        header[7:].strip(), audience=audience, required_scopes=required
                    )
                except InsufficientScope as exc:
                    return self._bearer_error(
                        403, "insufficient_scope", f'Bearer error="insufficient_scope", scope="{" ".join(exc.required)}"'
                    )
                except TokenValidationError:
                    return self._bearer_error(401, "invalid_token", 'Bearer error="invalid_token"')
                return fn(*args, **kwargs)

            return cast(F, wrapper)

        return decorate(view) if view is not None else decorate

    @staticmethod
    def _bearer_error(status: int, code: str, challenge: str) -> Response:
        resp = jsonify({"error": code})
        resp.status_code = status
        resp.headers["WWW-Authenticate"] = challenge
        return resp

    @staticmethod
    def bearer_claims() -> AccessTokenClaims:
        """Claims validated by :meth:`bearer_required` for the current request."""
        return cast(AccessTokenClaims, g.moon_sso_claims)

    # ---- blueprint ----

    def _build_blueprint(self) -> Blueprint:
        bp = Blueprint("moon_sso", __name__)

        @bp.get("/login")
        def login() -> Response:
            prompt = request.args.get("prompt")
            req = self.sso.authorization_request(
                redirect_uri=self.redirect_uri,
                scope=self.scope,
                prompt=prompt if prompt in ("login", "consent", "select_account", "none") else None,
                return_to=safe_return_to(request.args.get("return_to"), self.after_login),
            )
            sid = self._cookie_sid()
            data = (self.store.get(sid) if sid else None) or {}
            if sid is None or not data:
                sid = new_session_id()
            data[SESSION_AUTH_REQUEST] = req.to_dict()
            self.store.set(sid, data)
            resp = self._redirect(req.url)
            self._set_cookie(resp, sid)
            return resp

        @bp.get("/callback")
        def callback() -> Any:
            sid = self._cookie_sid()
            data = (self.store.get(sid) if sid else None) or {}
            auth_req = auth_request_from(data)
            if sid is None or auth_req is None:
                return jsonify({"error": "invalid_request", "error_description": "no login in progress"}), 400
            data.pop(SESSION_AUTH_REQUEST, None)
            self.store.set(sid, data)
            try:
                tokens = self.sso.handle_callback(request.args.to_dict(), auth_req)
            except AuthorizationResponseError as exc:
                return jsonify({"error": exc.error, "error_description": exc.error_description}), 400
            except MoonSSOError as exc:
                return jsonify({"error": exc.error, "error_description": exc.error_description}), (502 if exc.retryable else 400)
            self.store.delete(sid)
            self._sessions.pop(sid)
            new_sid = new_session_id()
            StoreTokenAdapter(self.store, new_sid).save(tokens)
            if self.on_login is not None:
                self.on_login(tokens)
            resp = self._redirect(safe_return_to(auth_req.return_to, self.after_login))
            self._set_cookie(resp, new_sid)
            return resp

        @bp.route("/logout", methods=["GET", "POST"])
        def logout() -> Response:
            sid = self._cookie_sid()
            target = self.after_logout
            if sid is not None:
                end_url = self.user_session(sid).logout(post_logout_redirect_uri=self.post_logout_redirect_uri)
                self.store.delete(sid)
                self._sessions.pop(sid)
                if end_url and self.post_logout_redirect_uri:
                    target = end_url
            resp = self._redirect(target)
            resp.delete_cookie(self.cookie_name, path="/", domain=self.cookie_domain)
            return resp

        @bp.post("/webhook")
        def webhook() -> Any:
            if self.webhook is None:
                return jsonify({"error": "not_configured"}), 404
            try:
                event = self.webhook.verify(request.get_data(cache=False), request.headers)
            except WebhookVerificationError as exc:
                return jsonify({"error": exc.error, "error_description": exc.error_description}), 400
            if not event.duplicate and self.on_webhook is not None:
                self.on_webhook(event)
            return jsonify({"ok": True})

        @bp.post("/backchannel-logout")
        def backchannel() -> Any:
            headers = {"Cache-Control": "no-store"}
            token = request.form.get("logout_token")
            if not token:
                return jsonify({"error": "invalid_request", "error_description": "missing logout_token"}), 400, headers
            try:
                lt = self.sso.verify_logout_token(token)
            except (LogoutTokenError, TokenValidationError) as exc:
                return jsonify({"error": "invalid_request", "error_description": exc.error_description}), 400, headers
            except MoonSSOError as exc:
                return jsonify({"error": "temporarily_unavailable", "error_description": exc.error}), 503, headers
            self.store.delete_matching(sub=lt.sub, sid=lt.sid)
            if self.on_logout is not None:
                self.on_logout(lt.sub, lt.sid)
            return "", 200, headers

        # Webhook and back-channel requests come from the SSO server, not a browser
        # form: with Flask-WTF call ``csrf.exempt(auth.blueprint)``.
        return bp

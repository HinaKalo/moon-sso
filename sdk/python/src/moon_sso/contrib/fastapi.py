"""FastAPI / Starlette integration.

.. code-block:: python

    from fastapi import Depends, FastAPI
    from moon_sso import AsyncMoonSSO
    from moon_sso.contrib.fastapi import MoonSSOFastAPI

    sso = AsyncMoonSSO("https://sso.moonl.cloud", "my-app", "secret",
                       redirect_uri="https://app.example/auth/callback")
    auth = MoonSSOFastAPI(sso, webhook_secret="whsec_...")
    app = FastAPI()
    auth.init_app(app, prefix="/auth")

    @app.get("/")
    async def home(user=Depends(auth.require_user)):
        return {"hello": user.name}

    @app.get("/api/items")
    async def items(claims=Depends(auth.require_bearer(scopes=["items:read"]))):
        ...
"""

from __future__ import annotations

import inspect
import logging
from typing import Any, Awaitable, Callable, Iterable, Union
from urllib.parse import urlencode

from fastapi import APIRouter, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response

from ..aio import AsyncMoonSSO, AsyncUserSession
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

__all__ = ["LoginRequired", "MoonSSOFastAPI"]

log = logging.getLogger("moon_sso")

Handler = Callable[..., Union[Any, Awaitable[Any]]]


class LoginRequired(Exception):
    """Raised by :meth:`MoonSSOFastAPI.require_user`; rendered as redirect / HX-Redirect / 401."""

    def __init__(self, login_url: str) -> None:
        super().__init__("login required")
        self.login_url = login_url


async def _maybe_await(v: Any) -> Any:
    return await v if inspect.isawaitable(v) else v


class MoonSSOFastAPI:
    """Login/callback/logout routes, user and bearer dependencies, webhook and back-channel endpoints."""

    def __init__(
        self,
        sso: AsyncMoonSSO,
        *,
        session_store: SessionStore | None = None,
        cookie_name: str = "moon_sso_session",
        cookie_secure: bool | None = None,
        cookie_samesite: str = "lax",
        cookie_domain: str | None = None,
        redirect_uri: str | None = None,
        scope: str | None = None,
        after_login: str = "/",
        after_logout: str = "/",
        post_logout_redirect_uri: str | None = None,
        webhook_secret: str | None = None,
        on_webhook: Handler | None = None,
        on_logout: Handler | None = None,
        on_login: Handler | None = None,
    ) -> None:
        self.sso = sso
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
        self.prefix = ""
        self._sessions: LRU[AsyncUserSession] = LRU()
        self.router = self._build_router()

    # ---- wiring ----

    def init_app(self, app: FastAPI, prefix: str = "/auth") -> None:
        """Mount the routes under ``prefix`` and install the :class:`LoginRequired` handler."""
        self.prefix = prefix.rstrip("/")
        app.include_router(self.router, prefix=self.prefix)
        app.add_exception_handler(LoginRequired, self._login_required_handler)  # type: ignore[arg-type]

    @property
    def login_path(self) -> str:
        return self.prefix + "/login"

    def login_url(self, return_to: str | None = None) -> str:
        if return_to:
            return self.login_path + "?" + urlencode({"return_to": safe_return_to(return_to)})
        return self.login_path

    async def _login_required_handler(self, request: Request, exc: LoginRequired) -> Response:
        if is_htmx(request.headers):
            return Response(status_code=200, headers={"HX-Redirect": exc.login_url})
        if wants_html(request.headers.get("accept")):
            return RedirectResponse(exc.login_url, status_code=302)
        return JSONResponse(
            {"error": "login_required", "error_description": "sign in first", "login_url": exc.login_url},
            status_code=401,
        )

    # ---- web session helpers ----

    def _cookie_sid(self, request: Request) -> str | None:
        sid = request.cookies.get(self.cookie_name)
        return sid if sid and len(sid) <= 128 else None

    def _set_cookie(self, response: Response, sid: str) -> None:
        response.set_cookie(
            self.cookie_name,
            sid,
            httponly=True,
            secure=self.cookie_secure,
            samesite=self.cookie_samesite,  # type: ignore[arg-type]
            domain=self.cookie_domain,
            path="/",
        )

    def _clear_cookie(self, response: Response) -> None:
        response.delete_cookie(self.cookie_name, path="/", domain=self.cookie_domain)

    def user_session(self, session_id: str) -> AsyncUserSession:
        """The shared token manager of a web session (one refresh lock per browser session)."""
        return self._sessions.get_or_create(
            session_id, lambda: self.sso.session(store=StoreTokenAdapter(self.store, session_id))
        )

    def _redirect(self, request: Request, url: str) -> Response:
        if is_htmx(request.headers):
            return Response(status_code=200, headers={"HX-Redirect": url})
        return RedirectResponse(url, status_code=302)

    # ---- dependencies ----

    async def optional_user(self, request: Request) -> WebUser[AsyncUserSession] | None:
        """Dependency: the signed-in user or ``None`` (refreshes tokens when needed)."""
        sid = self._cookie_sid(request)
        if sid is None:
            return None
        data = self.store.get(sid)
        if not data or not data.get("tokens"):
            return None
        session = self.user_session(sid)
        try:
            await session.get_access_token()
        except SessionExpired:
            self._sessions.pop(sid)
            return None
        tokens = await session.tokens()
        if tokens is None:
            return None
        claims = dict(tokens.id_claims or {})
        sub = str(claims.get("sub") or data.get("sub") or "")
        if not sub:
            return None
        return WebUser(sub=sub, claims=claims, session=session, profile=session.profile)

    async def require_user(self, request: Request) -> WebUser[AsyncUserSession]:
        """Dependency: the signed-in user; otherwise redirect (302 / HX-Redirect) or 401 JSON."""
        user = await self.optional_user(request)
        if user is None:
            target = request.url.path + (("?" + request.url.query) if request.url.query else "")
            raise LoginRequired(self.login_url(target))
        return user

    def require_bearer(
        self, *, scopes: Iterable[str] = (), audience: str | Iterable[str] | None = None
    ) -> Callable[[Request], Awaitable[AccessTokenClaims]]:
        """Dependency factory validating ``Authorization: Bearer`` access tokens locally."""
        required = tuple(scopes)

        async def dependency(request: Request) -> AccessTokenClaims:
            header = request.headers.get("authorization", "")
            if not header[:7].lower() == "bearer " or not header[7:].strip():
                raise HTTPException(401, detail="missing bearer token", headers={"WWW-Authenticate": 'Bearer realm="api"'})
            try:
                return await self.sso.verify_access_token(header[7:].strip(), audience=audience, required_scopes=required)
            except InsufficientScope as exc:
                raise HTTPException(
                    403,
                    detail="insufficient_scope",
                    headers={"WWW-Authenticate": f'Bearer error="insufficient_scope", scope="{" ".join(exc.required)}"'},
                ) from exc
            except TokenValidationError as exc:
                raise HTTPException(
                    401, detail="invalid_token", headers={"WWW-Authenticate": 'Bearer error="invalid_token"'}
                ) from exc

        return dependency

    # ---- routes ----

    def _build_router(self) -> APIRouter:
        router = APIRouter()

        @router.get("/login", name="moon_sso_login")
        async def login(request: Request, return_to: str | None = None, prompt: str | None = None) -> Response:
            req = await self.sso.authorization_request(
                redirect_uri=self.redirect_uri,
                scope=self.scope,
                prompt=prompt if prompt in ("login", "consent", "select_account", "none") else None,
                return_to=safe_return_to(return_to, self.after_login),
            )
            sid = self._cookie_sid(request)
            data = (self.store.get(sid) if sid else None) or {}
            if sid is None or not data:
                sid = new_session_id()
            data[SESSION_AUTH_REQUEST] = req.to_dict()
            self.store.set(sid, data)
            resp = self._redirect(request, req.url)
            self._set_cookie(resp, sid)
            return resp

        @router.get("/callback", name="moon_sso_callback")
        async def callback(request: Request) -> Response:
            sid = self._cookie_sid(request)
            data = (self.store.get(sid) if sid else None) or {}
            auth_req = auth_request_from(data)
            if sid is None or auth_req is None:
                return JSONResponse({"error": "invalid_request", "error_description": "no login in progress"}, status_code=400)
            data.pop(SESSION_AUTH_REQUEST, None)
            self.store.set(sid, data)
            try:
                tokens = await self.sso.handle_callback(dict(request.query_params), auth_req)
            except AuthorizationResponseError as exc:
                return JSONResponse({"error": exc.error, "error_description": exc.error_description}, status_code=400)
            except MoonSSOError as exc:
                status = 502 if exc.retryable else 400
                return JSONResponse({"error": exc.error, "error_description": exc.error_description}, status_code=status)
            # New session id after login (session fixation defence).
            self.store.delete(sid)
            self._sessions.pop(sid)
            new_sid = new_session_id()
            adapter = StoreTokenAdapter(self.store, new_sid)
            adapter.save(tokens)
            if self.on_login is not None:
                await _maybe_await(self.on_login(tokens))
            resp = self._redirect(request, safe_return_to(auth_req.return_to, self.after_login))
            self._set_cookie(resp, new_sid)
            return resp

        async def logout(request: Request) -> Response:
            sid = self._cookie_sid(request)
            target = self.after_logout
            if sid is not None:
                session = self.user_session(sid)
                end_url = await session.logout(post_logout_redirect_uri=self.post_logout_redirect_uri)
                self.store.delete(sid)
                self._sessions.pop(sid)
                if end_url and self.post_logout_redirect_uri:
                    target = end_url
            resp = self._redirect(request, target)
            self._clear_cookie(resp)
            return resp

        router.add_api_route("/logout", logout, methods=["GET", "POST"], name="moon_sso_logout")

        @router.post("/webhook", name="moon_sso_webhook")
        async def webhook(request: Request) -> Response:
            if self.webhook is None:
                return JSONResponse({"error": "not_configured"}, status_code=404)
            body = await request.body()
            try:
                event = self.webhook.verify(body, request.headers)
            except WebhookVerificationError as exc:
                return JSONResponse({"error": exc.error, "error_description": exc.error_description}, status_code=400)
            if not event.duplicate and self.on_webhook is not None:
                await _maybe_await(self.on_webhook(event))
            return JSONResponse({"ok": True})

        @router.post("/backchannel-logout", name="moon_sso_backchannel")
        async def backchannel(request: Request) -> Response:
            headers = {"Cache-Control": "no-store"}
            form = await request.form()
            token = form.get("logout_token")
            if not isinstance(token, str) or not token:
                return JSONResponse({"error": "invalid_request", "error_description": "missing logout_token"}, 400, headers)
            try:
                lt = await self.sso.verify_logout_token(token)
            except (LogoutTokenError, TokenValidationError) as exc:
                return JSONResponse({"error": "invalid_request", "error_description": exc.error_description}, 400, headers)
            except MoonSSOError as exc:
                return JSONResponse({"error": "temporarily_unavailable", "error_description": exc.error}, 503, headers)
            self.store.delete_matching(sub=lt.sub, sid=lt.sid)
            if self.on_logout is not None:
                await _maybe_await(self.on_logout(lt.sub, lt.sid))
            return Response(status_code=200, headers=headers)

        return router


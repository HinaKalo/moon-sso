"""Configuration and I/O-free logic shared by the sync and async clients."""

from __future__ import annotations

import hmac
import threading
import time
from typing import Any, Iterable, Mapping
from urllib.parse import parse_qsl, quote, urlencode, urlsplit

import httpx

from ._util import USER_AGENT, ReplayCache, error_from_response, expect_json, json_body
from .discovery import normalize_issuer
from .dpop import DPoPKey
from .errors import (
    AuthorizationResponseError,
    LogoutTokenError,
    MoonSSOError,
    OtpRequired,
    PasswordChangeRequired,
    SessionExpired,
)
from .models import (
    AuthorizationRequest,
    ChangesPage,
    ClientRegistration,
    LogoutToken,
    PendingChallenge,
    ProviderMetadata,
    TokenSet,
    UsersPage,
)
from .pkce import PKCE, random_token

DEFAULT_SCOPE = "openid profile offline_access"
AUTH_METHODS = ("client_secret_basic", "client_secret_post", "none")


class _ClientBase:
    """Settings and pure helpers. Not part of the public API."""

    def __init__(
        self,
        issuer: str,
        client_id: str,
        client_secret: str | None = None,
        *,
        redirect_uri: str | None = None,
        scope: str = DEFAULT_SCOPE,
        token_endpoint_auth_method: str | None = None,
        dpop: bool | None = None,
        dpop_key: DPoPKey | None = None,
        audience: str | Iterable[str] | None = None,
        leeway: float = 60.0,
        refresh_skew: float = 120.0,
        user_agent: str | None = None,
    ) -> None:
        if not client_id:
            raise ValueError("client_id is required")
        self.issuer = normalize_issuer(issuer)
        self.client_id = client_id
        self._client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.scope = scope
        method = token_endpoint_auth_method or ("client_secret_basic" if client_secret else "none")
        if method not in AUTH_METHODS:
            raise ValueError(f"unsupported token_endpoint_auth_method {method!r}")
        if method != "none" and not client_secret:
            raise ValueError(f"{method} needs client_secret")
        if method == "none" and client_secret:
            raise ValueError("public clients (auth method 'none') must not have a client_secret")
        self.token_endpoint_auth_method = method
        self.is_public = method == "none"
        self.dpop_enabled = self.is_public if dpop is None else bool(dpop)
        if dpop_key is not None and dpop is None:
            self.dpop_enabled = True
        self.dpop_key: DPoPKey | None = (dpop_key or DPoPKey.generate()) if self.dpop_enabled else None
        if audience is None:
            self.audiences: list[str] = [client_id]
        elif isinstance(audience, str):
            self.audiences = [audience]
        else:
            self.audiences = list(audience)
        self.leeway = leeway
        self.refresh_skew = refresh_skew
        self.user_agent = user_agent or USER_AGENT
        self.logout_replay = ReplayCache(ttl=300.0)
        self._cc_tokens: dict[str, TokenSet] = {}
        self._cc_lock = threading.Lock()

    @property
    def api_base(self) -> str:
        return self.issuer + "/api/v1"

    def _default_headers(self) -> dict[str, str]:
        return {"User-Agent": self.user_agent}

    # ---- client authentication ----

    def _client_auth(self, data: dict[str, str]) -> tuple[dict[str, str], httpx.Auth | None, dict[str, str]]:
        """Return (form, auth, headers) for the configured auth method."""
        form = dict(data)
        headers: dict[str, str] = {}
        if self.token_endpoint_auth_method == "client_secret_basic":
            assert self._client_secret is not None
            # RFC 6749 §2.3.1: form-urlencode both parts before base64.
            import base64

            raw = f"{quote(self.client_id, safe='')}:{quote(self._client_secret, safe='')}".encode("utf-8")
            headers["Authorization"] = "Basic " + base64.b64encode(raw).decode("ascii")
            form.pop("client_id", None)
        elif self.token_endpoint_auth_method == "client_secret_post":
            assert self._client_secret is not None
            form["client_id"] = self.client_id
            form["client_secret"] = self._client_secret
        else:
            form["client_id"] = self.client_id
        return form, None, headers

    # ---- authorization request / response ----

    def _build_authorization_request(
        self,
        meta: ProviderMetadata,
        *,
        redirect_uri: str | None,
        scope: str | None,
        prompt: str | None,
        login_hint: str | None,
        resource: str | None,
        max_age: int | None,
        response_mode: str | None,
        return_to: str | None,
        extra: Mapping[str, str] | None,
    ) -> AuthorizationRequest:
        ruri = redirect_uri or self.redirect_uri
        if not ruri:
            raise ValueError("redirect_uri is required (pass it here or to the client)")
        sc = scope or self.scope
        pkce = PKCE.generate()
        state = random_token(32)
        nonce = random_token(32) if "openid" in sc.split() else None
        params: dict[str, str] = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": ruri,
            "scope": sc,
            "state": state,
            "code_challenge": pkce.challenge,
            "code_challenge_method": "S256",
        }
        if nonce:
            params["nonce"] = nonce
        if self.dpop_key is not None:
            params["dpop_jkt"] = self.dpop_key.thumbprint
        for k, v in (
            ("prompt", prompt),
            ("login_hint", login_hint),
            ("resource", resource),
            ("max_age", str(max_age) if max_age is not None else None),
            ("response_mode", response_mode),
        ):
            if v:
                params[k] = v
        for k, v in (extra or {}).items():
            if k in params:
                raise ValueError(f"extra parameter {k!r} would override a protocol parameter")
            params[k] = v
        sep = "&" if "?" in meta.authorization_endpoint else "?"
        url = meta.authorization_endpoint + sep + urlencode(params)
        return AuthorizationRequest(
            url=url,
            state=state,
            nonce=nonce,
            code_verifier=pkce.verifier,
            redirect_uri=ruri,
            scope=sc,
            return_to=return_to,
        )

    @staticmethod
    def _callback_params(callback: str | Mapping[str, Any]) -> dict[str, str]:
        if isinstance(callback, str):
            if "?" in callback:
                query = callback.split("?", 1)[1].split("#", 1)[0]
            elif "=" in callback:
                query = callback  # a bare query string
            else:
                query = urlsplit(callback).query
            return dict(parse_qsl(query, keep_blank_values=True))
        out: dict[str, str] = {}
        for k, v in callback.items():
            if isinstance(v, (list, tuple)):
                v = v[0] if v else ""
            out[str(k)] = "" if v is None else str(v)
        return out

    def _validate_callback(
        self, meta: ProviderMetadata, callback: str | Mapping[str, Any], request: AuthorizationRequest, max_age: float
    ) -> str:
        params = self._callback_params(callback)
        state = params.get("state", "")
        if not state or not hmac.compare_digest(state.encode(), request.state.encode()):
            raise AuthorizationResponseError("invalid_state", "state does not match the authorization request", 400)
        iss = params.get("iss")
        if iss is not None:
            if iss.rstrip("/") != self.issuer:
                raise AuthorizationResponseError("invalid_issuer", "iss does not match the issuer (RFC 9207)", 400)
        elif meta.iss_parameter_supported:
            raise AuthorizationResponseError("invalid_issuer", "authorization response lacks iss (RFC 9207)", 400)
        if params.get("error"):
            raise AuthorizationResponseError(params["error"], params.get("error_description") or None, 400)
        if time.time() - request.created_at > max_age:
            raise AuthorizationResponseError("request_expired", "authorization request is too old", 400)
        code = params.get("code")
        if not code:
            raise AuthorizationResponseError("invalid_request", "authorization response lacks code", 400)
        return code

    def _end_session_url(
        self,
        meta: ProviderMetadata,
        id_token_hint: str | None,
        post_logout_redirect_uri: str | None,
        state: str | None,
    ) -> str | None:
        if not meta.end_session_endpoint:
            return None
        params: dict[str, str] = {"client_id": self.client_id}
        if id_token_hint:
            params["id_token_hint"] = id_token_hint
        if post_logout_redirect_uri:
            params["post_logout_redirect_uri"] = post_logout_redirect_uri
        if state:
            params["state"] = state
        sep = "&" if "?" in meta.end_session_endpoint else "?"
        return meta.end_session_endpoint + sep + urlencode(params)

    # ---- token responses ----

    @staticmethod
    def _token_error(resp: httpx.Response, refreshing: bool) -> MoonSSOError:
        err = error_from_response(resp)
        if refreshing and err.error == "invalid_grant":
            return SessionExpired(err.error_description, err.status, body=err.body)
        return err

    def _tokens_from(self, resp: httpx.Response, refreshing: bool) -> TokenSet:
        if resp.status_code != 200:
            raise self._token_error(resp, refreshing)
        return TokenSet.from_response(expect_json(resp))

    # ---- first-party challenge ----

    def _challenge_form(self, pkce: PKCE, scope: str, **fields: str | None) -> dict[str, str]:
        form = {"code_challenge": pkce.challenge, "code_challenge_method": "S256", "scope": scope}
        form.update({k: v for k, v in fields.items() if v is not None})
        return form

    @staticmethod
    def _challenge_result(resp: httpx.Response, pkce: PKCE, scope: str, endpoint: str) -> str:
        """Return the authorization code or raise OtpRequired / PasswordChangeRequired / MoonSSOError."""
        if resp.status_code == 200:
            data = expect_json(resp)
            code = data.get("authorization_code")
            if not isinstance(code, str) or not code:
                raise MoonSSOError("invalid_response", "challenge response lacks authorization_code", resp.status_code)
            return code
        body = json_body(resp)
        if resp.status_code == 400 and body.get("error") == "insufficient_authorization" and body.get("auth_session"):
            pending = PendingChallenge(
                auth_session=str(body["auth_session"]),
                code_verifier=pkce.verifier,
                code_challenge=pkce.challenge,
                scope=scope,
                required=str(body.get("required") or "otp"),
                endpoint=endpoint,
            )
            raise OtpRequired(pending, body.get("error_description"), body=body)
        if body.get("error") == "password_change_required":
            raise PasswordChangeRequired(body.get("change_url"), body.get("error_description"), body=body)
        raise error_from_response(resp)

    @staticmethod
    def _dpop_htu_mismatch(resp: httpx.Response) -> bool:
        if resp.status_code != 400:
            return False
        body = json_body(resp)
        return body.get("error") == "invalid_dpop_proof" and "htu" in str(body.get("error_description") or "")

    # ---- id token merge on refresh ----

    @staticmethod
    def _merge_refreshed(old: TokenSet, new: TokenSet) -> TokenSet:
        if new.refresh_token is None:
            new.refresh_token = old.refresh_token
        if new.id_token is None:
            new.id_token = old.id_token
            new.id_claims = old.id_claims
        if new.scope is None:
            new.scope = old.scope
        return new

    # ---- client credentials cache ----

    def _cc_get(self, scope: str) -> TokenSet | None:
        ts = self._cc_tokens.get(scope)
        if ts is None:
            return None
        if ts.expires_in() <= min(self.refresh_skew, ts.lifetime / 4 if ts.lifetime else self.refresh_skew):
            return None
        return ts

    # ---- logout token replay ----

    def _check_logout_replay(self, token: LogoutToken) -> LogoutToken:
        if not self.logout_replay.add(token.issuer + "|" + token.jti):
            raise LogoutTokenError("logout token jti replayed")
        return token

    # ---- sync feed parsing ----

    @staticmethod
    def _changes_page(data: Mapping[str, Any]) -> ChangesPage:
        events = data.get("events") or []
        if not isinstance(events, list):
            raise MoonSSOError("invalid_response", "events is not a list")
        return ChangesPage(
            events=[e for e in events if isinstance(e, dict)],
            next_cursor=str(data.get("next_cursor") or ""),
            has_more=bool(data.get("has_more")),
        )

    @staticmethod
    def _users_page(data: Mapping[str, Any]) -> UsersPage:
        users = data.get("users") or []
        if not isinstance(users, list):
            raise MoonSSOError("invalid_response", "users is not a list")
        nc = data.get("next_cursor")
        return UsersPage(
            users=[u for u in users if isinstance(u, dict)],
            watermark=str(data.get("watermark") or "0"),
            has_more=bool(data.get("has_more")),
            next_cursor=str(nc) if nc else None,
        )

    @staticmethod
    def _registration(resp: httpx.Response) -> ClientRegistration:
        if resp.status_code not in (200, 201):
            raise error_from_response(resp)
        data = expect_json(resp)
        cid = data.get("client_id")
        if not isinstance(cid, str) or not cid:
            raise MoonSSOError("invalid_response", "registration response lacks client_id", resp.status_code)
        return ClientRegistration(
            client_id=cid,
            client_secret=data.get("client_secret") or None,
            registration_access_token=data.get("registration_access_token") or None,
            registration_client_uri=data.get("registration_client_uri") or None,
            status=str(data.get("status") or "active"),
            webhook_secret=data.get("webhook_secret") or None,
            raw=data,
        )


def needs_refresh(tokens: TokenSet, skew: float, now: float | None = None) -> bool:
    """True when the access token is within ``skew`` seconds of expiring.

    Very short-lived tokens use a quarter of their lifetime instead, so a
    token never counts as "always expiring".
    """
    life = tokens.lifetime
    effective = min(skew, life / 4) if life > 0 else skew
    return tokens.expires_in(now) <= effective

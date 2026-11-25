"""Moon SSO Python SDK.

>>> from moon_sso import MoonSSO
>>> sso = MoonSSO("https://sso.moonl.cloud", "my-app", "secret", redirect_uri="https://app.example/callback")
>>> req = sso.authorization_request()          # redirect the browser to req.url
>>> tokens = sso.handle_callback(callback_url, req)
>>> session = sso.session(tokens)
>>> session.get_me()
"""

from ._version import __version__
from .aio import AsyncMoonSSO, AsyncUserSession, async_register_client, async_unregister_client
from .client import MoonSSO, register_client, unregister_client
from .dpop import DPoPKey
from .errors import (
    AuthorizationResponseError,
    CursorExpired,
    InsufficientScope,
    LogoutTokenError,
    MoonSSOError,
    OtpRequired,
    PasswordChangeRequired,
    SessionExpired,
    TokenValidationError,
    WebhookVerificationError,
)
from .models import (
    AccessTokenClaims,
    AuthorizationRequest,
    ChangesPage,
    ClientRegistration,
    LogoutToken,
    PendingChallenge,
    ProviderMetadata,
    SyncBatch,
    TokenSet,
    UsersPage,
)
from .pkce import PKCE, code_challenge, generate_code_verifier
from .session import UserSession
from .sse import SSEEvent, SSEParser
from .store import AsyncTokenStore, CallbackTokenStore, FileTokenStore, MemoryTokenStore, TokenStore
from .webhooks import WebhookEvent, WebhookVerifier, sign_webhook

__all__ = [
    "__version__",
    "AccessTokenClaims",
    "AsyncMoonSSO",
    "AsyncTokenStore",
    "AsyncUserSession",
    "AuthorizationRequest",
    "AuthorizationResponseError",
    "CallbackTokenStore",
    "ChangesPage",
    "ClientRegistration",
    "CursorExpired",
    "DPoPKey",
    "FileTokenStore",
    "InsufficientScope",
    "LogoutToken",
    "LogoutTokenError",
    "MemoryTokenStore",
    "MoonSSO",
    "MoonSSOError",
    "OtpRequired",
    "PKCE",
    "PasswordChangeRequired",
    "PendingChallenge",
    "ProviderMetadata",
    "SSEEvent",
    "SSEParser",
    "SessionExpired",
    "SyncBatch",
    "TokenSet",
    "TokenStore",
    "TokenValidationError",
    "UserSession",
    "UsersPage",
    "WebhookEvent",
    "WebhookVerificationError",
    "WebhookVerifier",
    "async_register_client",
    "async_unregister_client",
    "code_challenge",
    "generate_code_verifier",
    "register_client",
    "sign_webhook",
    "unregister_client",
]

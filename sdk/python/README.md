# moon_sso —— Moon SSO Python SDK

Moon SSO（OAuth 2.x / OpenID Connect 授权服务器）的官方 Python SDK。只需配置 issuer，其余端点全部通过 discovery 获取。

- 登录：授权码 + PKCE S256，校验 `state`、`iss`（RFC 9207）、`nonce`、ID Token（签名、`iss`、`aud`、`exp`、`iat`、`at_hash`）
- 令牌：剩余寿命不足 120 秒时自动刷新；同一会话的并发刷新只发一个请求（single-flight）；刷新令牌轮换后立即持久化；`invalid_grant` 抛 `SessionExpired`，网络错误、429、5xx 不会清除登录态
- 重试：token 端点遇到网络错误、502、503、504 时原参数重试一次；资源请求返回 401 时强制刷新一次并重放
- 资源服务器：本地校验 access token（`typ: at+jwt`、`iss`、`aud`、`exp`、`nbf`），JWKS 缓存 1 小时，遇到未知 `kid` 时强制重新拉取（最多每 30 秒一次）
- 第一方应用内登录（含 OTP 第二步）、应用内注册、DPoP（ES256）
- 账号 API、SSE 实时事件、Standard Webhooks 验签、Back-Channel Logout、变更流（410 时自动全量同步）、动态客户端注册
- 同步 `MoonSSO` 与异步 `AsyncMoonSSO` 两套 API，带完整类型标注（`py.typed`）
- 框架适配：FastAPI、Flask、Django，都能识别 HTMX 请求

运行时依赖只有 `httpx` 和 `PyJWT[crypto]`（`cryptography`）。要求 Python 3.10+。

## 安装

```bash
pip install https://sso.moonl.cloud/sdk/pypi/moon_sso-1.0.0-py3-none-any.whl
```

框架适配器的依赖按需安装（extras）：

```bash
pip install "moon_sso[fastapi] @ https://sso.moonl.cloud/sdk/pypi/moon_sso-1.0.0-py3-none-any.whl"
pip install "moon_sso[flask] @ https://sso.moonl.cloud/sdk/pypi/moon_sso-1.0.0-py3-none-any.whl"
pip install "moon_sso[django] @ https://sso.moonl.cloud/sdk/pypi/moon_sso-1.0.0-py3-none-any.whl"
```

`import moon_sso` 不会导入任何 Web 框架，适配器在 `moon_sso.contrib.*` 中按需导入。

## 基本概念

```python
from moon_sso import MoonSSO

sso = MoonSSO(
    "https://sso.moonl.cloud",          # issuer，其余地址自动发现
    "my-app",                           # client_id
    os.environ["MOON_SSO_SECRET"],      # 机密客户端才需要；公共客户端不传
    redirect_uri="https://app.example.com/auth/callback",
    scope="openid profile offline_access",
)
```

| 参数 | 说明 |
|---|---|
| `token_endpoint_auth_method` | 默认：有密钥时用 `client_secret_basic`，没有时用 `none` |
| `dpop` / `dpop_key` | 公共客户端默认启用 DPoP；`DPoPKey.generate()` 生成，`to_pem()` / `from_pem()` 持久化 |
| `audience` | 校验 access token 时期望的 `aud`，默认是 `client_id` |
| `refresh_skew` | 提前刷新的秒数，默认 120 |
| `http_client` | 自定义 `httpx.Client`（代理、证书等） |

所有请求都带 `User-Agent: moon-sso-sdk-python/<版本>`，服务端会在用户的“登录设备”中显示为“应用 SDK”。

## 脚本与后台任务

### 用户登录（授权码流程）

```python
req = sso.authorization_request()                 # 含 PKCE、state、nonce
# 把 req.to_dict() 存进会话，然后把浏览器重定向到 req.url
...
# 回调：传入完整回调 URL（或 query 参数字典）
tokens = sso.handle_callback(callback_url, AuthorizationRequest.from_dict(saved))
print(tokens.id_claims["sub"], tokens.id_claims["preferred_username"])
```

### 令牌管理与账号 API

```python
from moon_sso import FileTokenStore, SessionExpired

session = sso.session(
    tokens,
    store=FileTokenStore("~/.config/myapp/tokens.json"),   # 默认是内存存储
    on_session_expired=lambda exc: print("请重新登录"),
    on_profile_changed=lambda profile: print("资料已更新", profile),
)

me = session.get_me()                                # 带 ETag，未变化时走 304
session.update_profile(display_name="新昵称", if_match=True)   # 需要 profile:write
session.upload_avatar(open("avatar.png", "rb").read())        # ≤ 5 MB
session.delete_avatar()
session.change_password("旧密码", "新密码")                     # 需要 password:write

token = session.get_access_token()                   # 需要时自动刷新（线程安全、single-flight）
resp = session.request("GET", "https://api.example.com/x")      # 401 时自动刷新并重放一次

try:
    session.get_access_token()
except SessionExpired:
    ...                                              # 只有 invalid_grant 才会走到这里

logout_url = session.logout(post_logout_redirect_uri="https://app.example.com/")
```

自定义存储只需实现 `load()`、`save(tokens)`、`clear()` 三个方法（`TokenStore` 协议）；刷新令牌每次使用都会轮换，`save` 必须立即、原子地写入。

### 第一方应用内登录（含两步验证）

```python
from moon_sso import MoonSSO, OtpRequired, PasswordChangeRequired

app = MoonSSO("https://sso.moonl.cloud", "my-native-app")      # 公共客户端，默认启用 DPoP
try:
    tokens = app.login_with_password("bob", "password")
except OtpRequired as need:
    tokens = app.submit_otp(need, input("验证码: "))           # SDK 保存了 PKCE verifier 和 DPoP 绑定
except PasswordChangeRequired as exc:
    print("请先在浏览器中修改密码：", exc.change_url)

tokens = app.native_register("newuser", "Strong-Pass-123", display_name="新用户")   # 应用内注册
```

### 服务端注册 API

```python
sso.registration_info()                     # 是否开放注册、用户名和口令规则
sso.register_user("alice2", "Strong-Pass-123", display_name="Alice")   # 422 时 MoonSSOError.field 指出字段
```

### 变更流（`client_credentials` + `users:sync`）

```python
cursor = load_cursor()                       # 从未同步过就传 None：先做一次全量同步
for batch in sso.iter_changes(cursor):
    for user in batch.users:                 # 全量同步的快照行
        upsert(user)
    for event in batch.events:               # 增量事件，按 data.profile_version 丢弃旧事件
        apply(event)
    if batch.cursor is not None:
        save_cursor(batch.cursor)            # 处理完一批再保存游标
```

游标过期（HTTP 410）时，`iter_changes` 会自动调用 `GET /api/v1/users` 全量拉取，并从第一页的 watermark 继续拉变更流。也可以直接使用 `sync_changes(cursor)`（410 时抛 `CursorExpired`）、`full_sync()`、`list_users()`、`get_user(sub)`。`client_credentials` 令牌会被缓存，到期前 120 秒自动更换。

### 实时事件（SSE）

```python
for event in session.events():               # 自动重连，带 Last-Event-ID，必要时先刷新令牌
    print(event.event, event.json())
```

- `user.updated`：更新本地 profile 并触发 `on_profile_changed`
- `user.password_changed`、`user.disabled`、`user.deleted`、`consent.revoked`：先尝试刷新；刷新报 `invalid_grant` 就抛 `SessionExpired`
- `resync`：重新获取 `/api/v1/me`；`token_expired`：刷新后立即重连
- 在其他线程调用 `session.stop_events()` 可结束循环

### 动态客户端注册（DCR）

```python
from moon_sso import register_client

reg = register_client("https://sso.moonl.cloud", initial_access_token, {
    "client_name": "My App",
    "redirect_uris": ["https://app.example.com/auth/callback"],
    "token_endpoint_auth_method": "client_secret_basic",
    "application_type": "web",
    "scope": "openid profile offline_access",
})
print(reg.client_id, reg.client_secret, reg.registration_access_token, reg.status)   # status: active / pending_approval
```

### 异步（asyncio）

`AsyncMoonSSO` 与 `MoonSSO` 参数相同，方法都是协程；`AsyncUserSession` 用 `asyncio.Lock` 实现 single-flight，`events()` 是异步迭代器。

```python
async with AsyncMoonSSO(issuer, client_id, secret, redirect_uri=...) as sso:
    session = sso.session(tokens)
    me = await session.get_me()
    async for ev in session.events():
        ...
```

## FastAPI

```python
from fastapi import Depends, FastAPI
from moon_sso import AsyncMoonSSO
from moon_sso.contrib.fastapi import MoonSSOFastAPI

sso = AsyncMoonSSO("https://sso.moonl.cloud", "my-app", SECRET,
                   redirect_uri="https://app.example.com/auth/callback")
auth = MoonSSOFastAPI(
    sso,
    webhook_secret=WEBHOOK_SECRET,               # 可选：启用 /auth/webhook
    on_webhook=handle_event,                     # 同步或异步函数，参数是 WebhookEvent
    on_logout=lambda sub, sid: ...,              # 可选：back-channel logout 回调
    post_logout_redirect_uri="https://app.example.com/",   # 设置后退出时跳到 SSO 的 end_session
)
app = FastAPI()
auth.init_app(app, prefix="/auth")   # /auth/login /auth/callback /auth/logout /auth/webhook /auth/backchannel-logout

@app.get("/")
async def home(user = Depends(auth.require_user)):
    me = await user.session.get_me()
    return {"hello": me["name"]}

@app.get("/api/items")
async def items(claims = Depends(auth.require_bearer(scopes=["profile"]))):
    return {"sub": claims.sub}
```

- 未登录时：浏览器请求返回 302 到登录页；HTMX 请求（`HX-Request: true`）返回 `200` 加 `HX-Redirect`；其他 API 请求返回 401 JSON。
- 令牌保存在服务端会话存储里（默认 `MemorySessionStore`），浏览器只拿到一个随机的 HttpOnly Cookie。多进程部署时请实现 `SessionStore` 协议（`get`/`set`/`delete`/`delete_matching`），例如基于 Redis。
- 登录成功后会更换会话 ID，防止会话固定攻击；`return_to` 只接受站内相对路径。

## Flask

```python
from flask import Flask
from moon_sso import MoonSSO
from moon_sso.contrib.flask import MoonSSOFlask, current_user

sso = MoonSSO("https://sso.moonl.cloud", "my-app", SECRET,
              redirect_uri="https://app.example.com/auth/callback")
app = Flask(__name__)
auth = MoonSSOFlask(sso, app, url_prefix="/auth", webhook_secret=WEBHOOK_SECRET, on_webhook=handle_event)

@app.get("/")
@auth.login_required
def home():
    return f"你好，{current_user().name}"

@app.get("/api/items")
@auth.bearer_required(scopes=["profile"])
def items():
    return {"sub": auth.bearer_claims().sub}
```

使用 Flask-WTF 的 CSRF 保护时，请对 SDK 的蓝图豁免：`csrf.exempt(auth.blueprint)`（webhook 和 back-channel 请求来自 SSO 服务器）。

## Django

`settings.py`：

```python
INSTALLED_APPS += ["django.contrib.sessions"]
MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",
    "moon_sso.contrib.django.middleware.MoonSSOMiddleware",
    # ...
]
MOON_SSO = {
    "ISSUER": "https://sso.moonl.cloud",
    "CLIENT_ID": "my-app",
    "CLIENT_SECRET": os.environ["MOON_SSO_SECRET"],
    "REDIRECT_URI": "https://app.example.com/auth/callback",
    "SCOPE": "openid profile offline_access",
    "AFTER_LOGIN": "/",
    "AFTER_LOGOUT": "/",
    "POST_LOGOUT_REDIRECT_URI": None,              # 设置后退出时跳到 SSO 的 end_session
    "WEBHOOK_SECRET": os.environ.get("MOON_SSO_WEBHOOK_SECRET"),
    "WEBHOOK_HANDLER": "myapp.sso.on_webhook",     # 可调用对象或点分路径，参数是 WebhookEvent
    "LOGOUT_HANDLER": "myapp.sso.on_logout",       # (sub, sid)
    "CACHE_ALIAS": "default",                      # 用于令牌镜像和 back-channel 会话索引
}
```

`urls.py`：

```python
path("auth/", include("moon_sso.contrib.django.urls")),   # login / callback / logout / webhook / backchannel-logout
```

视图：

```python
from moon_sso.contrib.django.decorators import bearer_required, login_required

@login_required
def home(request):
    user = request.moon_sso_user                 # WebUser，未登录时为 None
    return JsonResponse(user.session.get_me())

@bearer_required(scopes=["profile"])
def api(request):
    return JsonResponse({"sub": request.moon_sso_claims.sub})
```

令牌保存在 Django 会话中，并在缓存里保留一份镜像，保证同一浏览器的并发请求总能拿到最新轮换的刷新令牌。多进程部署时请使用共享缓存（Redis、Memcached），back-channel logout 依赖它找到需要删除的会话。

## Webhook 与 Back-Channel Logout（不使用框架适配器时）

```python
from moon_sso import WebhookVerifier, WebhookVerificationError

verifier = WebhookVerifier(WEBHOOK_SECRET)        # "whsec_..."
try:
    event = verifier.verify(raw_body_bytes, request_headers)   # 必须是原始字节
except WebhookVerificationError:
    return 400
if not event.duplicate and not event.is_stale(known_profile_version(event.sub)):
    apply(event)
```

```python
lt = sso.verify_logout_token(form["logout_token"])   # 校验签名、typ、iss、aud、iat、exp、events、sub/sid、nonce、jti 防重放
destroy_sessions(sub=lt.sub, sid=lt.sid)
```

`jti` 防重放缓存默认在进程内（5 分钟）。多进程部署时，可以把 `sso.logout_replay` 换成任何提供 `add(key) -> bool`（首次出现返回 `True`）的共享实现，例如基于 Redis `SET NX EX 300`。

## 资源服务器

```python
claims = sso.verify_access_token(token, audience="https://api.example.com", required_scopes=["orders:read"])
claims.sub, claims.scopes, claims.client_id, claims.is_client_token
```

失败时抛 `TokenValidationError`（401），缺少 scope 时抛 `InsufficientScope`（403）。

## 错误模型

所有错误都是 `MoonSSOError` 的子类，带有 `error`（OAuth 错误码，或 `network`、`invalid_response`）、`error_description`、`status`、`field`（422 时提供）。

| 异常 | 场景 |
|---|---|
| `SessionExpired` | 刷新令牌被拒（`invalid_grant`），登录已彻底失效 |
| `OtpRequired` | 应用内登录需要两步验证码，交给 `submit_otp` |
| `PasswordChangeRequired` | 管理员重置了密码，`change_url` 指向修改页面 |
| `AuthorizationResponseError` | 回调中 `state`、`iss` 不匹配或带有 `error` |
| `TokenValidationError` / `InsufficientScope` | JWT 校验失败 / scope 不足 |
| `LogoutTokenError` | back-channel logout token 无效或重放 |
| `WebhookVerificationError` | webhook 签名或时间戳无效 |
| `CursorExpired` | 变更流游标超过保留期（410） |

`MoonSSOError.retryable` 为真（网络错误、429、5xx）时，可以稍后重试，登录态不会被清除。SDK 不会把令牌、密钥写入日志；`TokenSet`、`DPoPKey` 等对象的 `repr` 也不包含敏感值。

## 已知服务端问题

- `POST /api/v1/native/register` 的 DPoP 证明，服务端按 `/oauth/authorize-challenge` 的地址校验 `htu`（`server/internal/oidc/challenge.go` 中 `parseChallengeReq` 写死了该地址），与规范 §3“htu 取对应 URL”不一致。SDK 先按规范发送；收到 `invalid_dpop_proof`（htu 不匹配）时，再用 challenge 端点地址重试一次。

## 开发与测试

```bash
python -m venv .venv
.venv/Scripts/python -m pip install -e ".[test]"         # Linux/macOS 为 .venv/bin/python
.venv/Scripts/python -m pytest                            # 集成测试需要本机测试床 http://127.0.0.1:18601
.venv/Scripts/python -m build                             # 生成 dist/ 下的 wheel 和 sdist
```

测试床地址可以用环境变量 `MOON_SSO_TESTBED` 覆盖；测试床不可用时，集成测试会自动跳过。

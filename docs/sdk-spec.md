# Moon SSO SDK 规范（所有语言 SDK 必须遵守）

本文件是各语言 SDK 的共同契约。HTTP 接口的细节见 `server/web/static/openapi.yaml`（线上地址 `https://sso.moonl.cloud/static/<hash>/openapi.yaml`，或 `/openapi.yaml`）。Go SDK（`sdk/go`）是参考实现，行为有疑问时以它为准。

## 0. 通用

- **Issuer**：生产环境是 `https://sso.moonl.cloud`，测试床是 `http://127.0.0.1:18601`。SDK 只接收 issuer，其余地址全部通过 `/.well-known/openid-configuration` 发现。discovery 缓存 1 小时，取失败时沿用过期的缓存。
- 只依赖各语言的主流库。不要自己实现密码学原语，只组合平台或成熟库提供的 JWS、ECDSA、SHA-256、HMAC。
- **User-Agent**：`moon-sso-sdk-<lang>/<version>`，服务端据此在用户的“登录设备”列表里显示为“应用 SDK”。
- **错误模型**：SDK 统一抛出（或返回）带以下字段的错误：
  - `error`：OAuth 错误码，或 `network`、`invalid_response`
  - `error_description`
  - HTTP 状态码
  - `field`：422 校验错误时提供
- **会话失效**：只有 `invalid_grant`（刷新失败）表示会话彻底失效，此时触发 `SessionExpired` / `onSessionExpired`。网络错误、5xx、429 都不能清除登录态。

## 1. 令牌与续期（“无感知续期”）

1. 令牌响应包含 `access_token`（JWT，`typ: at+jwt`，ES256）、`expires_in`、`refresh_token`、`id_token`（RS256 或 ES256）和 `scope`。本地以 `expires_at = now + expires_in` 计算过期时间。**刷新响应只在用户资料自上次签发后有变化时才带 `id_token`**（OIDC Core 12.2 允许省略），SDK 必须把 `id_token` 当作可选字段：带了就用它更新缓存的 profile，没带就保留原值。
2. **主动刷新**：
   - 服务端 SDK：access token 剩余寿命不足 120 秒时刷新。
   - 客户端 SDK（桌面、安卓、浏览器）：用掉 75% 寿命时刷新。另外，每次请求前都检查一次，以覆盖电脑休眠后被唤醒的情况。
3. **single-flight**：同一会话、同一时刻最多只有一个刷新请求，其余调用等待同一个结果。
   - 桌面 SDK：同一份 token 存储被多个进程共享时，再加一把跨进程锁（Windows 命名 Mutex / 文件锁），拿到锁后先重读存储，发现已被别的进程刷新就直接使用。
   - 浏览器 SDK：用 Web Locks API（`navigator.locks.request`），并通过 BroadcastChannel 把新 token 广播给其他标签页。
4. **轮换**：每次刷新返回新的 refresh_token，必须立即原子地持久化，旧值作废。服务端有 60 秒宽限期：同一个旧 refresh token 被重复提交时，服务端返回同一个后继令牌。因此，网络重试或多进程同时刷新都是安全的。
5. **重试**：`refresh_token` 和 `client_credentials` 请求遇到网络错误、连接重置、502、503、504 时，带同样的参数（DPoP 证明重新生成）重试一次。**`authorization_code` 换取不要重试**：授权码只能用一次，服务端会把重复提交的授权码视为攻击，并吊销它已签出的令牌，这时应让用户重新登录。401 加 `invalid_client` 不重试；400 加 `invalid_grant` 视为会话失效。
6. **资源请求的 401 处理**：API 返回 401 时强制刷新一次，再重放原请求一次。仍然 401 就把错误交给调用方，不清除会话（除非刷新本身报 `invalid_grant`）。
7. **ID Token 校验**：
   - 用 discovery 的 `jwks_uri` 取 JWKS，缓存 1 小时；遇到未知 kid 时强制重新拉取，但最多每 30 秒一次。
   - 校验 `iss`、`aud == client_id`、`exp`、`iat`（允许 60 秒时钟偏差），授权码换取时还要校验 `nonce`。`at_hash` 存在时也要校验。
8. **access token 本地校验**（资源服务器场景）：校验签名、`typ == at+jwt`、`iss`、`exp`、`nbf`，以及 `aud` 是否包含期望的受众（本应用的 `client_id`，或调用方配置的 resource）。
9. **授权响应**：必须校验 `state` 和 `iss`（RFC 9207）。`iss` 与 issuer 不同时拒绝。

## 2. 授权流程

- **PKCE S256 永远必需**：`code_verifier` 为 43–128 字符的随机 base64url。`state`、`nonce` 都是 ≥128 位的随机值。
- **Web 服务端**：
  - 回调 `redirect_uri` 必须与登记值完全一致。
  - 推荐 scope：`openid profile offline_access`。
  - 会话里保存 tokens，以及 `expires_at`、`id_token` claims。
  - 识别 HTMX 请求（请求头 `HX-Request: true`）：需要登录时返回 `200` 加 `HX-Redirect: <url>`，不返回 302。
- **原生应用**（桌面、安卓）：
  - 用系统浏览器打开授权页（安卓用 Custom Tabs）。
  - 桌面端的回调是 `http://127.0.0.1:<随机端口>/callback`，服务端对回环地址忽略端口。SDK 起一个一次性本地 HTTP 监听，收到回调后给浏览器回一个“登录完成，可以关闭此页面”的 HTML 页面，并设置 5 分钟超时。
  - 安卓的回调是 `<applicationId>:/oauth2redirect`（反向域名 scheme）或 App Link。
- **第一方应用内登录**：`POST /oauth/authorize-challenge`，请求参数为 `client_id`、`username`、`password`、`scope`、`code_challenge`、`code_challenge_method=S256`。
  - 返回 `200 {"authorization_code"}` 时，用 `grant_type=authorization_code&code=...&code_verifier=...&client_id=...` 换 token，**不带 redirect_uri**。
  - 返回 `400 {"error":"insufficient_authorization","auth_session":"...","required":"otp"}` 时，SDK 回调或抛出 `OtpRequired(authSession)`，应用拿到用户输入的验证码后，再调用一次 challenge，参数为 `auth_session` 和 `otp`。PKCE 参数要与第一次相同，所以 SDK 必须保存 verifier。
  - 返回 `password_change_required` 时，暴露 `change_url`。
- **应用内注册**：`POST /api/v1/native/register`，表单字段为 `client_id`、`username`、`password`、`display_name`、`scope`，以及 PKCE 参数。返回授权码，处理方式同上。422 带 `field`，403 表示 `registration_closed`。
- **普通注册 API**（任何应用的服务端都可以调用）：`POST /api/v1/register`，需要客户端认证，JSON 字段为 `{username, password, display_name}`。
- `GET /api/v1/registration`：返回注册是否开放，以及口令和用户名规则。
- **退出**：
  - 本地清除 tokens。
  - 调用 `/oauth/revoke` 吊销 refresh_token，失败不影响退出。
  - 浏览器或服务端应用可以跳转到 `end_session_endpoint?id_token_hint=...&post_logout_redirect_uri=...&state=...`。

## 3. DPoP（RFC 9449）

公共客户端（SPA、桌面、安卓）**默认启用 DPoP**，客户端设置了 `require_dpop` 时必须启用。

- **密钥**：每个安装一把 P-256 密钥，长期保存。
  - 浏览器：WebCrypto 生成 `extractable:false` 的密钥，存在 IndexedDB。
  - 安卓：Keystore 中的 EC 密钥。
  - 桌面：密钥本身可以导出，但必须存进系统安全存储。
- **证明**：
  - JWS 头为 `{"typ":"dpop+jwt","alg":"ES256","jwk":<公钥 JWK，只含 kty/crv/x/y>}`。
  - claims 为 `{"jti":<随机>, "htm":"POST", "htu":<token 端点完整 URL，不含 query>, "iat":<秒>, "nonce":<最近一次收到的 DPoP-Nonce>}`。
- **nonce**：服务端每个响应都会带 `DPoP-Nonce` 响应头，SDK 记下最新值。收到 `400 use_dpop_nonce` 时，用新 nonce 立即重试一次。
- **授权请求**：附加 `dpop_jkt=<base64url(SHA-256 JWK thumbprint)>`。
- **范围**：DPoP 只用于 `/oauth/token` 和 `/oauth/authorize-challenge`、`/api/v1/native/register`（htu 分别取对应 URL）。资源请求仍然用 `Authorization: Bearer <access_token>`，服务端下发的 access token 是 Bearer 类型。

## 4. 账号 API（`/api/v1`）

| 调用 | 所需 scope | 说明 |
|---|---|---|
| `GET /api/v1/me` | profile | 返回 Profile（`sub`、`preferred_username`、`name`、`nickname`、`picture`、`updated_at`、`profile_version`、`totp_enabled`），ETag 为 `"pv-<n>"` |
| `PATCH /api/v1/me` | `profile:write` | JSON `{"username"?, "display_name"?}`，可带 `If-Match` |
| `PUT /api/v1/me/avatar` | `profile:write` | 请求体为图片原始字节（Content-Type 为图片类型），或 multipart 字段 `avatar`；最大 5 MB |
| `DELETE /api/v1/me/avatar` | `profile:write` | 删除头像 |
| `POST /api/v1/me/password` | `password:write` | JSON `{"current_password","new_password","keep_this_device":true}` |

调用成功后，SDK 立即更新本地缓存的 profile，并触发 `onProfileChanged`。

## 5. 资料同步

### 5.1 SSE（客户端 SDK：桌面、安卓、浏览器、需要实时的服务端）

- 用 HTTP 流读取 `GET /api/v1/me/events`，请求头带 `Authorization: Bearer`、`Accept: text/event-stream`，**不要**用浏览器原生 EventSource，也**不要**把 token 放进 URL。
- 解析 SSE 帧中的 `id:`、`event:`、`data:`、`retry:` 字段，忽略注释行（`: ping`）。
- 断开后按 `retry:` 给出的毫秒数（没有时为 3–8 秒）加上随机抖动重连。重连时：
  - 取有效的 access token，必要时先刷新；
  - 带上 `Last-Event-ID: <最后一个 id>`。
- 事件处理：
  - `user.updated`：用 data 更新本地 profile，或重新调用 `/api/v1/me`，然后触发 `onProfileChanged`。
  - `user.password_changed`、`user.disabled`、`user.deleted`、`consent.revoked`：先尝试刷新一次；刷新报 `invalid_grant` 就触发 `SessionExpired`，刷新成功（说明是当前设备自己改的密码）就继续。
  - `resync`：重新调用 `/api/v1/me`。
  - `token_expired`：刷新后立即重连。
- 应用进入后台时（安卓）可以断开，回到前台再连；Last-Event-ID 保证不会漏事件。

### 5.2 Webhook（服务端 SDK）

- 请求头为 `webhook-id`、`webhook-timestamp`、`webhook-signature`，格式见 Standard Webhooks。
- 签名算法：`v1,` 加 `base64(HMAC_SHA256(key, "{id}.{timestamp}.{body}"))`，其中 key 是 `whsec_` 之后的部分做 base64 解码得到的字节。
- `webhook-signature` 里可能有多个以空格分隔的签名，任意一个匹配即通过；比较必须用常量时间。
- 时间戳与当前时间相差超过 5 分钟时拒绝。
- body 为 Event JSON：`{id, seq, type, occurred_at, data:{sub,status,preferred_username,name,nickname,picture,profile_version,updated_at,changed}}`。
- 接收方按 `profile_version` 丢弃旧事件；`webhook-id` 可用于去重。
- **测试向量**（各 SDK 的单元测试必须通过）：
  - secret：`whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw`
  - id：`msg_p5jXN8AQM9LWM0D4loKWxJek`
  - timestamp：`1614265330`
  - body：`{"test": 2432232314}`
  - 期望签名：`v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=`

### 5.3 Back-Channel Logout（服务端 SDK）

- 接收 `POST`（表单字段 `logout_token`）。
- 用 JWKS 校验签名，并检查：
  - 头部 `typ == "logout+jwt"`；
  - `iss`；
  - `aud` 包含 client_id；
  - `iat` 不晚于当前时间加 60 秒，`exp` 未过期；
  - `events` 中包含键 `http://schemas.openid.net/event/backchannel-logout`；
  - 带有 `sub` 或 `sid`；
  - 不允许出现 `nonce`；
  - `jti` 在 5 分钟内去重。
- 校验通过后调用应用回调 `onLogout(sub, sid)`，返回 200。

### 5.4 变更流（服务端 SDK）

- `client_credentials` 取 token（scope `users:sync`），然后用 `GET /api/v1/users/changes?cursor=&limit=` 分页。
- 游标由应用持久化。返回 410 时，用 `GET /api/v1/users` 全量拉取，记下第一页的 watermark，再从 watermark 继续拉变更流。
- SDK 提供 `syncChanges(cursor) -> (events, nextCursor)` 和 `fullSync()` 的迭代器。

## 6. 动态注册（DCR）

`POST /oauth/register`，请求头 `Authorization: Bearer <initial access token>`，JSON 字段按 RFC 7591：`client_name`、`redirect_uris`、`token_endpoint_auth_method`、`application_type`、`scope`、`webhook_url` 等。SDK 提供 `registerClient(iat, metadata)`，返回 `client_id`、`client_secret?`、`registration_access_token` 和 `status`（`pending_approval`/`active`）。

## 7. 存储

- **桌面**：
  - Windows 用 DPAPI（CurrentUser）加密后写文件，或用 Credential Manager；
  - macOS 用 Keychain；
  - Linux 用 Secret Service（libsecret），不可用时退回 0600 权限的文件，并给出警告。
  - 存储内容为 JSON：refresh_token、access_token、expires_at、id_token、profile、DPoP 私钥。
- **安卓**：用 Keystore AES-GCM 加密后存入 DataStore 或 SharedPreferences；授权进行中的 PKCE、state、nonce 也要落盘，保证进程被杀后还能完成授权。
- **浏览器**：
  - access token 只放内存。
  - 纯 SPA 模式下，refresh token 存 IndexedDB，并且必须 DPoP 绑定，所以即使被读走也无法在别的设备上使用。
  - 推荐 BFF 模式：由 Node SDK 把 token 保存在服务端会话中。

## 8. 测试床（集成测试）

本机运行 `server/bin/testbed.exe`，地址为 `http://127.0.0.1:18601`，其中的数据可以随意破坏。

**固定用户**：

| 用户名 | 密码 | 两步验证 |
|---|---|---|
| alice | `Wonderland-Pass-1` | 无 |
| bob | `Builder-Pass-22` | TOTP 密钥 `JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP` |

**固定客户端**：

| client_id | 类型 | 说明 |
|---|---|---|
| `test-web` | 机密 | secret `test-web-secret-0123456789abcdef`；回调 `http://127.0.0.1:18700/callback`；第一方、免同意；public sub；含 `users:sync` 和 `client_credentials` |
| `test-native` | 公共原生 | 回调 `http://127.0.0.1/callback`、`com.example.test:/oauth2redirect`；第一方，允许应用内登录 |
| `test-native-dpop` | 公共原生 | 同 test-native，但要求 DPoP |
| `test-spa` | 公共浏览器 | 回调 `http://127.0.0.1:18700/`；要求 DPoP；允许应用内登录 |
| `test-third` | 机密 | secret `test-third-secret-0123456789abcd`；第三方，需要同意；pairwise sub |

**测试专用接口**（只在测试床上存在）：

- `POST /__test/authorize`：表单为普通授权参数加 `username`、`password`，替代浏览器完成登录。返回 `{"redirect": "<回调 URL，含 code/state/iss>", "session_token": "..."}`。
- `POST /__test/users`：JSON `{"username","password"}`，创建新用户。会修改密码、用户名或头像的测试，**必须用新建的随机用户**（如 `t_<随机8位>`），不要改 alice 和 bob。
- `POST /__test/users/{username}/profile`：JSON `{"display_name"}`，在服务端修改资料，会触发事件。
- `POST /__test/totp?secret=...`：返回 `{"code"}`。
- `POST /__test/clients/{id}/webhook`：JSON `{"url"}`，返回 `{"secret":"whsec_..."}`，允许 http 回环地址。
- `POST /__test/clients/{id}/backchannel`：JSON `{"url"}`。
- `POST /__test/clients/{id}/trust`：把客户端（如通过 DCR 自己注册的）标记为第一方、免同意、允许应用内登录、public sub。
- `POST /__test/logout?session_token=...`：结束该 SSO 会话，触发 back-channel logout。
- `POST /__test/iat`：返回一次性的 initial access token。

多个 SDK 的测试会并行跑同一个测试床。不要修改共享客户端的 webhook 或 backchannel 配置，需要时用 DCR（`/__test/iat` 加 `/oauth/register`）注册自己的客户端：测试床把应用注册设为 open，注册后立即可用。

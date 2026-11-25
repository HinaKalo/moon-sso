# Moon SSO TypeScript SDK

Moon SSO（OAuth 2.x / OpenID Connect）的官方 TypeScript SDK，包含两个包：

| 包 | 运行环境 | 用途 |
|---|---|---|
| `@moon-sso/browser` | 浏览器（也能在 Node.js ≥ 20 中运行，便于测试和 SSR） | 纯前端 SPA：PKCE 跳转登录、应用内登录（含两步验证）、DPoP 绑定的无感续期、账号 API、实时资料事件 |
| `@moon-sso/node` | Node.js ≥ 20.10 | 服务端：BFF / Web 应用登录与会话、`(req, res, next)` 中间件、资源服务器 access token 校验、Webhook 验签、Back-Channel Logout、变更流、`client_credentials`、动态注册 |

两个包都只依赖平台能力（`fetch`、WebCrypto `crypto.subtle`），没有任何运行时依赖。产物为 ESM，附带 `.d.ts` 类型声明。行为遵守 `docs/sdk-spec.md`。

## 安装

SDK 以 tarball 形式发布在 `https://sso.moonl.cloud/sdk/npm/<包名>-<版本>.tgz`：

```bash
# 浏览器 SPA
npm install https://sso.moonl.cloud/sdk/npm/moon-sso-browser-1.0.0.tgz

# Node.js 服务端
npm install https://sso.moonl.cloud/sdk/npm/moon-sso-node-1.0.0.tgz
```

`package.json` 中会记录为：

```json
{
  "dependencies": {
    "@moon-sso/browser": "https://sso.moonl.cloud/sdk/npm/moon-sso-browser-1.0.0.tgz",
    "@moon-sso/node": "https://sso.moonl.cloud/sdk/npm/moon-sso-node-1.0.0.tgz"
  }
}
```

只用 TypeScript 时建议 `"module": "NodeNext"`（Node）或 `"moduleResolution": "Bundler"`（前端打包器）。

SDK 只需要 issuer（生产环境 `https://sso.moonl.cloud`），其余地址都通过 `/.well-known/openid-configuration` 发现，发现文档缓存 1 小时，取不到时沿用旧缓存。

---

## 一、浏览器 SPA（`@moon-sso/browser`）

### 初始化

```ts
import { createMoonSso, MoonSsoError, OtpRequiredError, PasswordChangeRequiredError } from '@moon-sso/browser';

const sso = await createMoonSso({
  issuer: 'https://sso.moonl.cloud',
  clientId: 'my-spa',
  redirectUri: 'https://app.example.com/',            // 必须与登记值完全一致
  postLogoutRedirectUri: 'https://app.example.com/',
  scope: 'openid profile offline_access profile:write',
});

sso.on('sessionExpired', () => showLoginPage());       // 只有 invalid_grant 才会触发
sso.on('profileChanged', (p) => renderProfile(p));
```

默认存储方式：

- access token 只放在内存中；
- refresh token 存在 IndexedDB，并且通过 DPoP 绑定到本机密钥，即使被读走也无法在别处使用；
- DPoP 私钥由 WebCrypto 生成（`extractable: false`），存在 IndexedDB，每个安装一把，长期使用。

### 跳转登录（PKCE + state + nonce + iss 校验）

```ts
// 登录按钮
await sso.login({ returnTo: '/settings' });

// 回调页（redirectUri 对应的页面）启动时
if (sso.isRedirectCallback()) {
  const { user, returnTo } = await sso.handleRedirectCallback(); // 校验 state、iss、nonce、at_hash、ID Token 签名
  history.replaceState(null, '', returnTo ?? '/');
}
```

`handleRedirectCallback` 换取令牌时会带上 DPoP 证明，遇到 `use_dpop_nonce` 自动用服务端 nonce 重试一次。

### 应用内登录（第一方应用，含两步验证）

```ts
try {
  await sso.signIn(username, password);
} catch (e) {
  if (e instanceof OtpRequiredError) {
    const code = await askUserForOtp();
    await sso.verifyOtp(e.authSession, code);   // SDK 自动复用第一次的 PKCE verifier
  } else if (e instanceof PasswordChangeRequiredError) {
    location.href = e.changeUrl;                // 管理员重置了口令，需先在浏览器中改密
  } else {
    throw e;
  }
}
```

验证码错误时 `verifyOtp` 会再次抛出 `OtpRequiredError`，可以让用户重新输入。

### 应用内注册

```ts
const info = await sso.registrationInfo();          // 是否开放注册、用户名和口令规则
try {
  await sso.register({ username, password, displayName });  // 成功后直接处于登录状态
} catch (e) {
  if (e instanceof MoonSsoError && e.status === 422) highlightField(e.field);
  if (e instanceof MoonSsoError && e.status === 403) showClosed();      // registration_closed
}
```

### 调用 API 与无感续期

```ts
const token = await sso.getAccessToken();           // 用掉 75% 寿命后自动刷新；每次调用前都会检查
const res = await sso.fetch('https://api.example.com/orders');  // 自动带 Bearer；401 时刷新一次并重放一次
```

续期规则：

- 同一时刻只有一个刷新请求：标签页内部用 single-flight，标签页之间用 Web Locks（`navigator.locks`）。拿到锁后会重新读取 IndexedDB，如果别的标签页已经刷新过，就直接用它通过 BroadcastChannel 广播的新 token。
- 网络错误、502/503/504 时，用同样的参数重试一次（DPoP 证明重新生成）。
- 只有 `invalid_grant` 会清除登录态并触发 `sessionExpired`；网络错误、5xx、429 都不会。
- `invalid_client` 不重试。

### 账号 API

```ts
const me = await sso.getMe();
await sso.updateProfile({ displayName: '新昵称' });            // 需要 profile:write
await sso.uploadAvatar(fileInput.files![0]!);                   // Blob/ArrayBuffer/Uint8Array，≤ 5 MB
await sso.deleteAvatar();
await sso.changePassword({ currentPassword, newPassword });     // 需要 password:write；本设备保持登录
```

每次调用成功后，本地缓存的 profile（`sso.profile`）都会更新，并触发 `profileChanged`。

### 实时事件（SSE）

```ts
await sso.startEvents();          // 基于 fetch 的 SSE，Authorization 头鉴权，不把 token 放进 URL
sso.on('event', (ev) => console.log(ev.type, ev.data));
// 断线后按 retry: 提示（默认 3–8 秒）加随机抖动重连，并带 Last-Event-ID 续传
await sso.stopEvents();
```

- `user.updated`：更新本地 profile，触发 `profileChanged`；
- `user.password_changed` / `user.disabled` / `user.deleted` / `consent.revoked`：先尝试刷新一次，`invalid_grant` 就触发 `sessionExpired`；
- `resync`：重新调用 `/api/v1/me`；
- `token_expired`：刷新后立即重连。

### 退出

```ts
await sso.logout();                       // 清除本地 token，吊销 refresh token（失败不影响退出），通知其他标签页
await sso.logout({ endSession: true });   // 再跳转到 end_session_endpoint，结束 SSO 会话
```

### 自定义存储、锁与标签页同步

在 Node.js、测试环境或受限浏览器中，可以替换默认实现：

```ts
import { MoonSso, MemoryStore, InProcessLockProvider } from '@moon-sso/browser';

const sso = new MoonSso({
  issuer, clientId,
  storage: new MemoryStore(),             // 实现 KeyValueStore { get, set, delete }
  locks: new InProcessLockProvider(),     // 实现 LockProvider { withLock(name, fn) }
  channel: null,                          // 或实现 TabChannel { post, subscribe, close }
});
await sso.init();
```

---

## 二、Node.js 服务端 / BFF（`@moon-sso/node`）

推荐 BFF 模式：token 只保存在服务端会话中，浏览器只持有 HttpOnly 会话 Cookie。

### Express 示例

```ts
import express from 'express';
import {
  MoonSsoClient, SessionManager, MemorySessionStore, moonSsoMiddleware, requireLogin,
  BackchannelLogoutVerifier, type RequestWithMoonSso,
} from '@moon-sso/node';

const client = new MoonSsoClient({
  issuer: 'https://sso.moonl.cloud',
  clientId: process.env.MOON_SSO_CLIENT_ID!,
  clientSecret: process.env.MOON_SSO_CLIENT_SECRET!,     // 默认 client_secret_basic
  redirectUri: 'https://app.example.com/auth/callback',
  postLogoutRedirectUri: 'https://app.example.com/',
  scope: 'openid profile offline_access',
});
const sessions = new SessionManager({ client, store: new MemorySessionStore() }); // 生产环境换成 Redis/数据库实现

const app = express();
app.use(moonSsoMiddleware({
  client,
  sessions,
  // 默认路由：/auth/login、/auth/callback（取自 redirectUri）、/auth/logout、/auth/backchannel-logout
  backchannel: { verifier: new BackchannelLogoutVerifier({ issuer: client.issuer, clientId: client.clientId, jwks: client.jwks }) },
  requireAuth: (req) => req.url?.startsWith('/app') ?? false,
}));

app.get('/app/me', requireLogin(), async (req, res) => {
  const ctx = (req as unknown as RequestWithMoonSso).moonSso;
  res.json(await ctx.account().getMe());     // access token 剩余不足 120 秒时自动刷新
});
```

中间件做的事：

- `GET /auth/login?returnTo=/x`：生成 PKCE、state、nonce，存入会话后跳转授权页；`returnTo` 只接受站内相对路径，防止开放重定向。
- `GET /auth/callback`：校验 state、iss，用 code + verifier + 完全一致的 redirect_uri 换取令牌，校验 ID Token（签名、iss、aud、exp、iat、nonce、at_hash），然后**轮换会话 ID**（防会话固定）。
- `POST /auth/logout`：吊销 refresh token、删除会话、清除 Cookie，再跳转到 `end_session_endpoint`。
- `POST /auth/backchannel-logout`：校验 logout token，按 `sid`（或 `sub`）删除会话。
- 其余请求：挂上 `req.moonSso`（`isAuthenticated`、`user`、`getAccessToken()`、`account()`、`requireLogin()`）。

**HTMX**：请求头带 `HX-Request: true` 时，需要登录的响应是 `200` + `HX-Redirect: <登录地址>`，不是 302。也可以直接用 `redirect(req, res, url)` 辅助函数。API 请求（`Accept` 不含 `text/html`）则返回 `401 {"error":"login_required"}`。

会话存储接口：

```ts
interface SessionStore {
  get(id: string): Promise<SessionData | undefined>;
  set(id: string, data: SessionData, ttlSeconds: number): Promise<void>;
  delete(id: string): Promise<void>;
  deleteBySid?(sid: string): Promise<number>;   // back-channel logout 需要
  deleteBySub?(sub: string): Promise<number>;
}
```

同一会话的并发刷新是 single-flight 的（进程内），刷新前会重新读取存储；多实例部署时，服务端 60 秒宽限期保证并发刷新安全。新的 refresh token 会立即写回存储。

### 不用中间件：手动流程

```ts
const { url, pending } = await client.createAuthorizationUrl({ returnTo: '/' });
// 把 pending 存在服务端会话里，然后跳转到 url
const tokens = await client.handleCallback(req.url!, pending);   // TokenSet：accessToken、refreshToken、idToken、expiresAt（秒）、claims
const fresh = await client.refresh(tokens.refreshToken!, { previous: tokens });
const info = await client.userinfo(fresh.accessToken);
const endUrl = await client.endSessionUrl({ idTokenHint: tokens.idToken });
await client.revoke(tokens.refreshToken!);
```

### 资源服务器：校验 access token

```ts
import { AccessTokenVerifier } from '@moon-sso/node';

const verifier = new AccessTokenVerifier({
  issuer: 'https://sso.moonl.cloud',
  audience: 'my-api',            // 本应用的 client_id 或配置的 resource
});

app.use('/api', verifier.middleware({ scopes: ['profile'] }));   // 成功后 req.auth 为 claims
// 或手动：const claims = await verifier.verify(token, { scopes: [...] });
```

校验内容：签名（JWKS 缓存 1 小时，遇到未知 kid 强制重取，但最多每 30 秒一次）、`typ == at+jwt`、`iss`、`exp`/`nbf`（允许 60 秒偏差）、`aud` 包含期望受众，以及可选的 scope。失败时返回 401（`WWW-Authenticate: Bearer error="invalid_token"`）或 403（`insufficient_scope`）。

### Webhook（Standard Webhooks）

```ts
import { createWebhookHandler } from '@moon-sso/node';

// 必须拿到原始请求体：放在 JSON body parser 之前，或使用 express.raw()
app.post('/webhooks/moon-sso', express.raw({ type: '*/*' }), createWebhookHandler({
  secret: process.env.MOON_SSO_WEBHOOK_SECRET!,   // whsec_...
  onEvent: async (event) => {
    // 按 data.profile_version 丢弃旧事件
    await upsertUser(event.data);
  },
}));
```

`WebhookVerifier` 计算 `v1,base64(HMAC_SHA256(key, "{id}.{timestamp}.{body}"))`；`webhook-signature` 里有多个签名时任意一个匹配即通过；用 WebCrypto 做常量时间比较；时间戳与当前时间相差超过 5 分钟就拒绝。处理器默认按 `webhook-id` 去重 10 分钟，成功返回 204，验签失败返回 400，`onEvent` 抛错时返回 500（服务端稍后重投）。

### Back-Channel Logout

```ts
import { BackchannelLogoutVerifier, createBackchannelLogoutHandler } from '@moon-sso/node';

const verifier = new BackchannelLogoutVerifier({ issuer, clientId, jwks: client.jwks });
app.post('/auth/backchannel-logout', createBackchannelLogoutHandler({
  verifier,
  onLogout: async (sub, sid) => { await destroySessions({ sub, sid }); },
}));
```

校验：签名、`typ == logout+jwt`、`iss`、`aud` 包含 client_id、`iat` 不晚于当前时间加 60 秒、`exp` 未过期、`events` 包含 back-channel-logout 事件、带有 `sub` 或 `sid`、不允许出现 `nonce`、`jti` 5 分钟内去重。使用 `moonSsoMiddleware` 时只要传入 `backchannel` 选项即可。

### 变更流（client_credentials，scope `users:sync`）

```ts
const feed = client.changesFeed();          // client_credentials token 自动缓存，剩余不足 120 秒时更新

let cursor = await loadCursor();            // 游标由应用持久化
for await (const item of feed.changes(cursor)) {
  if (item.kind === 'snapshot') {           // 游标过期（410）时先全量同步
    await replaceUsers(item.users);
    cursor = item.watermark;                // 第一页的 watermark
  } else {
    await applyEvents(item.events);
    cursor = item.cursor;
  }
  await saveCursor(cursor);
}

// 底层接口
const page = await feed.syncChanges(cursor, { limit: 200 });   // { events, nextCursor, hasMore }，410 抛 CursorExpiredError
for await (const p of feed.fullSync()) { /* p.users, p.watermark */ }
```

### 服务端注册 API

```ts
const rules = await client.registrationInfo();
const r = await client.registerUser({ username, password, displayName });  // POST /api/v1/register，需要客户端认证
// 然后带 login_hint 继续授权流程
const { url } = await client.createAuthorizationUrl({ loginHint: r.login_hint });
```

### 动态注册（DCR）

```ts
import { registerClient, ClientRegistration } from '@moon-sso/node';

const info = await registerClient({
  issuer: 'https://sso.moonl.cloud',
  initialAccessToken: 'iat_...',             // 在开发者中心生成
  metadata: {
    client_name: 'My App',
    redirect_uris: ['https://app.example.com/auth/callback'],
    token_endpoint_auth_method: 'client_secret_basic',
    application_type: 'web',
    scope: 'openid profile offline_access',
    webhook_url: 'https://app.example.com/webhooks/moon-sso',
  },
});
// info.client_id、info.client_secret、info.registration_access_token、info.status（active / pending_approval）
const manage = new ClientRegistration(info.registration_client_uri!, info.registration_access_token);
```

---

## 错误模型

所有失败都会抛出 `MoonSsoError`：

| 字段 | 含义 |
|---|---|
| `error` | OAuth 错误码，或 `network`、`invalid_response`、`login_required` 等 SDK 错误码 |
| `error_description` | 服务端描述 |
| `status` | HTTP 状态码（网络错误时没有） |
| `field` | 422 校验错误对应的字段 |

子类：`OtpRequiredError`（`authSession`）、`PasswordChangeRequiredError`（`changeUrl`）、`CursorExpiredError`、`WebhookVerificationError`。`e.isSessionExpired` 等价于 `e.error === 'invalid_grant'`。错误信息中不会出现 token、密钥或口令。

Node SDK 的请求头 `User-Agent` 为 `moon-sso-sdk-node/1.0.0`（可用 `userAgentSuffix` 追加应用名）。浏览器不允许脚本设置 User-Agent，浏览器 SDK 不设置该头。

## 浏览器使用注意事项（当前服务端版本）

- 服务端 CORS 预检只允许 `Authorization, Content-Type, DPoP, Last-Event-ID, Idempotency-Key` 请求头，因此浏览器 SDK 的 `getMe()` 不发送 `If-None-Match`；`updateProfile(..., { ifMatch })` 在浏览器中会被预检拦截，只在 Node 中可用。
- `/oauth/authorize-challenge` 与 `/api/v1/native/register` 的响应目前不带 `Access-Control-Allow-Origin`，跨域 SPA 的应用内登录 / 注册会被浏览器拦截；请把 SPA 部署在与 SSO 同源的位置，或改用跳转登录，直到服务端修复。
- `/api/v1/*` 返回 401 时不带 CORS 头，浏览器只能看到网络错误。SDK 会在过期前主动刷新，因此正常使用不受影响。

## 开发

```bash
cd sdk/typescript
npm install                  # 只安装 typescript 和 @types/node（开发依赖）
npm run build                # 同步 shared/ 到各包后用 tsc 编译
npm run typecheck            # 编译 + 测试代码类型检查
npm run test:unit            # 单元测试（node --test）
npm run test:integration     # 集成测试，需要本机测试床 http://127.0.0.1:18601
npm run pack                 # 生成 dist-pkg/moon-sso-browser-1.0.0.tgz 和 dist-pkg/moon-sso-node-1.0.0.tgz
```

目录结构：

```
sdk/typescript/
  shared/            两个包共用的核心代码（错误模型、编码、JWS/JWKS、PKCE、DPoP、OAuth 请求、SSE、账号 API）
  packages/browser/  @moon-sso/browser
  packages/node/     @moon-sso/node
  test-support/      测试辅助（测试床接口、本地签名密钥）
  examples/express-bff/  Express BFF 示例
  examples/spa/          无打包器的 SPA 示例（ES Modules + import map）
  dist-pkg/          npm pack 产物
```

`shared/` 会在构建时复制到各包的 `src/shared/`（生成文件，不要直接修改）。集成测试通过环境变量 `MOON_SSO_TESTBED` 可以指向其他测试床地址；测试只使用新建的随机用户和自己通过 DCR 注册的客户端，不会修改共享夹具。

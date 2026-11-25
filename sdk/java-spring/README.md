# Moon SSO Spring Boot Starter

`cloud.moonl.sso:moon-sso-spring-boot-starter` 是 Moon SSO（OAuth 2.x / OpenID Connect）的 Spring Boot 集成。只需配置 issuer、client_id 和 client_secret，就能获得：

- **登录**：授权码 + PKCE S256（机密客户端同样强制 PKCE）、`state`、`nonce`，校验授权响应中的 `iss`（RFC 9207），ID Token 支持 RS256/ES256 并校验 `at_hash`。
- **无感知续期**：令牌保存在 HTTP 会话中，由 `OAuth2AuthorizedClientManager` 在剩余寿命不足 120 秒时自动刷新；同一会话的并发刷新只发出一次请求；token 端点遇到网络错误或 502/503/504 时原样重试一次；只有 `invalid_grant` 才会结束登录态。
- **后端通道登出**（OIDC Back-Channel Logout）：校验 `typ=logout+jwt`、`iss`、`aud`、`iat`/`exp`、`events`、`sub`/`sid`、禁止 `nonce`，`jti` 5 分钟内防重放，然后按 `sid`/`sub` 结束本地会话。
- **资源服务器**：本地校验 access token（ES256、`typ=at+jwt`、`iss`、`aud`、`exp`、`nbf`）。
- **HTMX**：需要登录的 HTMX 请求返回 `200` + `HX-Redirect`，而不是 302。
- **Webhook**：校验 Standard Webhooks 签名（通过规范测试向量），按 `webhook-id` 去重、丢弃旧的 `profile_version`，再以 Spring `ApplicationEvent`（`UserUpdatedEvent` 等）发布。
- **账号 API**：`MoonSsoAccountClient` 以当前登录用户的身份读写 `/api/v1/me`（资料、头像、密码），遇到 401 自动强制刷新并重放一次。
- **用户同步**：`MoonSsoUserSync` 用 client_credentials 拉取变更流，游标过期（410）时自动全量同步并从 watermark 继续。
- **注册**：`MoonSsoRegistrationClient` 调用 `POST /api/v1/register` 和动态客户端注册（RFC 7591/7592）。

所有请求的 `User-Agent` 为 `moon-sso-sdk-java/<版本>`。日志中不会输出令牌、密钥或密码。

## 环境要求

- Java 21+
- Spring Boot 4.2（Spring Framework 7.1、Spring Security 7.2、Jackson 3），Servlet 栈（Spring MVC）

## 引入依赖

制品发布在静态 Maven 仓库 `https://sso.moonl.cloud/sdk/maven`。

Gradle（Kotlin DSL）：

```kotlin
repositories {
    mavenCentral()
    maven("https://sso.moonl.cloud/sdk/maven")
}

dependencies {
    implementation("cloud.moonl.sso:moon-sso-spring-boot-starter:0.1.0")
}
```

Maven：

```xml
<repositories>
  <repository>
    <id>moon-sso</id>
    <url>https://sso.moonl.cloud/sdk/maven</url>
  </repository>
</repositories>

<dependency>
  <groupId>cloud.moonl.sso</groupId>
  <artifactId>moon-sso-spring-boot-starter</artifactId>
  <version>0.1.0</version>
</dependency>
```

starter 会带入 `spring-boot-starter-webmvc`、`spring-boot-starter-security-oauth2-client`、`spring-boot-starter-security-oauth2-resource-server` 和 `spring-boot-starter-restclient`。

## 最小配置

在开发者中心创建应用，登记回调地址 `https://app.example.com/login/oauth2/code/moon-sso`，然后：

```yaml
moon-sso:
  issuer: https://sso.moonl.cloud
  client-id: ms_xxxxxxxxxxxx
  client-secret: ${MOON_SSO_CLIENT_SECRET}   # 不要把密钥写进仓库
  scopes: openid,profile,offline_access,profile:write
```

应用没有定义 `SecurityFilterChain` 时，starter 会提供一个默认的：除 `/error` 和 `/favicon.ico` 外所有地址都需要登录。

### 全部配置项

| 配置 | 默认值 | 说明 |
|---|---|---|
| `moon-sso.issuer` | — | 必填。其余地址都通过 `/.well-known/openid-configuration` 发现（缓存 1 小时，刷新失败时继续用旧值） |
| `moon-sso.client-id` | — | 必填 |
| `moon-sso.client-secret` | — | 机密客户端的密钥；为空时按公共客户端（`none`）处理，且不启用用户同步 |
| `moon-sso.scopes` | `openid,profile,offline_access` | 登录时申请的 scope；修改资料需要 `profile:write`，改密码需要 `password:write` |
| `moon-sso.registration-id` | `moon-sso` | Spring Security 的 registration id，登录入口为 `/oauth2/authorization/{id}` |
| `moon-sso.redirect-uri` | `{baseUrl}/login/oauth2/code/{registrationId}` | 必须与登记的回调地址完全一致 |
| `moon-sso.client-authentication-method` | 有密钥时 `client_secret_basic`，否则 `none` | 也可用 `client_secret_post` |
| `moon-sso.post-logout-redirect-uri` | `{baseUrl}/` | RP 发起登出后跳回的地址，需在应用中登记；置空则不带该参数 |
| `moon-sso.refresh-skew` | `120s` | access token 剩余寿命低于此值时刷新 |
| `moon-sso.clock-skew` | `60s` | 校验 JWT 时间类 claim 时允许的时钟偏差 |
| `moon-sso.discovery-ttl` | `1h` | discovery 缓存时间 |
| `moon-sso.connect-timeout` / `read-timeout` | `10s` / `30s` | 访问授权服务器的超时 |
| `moon-sso.login.default-security-filter-chain` | `true` | 应用未定义 `SecurityFilterChain` 时是否提供默认链 |
| `moon-sso.login.processing-url` | Spring 默认 `/login/oauth2/code/*` | 回调路径，需与 `redirect-uri` 的路径一致 |
| `moon-sso.login.failure-url` | `/moon-sso/login-error` | 登录失败（含 `iss` 不匹配）时跳转的地址；默认是 starter 提供的简单页面（只显示错误代码和“重新登录”链接），避免失败后又被立即送回 SSO |
| `moon-sso.login.user-name-attribute` | `sub` | 作为 principal 名称的 claim |
| `moon-sso.login.permit-all` | `/error,/favicon.ico` | 默认链中无需登录的路径 |
| `moon-sso.login.htmx` | `true` | HTMX 请求返回 200 + `HX-Redirect` |
| `moon-sso.login.revoke-on-logout` | `true` | 本地登出时吊销 refresh token |
| `moon-sso.resource-server.enabled` | `false` | 在 starter 的安全配置中接受 Bearer access token |
| `moon-sso.resource-server.audiences` | client-id | access token 的 `aud` 必须包含其中之一 |
| `moon-sso.webhook.secret` | — | `whsec_...`；设置后才启用 Webhook 端点 |
| `moon-sso.webhook.path` | `/moon-sso/webhooks` | Webhook 端点路径 |
| `moon-sso.webhook.tolerance` | `5m` | 时间戳允许偏差 |
| `moon-sso.webhook.max-body-bytes` | `262144` | 请求体上限 |
| `moon-sso.backchannel-logout.enabled` | `true` | 启用后端通道登出端点 |
| `moon-sso.backchannel-logout.path` | `/moon-sso/backchannel-logout` | 在应用中登记为 `backchannel_logout_uri` |
| `moon-sso.backchannel-logout.replay-window` | `5m` | `jti` 去重窗口 |
| `moon-sso.sync.scope` | `users:sync` | client_credentials 申请的 scope |
| `moon-sso.sync.page-size` | `100` | 变更流与快照的分页大小（最大 500） |

## 自定义安全配置

需要自己的访问规则时定义 `SecurityFilterChain`，再调用 `MoonSsoSecurity#apply`：

```java
@Configuration
class SecurityConfig {

    @Bean
    SecurityFilterChain security(HttpSecurity http, MoonSsoSecurity moonSso) {
        http.authorizeHttpRequests(a -> a
            .requestMatchers("/", "/css/**", "/error").permitAll()
            .anyRequest().authenticated());
        moonSso.apply(http);   // 登录、iss 校验、自动续期、HTMX、登出
        return http.build();
    }
}
```

`apply` 会配置：

- `oauth2Login()`：强制 PKCE 的授权请求、失败地址、回调路径；ID Token 解码器（共享 JWKS 缓存，未知 `kid` 时最多每 30 秒重新拉取一次）、`at_hash` 校验和带重试的 token 客户端都以 bean 形式提供，Spring Security 会自动采用；
- 回调前校验 `iss` 参数；
- `oauth2Client()`；
- HTMX 感知的认证入口（XHR 返回 401，开启资源服务器时 Bearer 请求返回 `WWW-Authenticate`）；
- 登出：先吊销 refresh token，再跳转到 `end_session_endpoint`（带 `id_token_hint` 和 `post_logout_redirect_uri`）。登出需 `POST /logout` 并携带 CSRF token。

Webhook 和后端通道登出端点由 Servlet Filter 处理，位于 Spring Security 之前，不需要放行规则，也不需要 CSRF token。

## 读取当前用户

```java
@GetMapping("/")
String home(@AuthenticationPrincipal OidcUser user, Model model) {
    model.addAttribute("name", user.getPreferredUsername());
    model.addAttribute("sub", user.getSubject());
    return "index";
}
```

## 账号 API

`MoonSsoAccountClient` 使用当前请求中登录用户的令牌，过期前自动刷新：

```java
@Controller
class ProfileController {

    private final MoonSsoAccountClient account;

    ProfileController(MoonSsoAccountClient account) {
        this.account = account;
    }

    @GetMapping("/profile")
    String profile(Model model) {
        model.addAttribute("profile", account.getProfile());          // GET /api/v1/me（带 If-None-Match）
        return "profile";
    }

    @PostMapping("/profile")
    String update(@RequestParam String displayName, @RequestParam long version) {
        try {
            account.updateProfile(ProfileUpdate.displayName(displayName), version); // If-Match: "pv-<version>"
        } catch (MoonSsoException ex) {
            if (ex.isVersionConflict()) { /* 412：资料已在别处被修改 */ }
            if ("validation_failed".equals(ex.getError())) { /* 422：ex.getField() 指出字段 */ }
        }
        return "redirect:/profile";
    }
}
```

其他方法：

```java
account.updateProfile(ProfileUpdate.username("new_name"));
account.uploadAvatar(bytes, MediaType.IMAGE_PNG);          // ≤ 5 MB
account.deleteAvatar();
account.changePassword(current, next, true);                // true：保留本设备的会话
```

每次修改成功后都会更新会话中缓存的资料，并发布 `MoonSsoProfileChangedEvent`。在后台任务等没有浏览器会话的场景，可以用 `account.withTokenSource(MoonSsoTokenSource.of(accessToken))` 指定令牌。

刷新返回 `invalid_grant` 时（用户在别处退出、改密码、撤销授权等），令牌被移除，抛出 `MoonSsoSessionExpiredException` 并发布 `MoonSsoSessionExpiredEvent`；在 Spring MVC 请求里该异常会让浏览器自动重新走登录流程。网络错误、5xx、429 不会清除登录态。

## HTMX

```html
<button hx-get="/profile/card" hx-target="#card">刷新</button>
```

会话失效时，这个请求得到 `200` 和 `HX-Redirect: /oauth2/authorization/moon-sso`，HTMX 会整页跳转去登录。HTMX 请求不会被记为“登录后返回的页面”。

## 资源服务器

```yaml
moon-sso:
  resource-server:
    enabled: true
    audiences: ms_xxxxxxxxxxxx          # 默认就是 client-id
```

也可以直接注入 `MoonSsoAccessTokenDecoder`（实现了 `JwtDecoder`）：

```java
Jwt jwt = accessTokenDecoder.decode(bearerToken);
```

## Webhook

1. 在开发者中心把 Webhook 地址设为 `https://app.example.com/moon-sso/webhooks`，记下 `whsec_...` 密钥。
2. 配置 `moon-sso.webhook.secret`。
3. 监听事件：

```java
@Component
class UserEvents {

    @EventListener
    void onUpdated(UserUpdatedEvent event) {
        // event.sub()、event.data().preferredUsername()、event.data().nickname()、event.data().picture()
        // 按 profile_version 丢弃比本地更旧的数据
        users.applyIfNewer(event.sub(), event.data().profileVersion(), event.data());
    }

    @EventListener
    void onDeleted(UserDeletedEvent event) {
        users.delete(event.sub());
    }

    @EventListener
    void onAny(MoonSsoEvent event) {
        // UserPasswordChangedEvent、UserDisabledEvent、UserEnabledEvent、ConsentRevokedEvent、
        // WebhookPingEvent（开发者中心的测试推送）、UnknownMoonSsoEvent（新类型）
    }
}
```

端点的响应：处理成功或重复投递返回 `204`；签名或时间戳不对返回 `401`；监听器抛异常返回 `500`，服务端会按退避策略重投。去重缓存在内存中，多实例部署时可以提供自己的 `ReplayCache` bean（例如基于 Redis），或在业务里用 `event.id()` 去重。

## 后端通道登出

在应用中把 `backchannel_logout_uri` 登记为 `https://app.example.com/moon-sso/backchannel-logout`。用户在 SSO 退出（或被管理员移除设备、修改密码）时，starter 会使已登录的本地会话失效，并发布：

```java
@EventListener
void onLogout(MoonSsoBackChannelLogoutEvent event) {
    // event.sub()、event.sid()、event.sessionsEnded()
}
```

默认的 `InMemoryMoonSsoSessionRegistry` 保存容器的会话对象，适用于单实例、容器管理会话的应用。使用 Spring Session 或多实例部署时，请提供自己的 `MoonSsoSessionRegistry` bean（例如基于 `FindByIndexNameSessionRepository` 按 `sid` 删除会话），并提供共享的 `ReplayCache`。

## 用户同步（变更流）

需要机密客户端，并在应用中开启 `client_credentials` 和 `users:sync`：

```java
@Component
class UserSyncJob {

    private final MoonSsoUserSync sync;
    private final CursorStore cursors;
    private final UserRepository users;

    @Scheduled(fixedDelay = 60_000)
    void run() {
        sync.synchronize(cursors.load(), new MoonSsoSyncHandler() {
            @Override public void onFullSyncStart(String watermark) { users.markAllStale(); }
            @Override public void onUser(MoonSsoUserSnapshot u)     { users.upsert(u); }
            @Override public void onEvent(MoonSsoEvent e)           { users.apply(e); }
            @Override public void onCursor(String cursor)           { cursors.save(cursor); }
        });
    }
}
```

- 没有游标或游标过期（410）时先调用 `GET /api/v1/users` 全量拉取，记下第一页的 watermark，再从 watermark 继续拉变更流。
- 底层方法：`syncChanges(cursor)` 返回 `ChangesPage(events, nextCursor, hasMore)`，游标过期时抛 `MoonSsoCursorExpiredException`；`fullSync()` 返回可迭代的 `FullSync`（`watermark()` + 惰性分页）；`getUser(sub)` 查询单个用户。
- `pollAndPublish(cursor, onUser)` 会把变更作为 `MoonSsoEvent`（`source() == CHANGES_FEED`）发布，可以与 Webhook 共用同一套监听器。

## 注册

```java
// 应用服务端代用户注册（需要机密客户端）
RegistrationResult r = registrationClient.register("new_user", password, "显示名");
// 随后引导用户登录，login_hint = r.loginHint()

// 注册是否开放、口令与用户名规则
RegistrationInfo info = registrationClient.registrationInfo();

// 动态客户端注册（RFC 7591），iat 在开发者中心生成
ClientInformation client = registrationClient.registerClient(iat, ClientMetadata.builder()
    .clientName("我的应用")
    .redirectUris(List.of("https://app.example.com/login/oauth2/code/moon-sso"))
    .grantTypes(List.of("authorization_code", "refresh_token"))
    .tokenEndpointAuthMethod("client_secret_basic")
    .scope("openid profile offline_access")
    .backchannelLogoutUri("https://app.example.com/moon-sso/backchannel-logout")
    .build());
// client.clientId()、client.clientSecret()、client.registrationAccessToken()、client.status()
// RFC 7592：readClient / updateClient / deleteClient
```

## 错误模型

所有调用失败时抛出 `MoonSsoException`：

| 方法 | 含义 |
|---|---|
| `getError()` | OAuth 错误码，或 `network`、`invalid_response` |
| `getErrorDescription()` | 服务端的说明 |
| `getStatus()` | HTTP 状态码（未收到响应时为 0） |
| `getField()` | 422 校验错误的字段 |
| `isTransient()` | 网络错误、429、5xx |
| `isVersionConflict()` | 412 |

子类：`MoonSsoSessionExpiredException`（`invalid_grant`）、`MoonSsoCursorExpiredException`（410）。

## 示例应用

`example/` 是一个 Thymeleaf 应用，演示登录、资料与头像修改、HTMX 片段刷新、Webhook 与后端通道登出事件。默认连接本机测试床的 `test-web` 客户端（回调 `http://127.0.0.1:18700/callback`）：

```bash
export JAVA_HOME="C:/Program Files/Eclipse Adoptium/jdk-21.0.13.9-hotspot"
export MOON_SSO_CLIENT_SECRET=<test-web 的密钥>
./gradlew :example:bootRun
# 打开 http://127.0.0.1:18700/
```

连接其他环境时设置 `MOON_SSO_ISSUER`、`MOON_SSO_CLIENT_ID`、`MOON_SSO_CLIENT_SECRET`、`MOON_SSO_REDIRECT_URI`、`MOON_SSO_WEBHOOK_SECRET`。

## 构建与测试

```bash
./gradlew test                    # 单元测试，不需要网络
./gradlew integrationTest         # 集成测试，需要测试床（MOON_SSO_TESTBED，默认 http://127.0.0.1:18601）
./gradlew build                   # 编译、两类测试、打包
./gradlew publishToBuildRepo      # 发布到 build/repo（静态 Maven 仓库）
```

集成测试只修改自己新建的随机用户和通过 DCR 注册的客户端，结束后会删除该客户端。

## 设计说明

- 令牌存放在 HTTP 会话（`HttpSessionOAuth2AuthorizedClientRepository`）；client_credentials 令牌存放在内存中的 `OAuth2AuthorizedClientService`。
- discovery 失败不会阻止应用启动；客户端配置在首次使用时解析。
- 所有扩展点（`ClientRegistrationRepository`、`OAuth2AuthorizedClientRepository`、`ReplayCache`、`MoonSsoSessionRegistry`、各解码器）都可以用同类型的 bean 替换。

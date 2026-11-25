# Moon SSO Go SDK

```
go get sso.moonl.cloud/sdk/go@latest
```

模块由 `sso.moonl.cloud` 自己托管，它实现了 Go module proxy 协议，所以 `go get` 可以直接使用。如果你配置了企业代理，请在 `GOPRIVATE` 里加上 `sso.moonl.cloud`。

| 包 | 用途 |
|---|---|
| `sso.moonl.cloud/sdk/go` | 核心：发现、PKCE、令牌、DPoP、会话与自动续期、账号 API、实时事件、Webhook、Back-Channel Logout、变更流、动态注册 |
| `sso.moonl.cloud/sdk/go/web` | 服务端 Web 应用：登录、回调、退出、会话中间件（静默续期、识别 HTMX）、Bearer 资源服务器 |
| `sso.moonl.cloud/sdk/go/desktop` | 桌面和命令行应用：系统浏览器加回环回调、系统安全存储（DPAPI、Keychain、Secret Service）、跨进程刷新锁 |

## 服务端 Web 应用

```go
client, _ := moonsso.NewClient(moonsso.Config{
    Issuer: "https://sso.moonl.cloud", ClientID: "ms_xxx", ClientSecret: "mss_xxx",
    RedirectURL: "https://app.example.com/auth/callback",
})
m, _ := web.New(web.Options{Client: client, CookieSecure: true, PostLogoutRedirect: "https://app.example.com/"})
mux.Handle("/auth/", m.Routes())        // /auth/login /auth/callback /auth/logout /auth/backchannel-logout
mux.Handle("/", m.Require(appHandler))  // 在处理函数里用 web.Profile(r)、web.AccessToken(r)
// Echo：e.Use(echo.WrapMiddleware(m.Require))
```

- 令牌只保存在服务端（`SessionStore`，内置内存实现，可以换成 Redis 或 SQL），浏览器里只有一个不透明的会话 Cookie。
- access token 过期前 2 分钟自动续期。同一会话同一时刻只发一次刷新请求。
- refresh token 失效时，先用 `prompt=none` 借助 SSO 会话静默重新登录，失败才跳到登录页。
- HTMX 请求收到的是 `HX-Redirect`，不是 302。
- 在开发者中心把后端登出通知地址设为 `https://app.example.com/auth/backchannel-logout`，用户在 SSO 退出时，本应用的会话会被立即清除。

## 桌面和命令行应用

```go
app, _ := desktop.Open(ctx, desktop.Config{Issuer: "https://sso.moonl.cloud", ClientID: "ms_xxx", AppName: "MyTool"})
if !app.Session.SignedIn(ctx) {
    _ = app.Login(ctx) // 打开系统浏览器，回调到 http://127.0.0.1:<随机端口>/callback
}
go app.Session.KeepFresh(ctx)                            // 后台续期，休眠唤醒后也能自动恢复
go app.Session.Listen(ctx, func(e moonsso.Event) { ... }) // 实时接收资料变更
resp, _ := app.Session.HTTPClient().Get("https://api.example.com/data") // 自动带令牌，遇到 401 刷新后重放一次
```

- 回调地址登记为 `http://127.0.0.1/callback`，服务端会忽略端口。
- refresh token 和 DPoP 私钥保存在系统安全存储里：Windows 用 DPAPI 加密文件，macOS 用 Keychain，Linux 用 Secret Service。
- 同一个应用开了多个实例时，通过文件锁串行化刷新。

**第一方应用（管理员开启了“允许应用内登录”）**可以用自己的界面登录：

```go
err := app.LoginWithPassword(ctx, username, password)
var otp *moonsso.OTPRequiredError
if errors.As(err, &otp) {
    err = app.CompleteOTP(ctx, otp.Challenge, codeFromUser)
}
err = app.Register(ctx, username, password, nickname) // 应用内注册（需要管理员开放自助注册）
```

## 账号 API（应用内修改资料，并同步到所有应用）

```go
sess.UpdateProfile(ctx, moonsso.ProfileUpdate{DisplayName: &nick, Username: &name}) // scope profile:write
sess.UploadAvatar(ctx, pngBytes, "image/png")
sess.ChangePassword(ctx, oldPw, newPw, true) // scope password:write；其他设备会被退出
```

## 资源服务器

```go
mux.Handle("/api/", web.Bearer(client, apiHandler)) // 校验 typ=at+jwt、iss、aud、exp
claims := web.TokenClaims(r)
```

## 资料同步（服务端）

```go
v, _ := moonsso.NewWebhookVerifier("whsec_...")
mux.Handle("/hooks/sso", v.Handler(func(ctx context.Context, e *moonsso.Event) error { ... }))

// 对账或补偿：需要机密客户端，并开通 users:sync 和 client_credentials
cursor, err = client.Sync(ctx, cursor, onEvent, onSnapshot) // 游标过期时自动全量同步
```

## 动态注册应用

```go
info, err := moonsso.RegisterClient(ctx, "https://sso.moonl.cloud", initialAccessToken, moonsso.ClientMetadata{
    ClientName: "My App", RedirectURIs: []string{"https://app.example.com/auth/callback"},
})
```

## 示例与测试

- `examples/desktop`：浏览器登录或应用内登录，打印资料并实时监听变更。
- `examples/web`：Web 应用加 Webhook 同步。
- 测试会连接本地测试床（`docs/sdk-spec.md` 第 8 节），运行命令为 `go test ./...`。

## Command-line tool (moonsso)

`moonsso` 用 API 令牌调用开发者 API 和超级管理员控制台 API。

```
go install sso.moonl.cloud/sdk/go/cmd/moonsso@latest
```

令牌按前缀区分类型：`msso_dev_…` 是开发者令牌，默认连接 `https://sso.moonl.cloud`；`msso_adm_…` 是控制台令牌，默认连接 `https://sso-admin.moonl.cloud`。`admin` 开头的命令只接受控制台令牌，其余命令默认使用开发者令牌，类型不符时直接拒绝。

```sh
moonsso login                                   # 提示粘贴令牌，输入不回显
echo "$TOKEN" | moonsso login --with-token      # 从标准输入读取
moonsso whoami                                  # 所有者、权限、到期时间（同 token info）
moonsso token rotate --grace 30m                # 轮换；旧令牌在宽限期内仍可用
moonsso token revoke
moonsso logout [--revoke]

moonsso apps list
moonsso apps create --name "My App" --type spa --redirect-uri https://app.example.com/callback
moonsso apps create -f app.json                 # RFC 7591 元数据；-f - 从标准输入读
moonsso apps update ID --set require_dpop=true --set 'webhook_events=["user.updated"]'
moonsso apps get|delete|rotate-secret|rotate-webhook-secret|test-webhook ID

moonsso admin stats
moonsso admin users list --q alice --status active
moonsso admin users create --username bob --display-name Bob   # 不给密码时返回临时密码
moonsso admin users disable|enable|reset-password|disable-totp|revoke-sessions|delete USER
moonsso admin clients list --status pending
moonsso admin clients approve|enable|disable|webhook-enable|rotate-secret|webhook-test|delete ID
moonsso admin dead-letters --client ID && moonsso admin redrive ID
moonsso admin settings get
moonsso admin settings set registration_open=false password_min_length=10
moonsso admin audit --actor @root --limit 50

moonsso api GET apps                            # 相对 API 前缀，也可写 /api/... 绝对路径
moonsso api PATCH apps/ID -d '{"client_name":"新名字"}'   # -d @file 或 -d @- 读文件或标准输入
```

- 全局参数可以放在任意位置：`--profile NAME`、`--url URL`、`--json`（输出原始 JSON）、`-h`。
- 配置保存在 `<用户配置目录>/moonsso/config.json`（目录 0700、文件 0600），开发者令牌存到 profile `developer`，控制台令牌存到 profile `admin`。
- 环境变量优先于配置文件：`MOONSSO_TOKEN`、`MOONSSO_ADMIN_TOKEN`、`MOONSSO_URL`、`MOONSSO_ADMIN_URL`、`MOONSSO_CONFIG`。令牌来自环境变量时，`token rotate` 只打印一次新令牌，需要自己更新变量。
- 令牌只通过 https 发送（本机地址除外），不会出现在 URL 里。令牌 7 天内到期或已被轮换时，会在标准错误输出提醒。
- 删除用户或应用需要输入用户名或应用 ID 确认；脚本里必须加 `--yes`。
- 应用密钥、Webhook 密钥和临时密码只显示一次。
- 退出码：0 成功，1 请求失败或服务器返回错误，2 用法错误。GET 请求在 502、503 或网络错误时自动重试一次，429 会按 `Retry-After`（不超过 10 秒）等待后重试一次。

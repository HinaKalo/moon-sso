# Moon SSO

Moon 的统一登录与账号中心：一个完整的 **OpenID Connect 身份提供方**，线上地址 `https://sso.moonl.cloud`，管理控制台 `https://sso-admin.moonl.cloud`。

## 功能

- **OIDC / OAuth 2.0**：授权码 + **强制 PKCE (S256)**、刷新令牌轮换（60 秒宽限）、`client_credentials`、Back-Channel Logout、`form_post`、DPoP、RFC 7591/7592 动态客户端注册、令牌内省与吊销。发现文档：`/.well-known/openid-configuration`。
- **令牌**：Access Token 为 `at+jwt`（ES256），ID Token 为 RS256 / ES256；签名密钥支持轮换（`moon-sso keys rotate`）。
- **账号**：用户名（可改名，有冷却期和旧名保留）、Argon2 密码、TOTP、头像、登录设备管理；`pairwise` / `public` 两种 subject 策略。
- **管理控制台**（独立监听端口，仅超级管理员）：用户、客户端、设置、审计日志、API 令牌（`msso_adm_…`）与管理 API。
- **事件推送**：Standard Webhooks 签名的 webhook、用户同步 feed。
- **SDK**（`sdk/`）：Go（参考实现）、TypeScript（浏览器 + Node）、Python、Java Spring Boot Starter、Kotlin（Android）、.NET。共同契约见 [`docs/sdk-spec.md`](docs/sdk-spec.md)。

## 目录

| 路径 | 说明 |
|---|---|
| `server/` | Go 服务端（Echo v5、htmx 控制台），二进制 `moon-sso` |
| `server/internal/db/migrations/` | 数据库迁移（嵌入二进制，`moon-sso migrate` 执行；`serve` 只校验不迁移） |
| `server/cmd/testbed/` | 本地测试床（SDK 集成测试使用，**不得部署**） |
| `sdk/` | 各语言 SDK，各自有 README 与测试 |
| `deploy/` | 部署脚本：`deploy.ps1`（构建 → staging → 冒烟 → 生产）、`remote/`（bootstrap、activate 含自动回滚、备份） |
| `docs/` | SDK 规范 |

## 运行与测试

```bash
cd server
go test ./...                       # 单元测试；端到端测试需要 MOON_SSO_TEST_DSN，未设置时跳过
go build -o bin/moon-sso ./cmd/moon-sso
./bin/moon-sso migrate -config /etc/moon-sso/config.toml
./bin/moon-sso serve   -config /etc/moon-sso/config.toml
```

其它子命令：`admin create|reset|list`、`user delete`、`keys rotate`、`gen-master-key`、`version`。

配置文件与密钥（`config.toml`、`master.key`、数据库 DSN）不在仓库中；`deploy/remote/bootstrap.sh` 会在服务器上生成并通过 systemd `LoadCredential` 注入。

## 安全

请通过本仓库 **Security → Report a vulnerability** 私下报告漏洞，见 [SECURITY.md](SECURITY.md)。

## 许可证

[MIT](LICENSE)

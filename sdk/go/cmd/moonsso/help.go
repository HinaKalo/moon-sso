package main

import (
	"fmt"
	"io"
)

const helpOverview = `moonsso：Moon SSO 命令行工具（开发者 API 与超级管理员控制台 API）

用法：
  moonsso [全局参数] <命令> [参数]

命令：
  login        保存 API 令牌（开发者 msso_dev_… 或控制台 msso_adm_…）
  logout       删除保存的令牌（--revoke 同时吊销）
  whoami       查看当前令牌和所有者（同 token info）
  token        令牌管理：info、rotate、revoke
  apps         管理我的应用（开发者令牌）
  admin        超级管理员控制台（控制台令牌）
  api          直接调用 API
  version      显示版本
  help         显示帮助：moonsso help <命令>

全局参数：
  --profile NAME   使用指定 profile（默认：开发者命令用 developer，admin 命令用 admin）
  --url URL        覆盖服务器地址
  --json           输出原始 JSON
  -h, --help       显示帮助

环境变量：
  MOONSSO_TOKEN        开发者令牌（优先于配置文件）
  MOONSSO_ADMIN_TOKEN  控制台令牌（admin 命令使用）
  MOONSSO_URL          开发者 API 地址，默认 https://sso.moonl.cloud
  MOONSSO_ADMIN_URL    控制台 API 地址，默认 https://sso-admin.moonl.cloud
  MOONSSO_CONFIG       配置文件路径

退出码：0 成功，1 请求或服务器错误，2 用法错误。
`

var helpTopics = map[string]string{
	"login": `用法：moonsso login [--with-token] [--url URL] [--profile NAME]

保存 API 令牌。终端中会提示粘贴令牌（不回显）；使用 --with-token 或通过管道输入时从标准输入读取。
令牌经服务器验证后保存：msso_dev_ 令牌存到 profile developer，msso_adm_ 令牌存到 profile admin，
可用 --profile 指定其他名称。

示例：
  moonsso login
  echo "$TOKEN" | moonsso login --with-token
  moonsso login --url https://sso-admin.example.com
`,
	"logout": `用法：moonsso logout [--revoke] [--profile NAME]

从配置中删除保存的令牌。加 --revoke 会先在服务器上吊销令牌。
`,
	"whoami": `用法：moonsso whoami [--profile NAME]

显示当前令牌的名称、所有者、权限、允许 IP、状态和过期时间。等同于 moonsso token info。
`,
	"token": `用法：
  moonsso token info
  moonsso token rotate [--grace 1h|30m|0|7d]
  moonsso token revoke

rotate   轮换当前令牌。旧令牌在宽限期内仍可用（默认 1 小时，最长 7 天，0 表示立即失效）。
         令牌来自配置文件时自动保存新令牌；来自环境变量时只打印一次新令牌，请自行更新变量。
revoke   立即吊销当前令牌，并从配置中删除。
`,
	"apps": `用法：
  moonsso apps list
  moonsso apps get ID
  moonsso apps create (-f FILE | -f -) [--name NAME] [--type web|spa|native|service]
                      [--redirect-uri URI]... [--scope "openid profile"] [--webhook-url URL] [--set key=value]...
  moonsso apps update ID [-f FILE] [--set key=value]...
  moonsso apps delete ID [--yes]
  moonsso apps rotate-secret ID
  moonsso apps rotate-webhook-secret ID
  moonsso apps test-webhook ID

create 的 -f 为 RFC 7591 客户端元数据 JSON（client_name、redirect_uris、grant_types 等），
其余参数会覆盖文件中的字段。--type：
  web      application_type=web（机密客户端）
  spa      application_type=web，token_endpoint_auth_method=none
  native   application_type=native，token_endpoint_auth_method=none
  service  grant_types=["client_credentials"]，scope="users:sync"
--set 的值能解析为 JSON 时按 JSON 处理（true、10、["a"]），否则作为字符串。
client_secret、webhook_secret 等密钥只显示一次。delete 需要输入应用 ID 确认，非交互模式下需要 --yes。

示例：
  moonsso apps create --name "My App" --type spa --redirect-uri https://app.example.com/callback
  moonsso apps update abc123 --set require_dpop=true --set 'webhook_events=["user.updated"]'
`,
	"admin": `用法（需要控制台令牌 msso_adm_…）：
  moonsso admin whoami
  moonsso admin stats
  moonsso admin users list [--q TEXT] [--status active|disabled] [--page N] [--per-page N]
  moonsso admin users get SUB|USERNAME
  moonsso admin users create --username NAME [--display-name NAME] [--password-stdin]
  moonsso admin users disable|enable|reset-password|disable-totp|revoke-sessions SUB|USERNAME
  moonsso admin users delete SUB|USERNAME [--yes]
  moonsso admin clients list [--q TEXT] [--status active|pending|disabled]
  moonsso admin clients get ID
  moonsso admin clients create (-f FILE | --name NAME ...) [--set first_party=true]...
  moonsso admin clients update ID [-f FILE] [--set key=value]...
  moonsso admin clients approve|enable|disable|webhook-enable ID
  moonsso admin clients rotate-secret|rotate-webhook-secret|webhook-test ID
  moonsso admin clients delete ID [--yes]
  moonsso admin dead-letters [--client ID]
  moonsso admin redrive ID
  moonsso admin settings get
  moonsso admin settings set key=value...
  moonsso admin audit [--action A] [--actor USER|@ADMIN] [--target T] [--limit N] [--before CURSOR]

users create 不带 --password-stdin 时由服务器生成临时密码（只显示一次）。
删除用户或应用需要输入用户名或应用 ID 确认，非交互模式下需要 --yes。
settings set 的值能解析为 JSON 时按 JSON 处理，例如 registration_open=false password_min_length=10。
`,
	"api": `用法：moonsso api METHOD PATH [-d JSON | -d @FILE | -d @-]

用当前 profile 的令牌直接调用 API，输出响应内容（JSON 会格式化）。
PATH 可以是 API 前缀下的相对路径（开发者令牌为 /api/v1/developer，控制台令牌为 /api/v1），
也可以是以 /api/ 开头的绝对路径。响应状态为错误时退出码为 1。

示例：
  moonsso api GET apps
  moonsso api PATCH apps/abc123 -d '{"client_name":"新名字"}'
  moonsso --profile admin api GET 'users?q=alice'
`,
	"version": `用法：moonsso version

显示版本号。
`,
	"help": `用法：moonsso help [命令]
`,
}

func (a *app) printHelp(w io.Writer, args []string) {
	if len(args) > 0 {
		topic := args[0]
		switch topic {
		case "token":
			if len(args) > 1 && args[1] == "info" {
				topic = "whoami"
			}
		case "app":
			topic = "apps"
		}
		if t, ok := helpTopics[topic]; ok {
			fmt.Fprint(w, t)
			return
		}
	}
	fmt.Fprint(w, helpOverview)
}

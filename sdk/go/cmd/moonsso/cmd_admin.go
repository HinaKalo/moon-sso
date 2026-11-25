package main

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

var statsLabels = []kv{
	{"users_total", "用户总数"},
	{"users_disabled", "已禁用用户"},
	{"users_new_24h", "24 小时新增用户"},
	{"logins_24h", "24 小时登录次数"},
	{"active_sessions", "活跃会话"},
	{"active_refresh_families", "活跃刷新令牌"},
	{"clients_total", "应用总数"},
	{"clients_pending", "待审批应用"},
	{"webhooks_failing", "Webhook 异常应用"},
	{"dead_letters", "死信"},
	{"sse_connections", "SSE 连接"},
	{"registration_open", "开放注册"},
	{"client_registration", "应用注册"},
}

var settingsOrder = []string{
	"site_name", "registration_open", "client_registration", "password_min_length",
	"username_cooldown_days", "username_reserve_days", "session_idle_days", "access_token_minutes",
	"refresh_idle_days", "refresh_absolute_days", "max_clients_per_developer",
}

var userOrder = []string{
	"sub", "username", "display_name", "status", "totp_enabled", "must_change_password",
	"registered_via", "created_at", "updated_at",
}

func (a *app) cmdAdmin(args []string) error {
	if len(args) == 0 {
		return usagef("admin", "缺少子命令")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "whoami":
		return a.cmdWhoami(rest, kindConsole, "admin")
	case "stats":
		return a.adminStats(rest)
	case "users", "user":
		return a.adminUsers(rest)
	case "clients", "client":
		return a.adminClients(rest)
	case "dead-letters":
		return a.adminDeadLetters(rest)
	case "redrive":
		return a.adminRedrive(rest)
	case "settings":
		return a.adminSettings(rest)
	case "audit":
		return a.adminAudit(rest)
	}
	return usagef("admin", "未知子命令 %q", sub)
}

func (a *app) adminStats(args []string) error {
	if _, err := exactArgs(newFlags("admin stats"), "admin", args, 0, ""); err != nil {
		return err
	}
	s, err := a.session(kindConsole)
	if err != nil {
		return err
	}
	res, m, err := s.object(http.MethodGet, "stats", nil, nil)
	if err != nil {
		return err
	}
	if a.jsonOut {
		a.printJSON(res.body)
		return nil
	}
	var rows []kv
	known := map[string]bool{}
	for _, l := range statsLabels {
		known[l.k] = true
		if v, ok := m[l.k]; ok {
			rows = append(rows, kv{l.v, fmtVal(l.k, v)})
		}
	}
	for _, r := range objectKV(m, nil) {
		key := r.k
		if i := strings.IndexByte(key, '.'); i >= 0 {
			key = key[:i]
		}
		if !known[key] {
			rows = append(rows, r)
		}
	}
	writeKV(a.stdout, rows)
	return nil
}

func (a *app) adminUsers(args []string) error {
	if len(args) == 0 {
		return usagef("admin", "缺少子命令：users list|get|create|disable|enable|reset-password|disable-totp|revoke-sessions|delete")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "list", "ls":
		return a.adminUsersList(rest)
	case "get", "show":
		return a.adminUserGet(rest)
	case "create":
		return a.adminUserCreate(rest)
	case "disable", "enable", "reset-password", "disable-totp", "revoke-sessions":
		return a.adminUserAction(sub, rest)
	case "delete", "rm":
		return a.adminUserDelete(rest)
	}
	return usagef("admin", "未知子命令 users %q", sub)
}

func (a *app) adminUsersList(args []string) error {
	fs := newFlags("admin users list")
	q := fs.String("q", "", "")
	status := fs.String("status", "", "")
	page := fs.Int("page", 0, "")
	perPage := fs.Int("per-page", 0, "")
	if _, err := exactArgs(fs, "admin", args, 0, ""); err != nil {
		return err
	}
	query := url.Values{}
	if *q != "" {
		query.Set("q", *q)
	}
	if *status != "" {
		if *status != "active" && *status != "disabled" {
			return usagef("admin", "--status 只能是 active 或 disabled")
		}
		query.Set("status", *status)
	}
	if *page < 0 || *perPage < 0 {
		return usagef("admin", "--page 和 --per-page 必须是正整数")
	}
	if *page > 0 {
		query.Set("page", strconv.Itoa(*page))
	}
	if *perPage > 0 {
		query.Set("per_page", strconv.Itoa(*perPage))
	}
	s, err := a.session(kindConsole)
	if err != nil {
		return err
	}
	res, m, err := s.object(http.MethodGet, "users", query, nil)
	if err != nil {
		return err
	}
	if a.jsonOut {
		a.printJSON(res.body)
		return nil
	}
	items := objects(m["users"])
	if len(items) == 0 {
		fmt.Fprintln(a.stdout, "没有匹配的用户")
		return nil
	}
	rows := make([][]string, len(items))
	for i, u := range items {
		rows[i] = []string{
			fmtVal("sub", u["sub"]), fmtVal("username", u["username"]), fmtVal("display_name", u["display_name"]),
			fmtVal("status", u["status"]), fmtVal("totp_enabled", u["totp_enabled"]), fmtVal("created_at", u["created_at"]),
		}
	}
	writeTable(a.stdout, []string{"SUB", "USERNAME", "DISPLAY_NAME", "STATUS", "TOTP", "CREATED"}, rows)
	line := fmt.Sprintf("第 %s 页，共 %s 个用户", orDash(sval(m, "page")), orDash(sval(m, "total")))
	if b, _ := m["has_next"].(bool); b {
		if n, err := strconv.Atoi(sval(m, "page")); err == nil {
			line += fmt.Sprintf("；下一页：--page %d", n+1)
		} else {
			line += "；还有下一页"
		}
	}
	fmt.Fprintln(a.stdout, line)
	return nil
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func (a *app) adminUserGet(args []string) error {
	pos, err := exactArgs(newFlags("admin users get"), "admin", args, 1, "用户 sub 或用户名")
	if err != nil {
		return err
	}
	s, err := a.session(kindConsole)
	if err != nil {
		return err
	}
	res, m, err := s.object(http.MethodGet, p("users", pos[0]), nil, nil)
	if err != nil {
		return err
	}
	if a.jsonOut {
		a.printJSON(res.body)
		return nil
	}
	writeKV(a.stdout, objectKV(m, userOrder, "sessions", "grants"))
	for _, sec := range []struct{ key, title string }{{"sessions", "会话"}, {"grants", "授权应用"}} {
		items := objects(m[sec.key])
		fmt.Fprintf(a.stdout, "\n%s（%d）\n", sec.title, len(items))
		if len(items) > 0 {
			genericTable(a.stdout, items)
		}
	}
	return nil
}

func (a *app) adminUserCreate(args []string) error {
	fs := newFlags("admin users create")
	username := fs.String("username", "", "")
	display := fs.String("display-name", "", "")
	pwStdin := fs.Bool("password-stdin", false, "")
	if _, err := exactArgs(fs, "admin", args, 0, ""); err != nil {
		return err
	}
	if strings.TrimSpace(*username) == "" {
		return usagef("admin", "缺少 --username")
	}
	body := map[string]any{"username": strings.TrimSpace(*username)}
	if *display != "" {
		body["display_name"] = *display
	}
	if *pwStdin {
		line, err := a.readLine()
		if err != nil || line == "" {
			return usagef("admin", "--password-stdin：标准输入中没有密码")
		}
		body["password"] = line
	}
	s, err := a.session(kindConsole)
	if err != nil {
		return err
	}
	res, m, err := s.object(http.MethodPost, "users", nil, body)
	if err != nil {
		return err
	}
	if a.jsonOut {
		a.printJSON(res.body)
		if sval(m, "temporary_password") != "" {
			fmt.Fprintln(a.stderr, "注意：临时密码只显示这一次，请立即转交用户。")
		}
		return nil
	}
	fmt.Fprintf(a.stdout, "已创建用户 %s\n", sval(m, "username"))
	writeKV(a.stdout, objectKV(m, userOrder, secretKeys...))
	a.printSecrets(m, "temporary_password")
	return nil
}

var userActionDone = map[string]string{
	"disable":         "已禁用用户 %s，其会话已注销",
	"enable":          "已启用用户 %s",
	"reset-password":  "已重置用户 %s 的密码，用户下次登录须修改密码",
	"disable-totp":    "已关闭用户 %s 的两步验证",
	"revoke-sessions": "已注销用户 %s 的全部会话",
}

func (a *app) adminUserAction(action string, args []string) error {
	pos, err := exactArgs(newFlags("admin users "+action), "admin", args, 1, "用户 sub 或用户名")
	if err != nil {
		return err
	}
	s, err := a.session(kindConsole)
	if err != nil {
		return err
	}
	res, m, err := s.object(http.MethodPost, p("users", pos[0], action), nil, nil)
	if err != nil {
		return err
	}
	if a.jsonOut {
		a.printJSON(res.body)
		if sval(m, "temporary_password") != "" {
			fmt.Fprintln(a.stderr, "注意：临时密码只显示这一次，请立即转交用户。")
		}
		return nil
	}
	name := sval(m, "username")
	if name == "" {
		name = pos[0]
	}
	fmt.Fprintf(a.stdout, userActionDone[action]+"\n", name)
	a.printSecrets(m, "temporary_password")
	return nil
}

func (a *app) adminUserDelete(args []string) error {
	fs := newFlags("admin users delete")
	yes := fs.Bool("yes", false, "")
	fs.BoolVar(yes, "y", false, "")
	pos, err := exactArgs(fs, "admin", args, 1, "用户 sub 或用户名")
	if err != nil {
		return err
	}
	if err := a.canConfirm(*yes, "admin"); err != nil {
		return err
	}
	s, err := a.session(kindConsole)
	if err != nil {
		return err
	}
	_, u, err := s.object(http.MethodGet, p("users", pos[0]), nil, nil)
	if err != nil {
		return err
	}
	username, sub := sval(u, "username"), sval(u, "sub")
	if username == "" || sub == "" {
		return errors.New("服务器返回的用户信息不完整")
	}
	warning := fmt.Sprintf("将永久删除用户 %s（%s）及其会话和授权，此操作无法撤销。", username, sub)
	if err := a.confirm(*yes, warning, username); err != nil {
		return err
	}
	if _, err := s.call(http.MethodDelete, p("users", sub), url.Values{"confirm": {username}}, nil); err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "已删除用户 %s\n", username)
	return nil
}

var clientActionDone = map[string]string{
	"approve":        "已批准应用 %s",
	"enable":         "已启用应用 %s",
	"disable":        "已停用应用 %s",
	"webhook-enable": "已重新启用应用 %s 的 Webhook",
}

func (a *app) adminClients(args []string) error {
	c := &clientAPI{a: a, scope: kindConsole, base: "clients", topic: "admin", admin: true}
	if len(args) == 0 {
		return usagef("admin", "缺少子命令：clients list|get|create|update|approve|enable|disable|rotate-secret|rotate-webhook-secret|webhook-test|webhook-enable|delete")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "list", "ls":
		return c.list(rest)
	case "get", "show":
		return c.get(rest)
	case "create":
		return c.create(rest)
	case "update":
		return c.update(rest)
	case "delete", "rm":
		return c.delete(rest)
	case "rotate-secret":
		return c.rotate(rest, "rotate-secret", "client_secret")
	case "rotate-webhook-secret":
		return c.rotate(rest, "rotate-webhook-secret", "webhook_secret")
	case "webhook-test", "test-webhook":
		return c.webhookTest(rest)
	case "approve", "enable", "disable", "webhook-enable":
		return a.adminClientAction(sub, rest)
	}
	return usagef("admin", "未知子命令 clients %q", sub)
}

func (a *app) adminClientAction(action string, args []string) error {
	pos, err := exactArgs(newFlags("admin clients "+action), "admin", args, 1, "应用 ID")
	if err != nil {
		return err
	}
	s, err := a.session(kindConsole)
	if err != nil {
		return err
	}
	res, m, err := s.object(http.MethodPost, p("clients", pos[0], action), nil, nil)
	if err != nil {
		return err
	}
	if a.jsonOut {
		a.printJSON(res.body)
		return nil
	}
	fmt.Fprintf(a.stdout, clientActionDone[action]+"\n", pos[0])
	if st := sval(m, "status"); st != "" {
		fmt.Fprintf(a.stdout, "当前状态：%s\n", st)
	}
	return nil
}

func (a *app) adminDeadLetters(args []string) error {
	fs := newFlags("admin dead-letters")
	client := fs.String("client", "", "")
	if _, err := exactArgs(fs, "admin", args, 0, ""); err != nil {
		return err
	}
	query := url.Values{}
	if *client != "" {
		query.Set("client_id", *client)
	}
	s, err := a.session(kindConsole)
	if err != nil {
		return err
	}
	res, m, err := s.object(http.MethodGet, "webhooks/dead-letters", query, nil)
	if err != nil {
		return err
	}
	if a.jsonOut {
		a.printJSON(res.body)
		return nil
	}
	items := objects(m["dead_letters"])
	if len(items) == 0 {
		fmt.Fprintln(a.stdout, "没有死信")
		return nil
	}
	rows := make([][]string, len(items))
	for i, d := range items {
		rows[i] = []string{
			fmtVal("id", d["id"]), fmtVal("client_id", d["client_id"]), fmtVal("seq", d["seq"]),
			fmtVal("attempts", d["attempts"]), truncate(fmtVal("last_error", d["last_error"]), 60), fmtVal("created_at", d["created_at"]),
		}
	}
	writeTable(a.stdout, []string{"ID", "CLIENT_ID", "SEQ", "ATTEMPTS", "LAST_ERROR", "CREATED"}, rows)
	fmt.Fprintf(a.stdout, "共 %d 条，重新投递：moonsso admin redrive ID\n", len(items))
	return nil
}

func (a *app) adminRedrive(args []string) error {
	pos, err := exactArgs(newFlags("admin redrive"), "admin", args, 1, "死信 ID")
	if err != nil {
		return err
	}
	s, err := a.session(kindConsole)
	if err != nil {
		return err
	}
	res, err := s.call(http.MethodPost, p("webhooks", "dead-letters", pos[0], "redrive"), nil, nil)
	if err != nil {
		return err
	}
	if a.jsonOut {
		a.printJSON(res.body)
		return nil
	}
	fmt.Fprintf(a.stdout, "死信 %s 已重新排队投递\n", pos[0])
	return nil
}

func (a *app) adminSettings(args []string) error {
	if len(args) == 0 {
		return usagef("admin", "缺少子命令：settings get 或 settings set key=value…")
	}
	sub, rest := args[0], args[1:]
	var method string
	var body map[string]any
	switch sub {
	case "get", "show":
		if _, err := exactArgs(newFlags("admin settings get"), "admin", rest, 0, ""); err != nil {
			return err
		}
		method = http.MethodGet
	case "set":
		pos, err := parseArgs(newFlags("admin settings set"), "admin", rest)
		if err != nil {
			return err
		}
		if len(pos) == 0 {
			return usagef("admin", "缺少 key=value")
		}
		body = map[string]any{}
		for _, s := range pos {
			k, v, err := parseAssignment(s)
			if err != nil {
				return usagef("admin", "%v", err)
			}
			body[k] = v
		}
		method = http.MethodPatch
	default:
		return usagef("admin", "未知子命令 settings %q", sub)
	}
	s, err := a.session(kindConsole)
	if err != nil {
		return err
	}
	var reqBody any
	if body != nil {
		reqBody = body
	}
	res, m, err := s.object(method, "settings", nil, reqBody)
	if err != nil {
		return err
	}
	if a.jsonOut {
		a.printJSON(res.body)
		return nil
	}
	if method == http.MethodPatch {
		fmt.Fprintln(a.stdout, "设置已保存")
	}
	writeKV(a.stdout, objectKV(m, settingsOrder))
	return nil
}

func (a *app) adminAudit(args []string) error {
	fs := newFlags("admin audit")
	action := fs.String("action", "", "")
	actor := fs.String("actor", "", "")
	target := fs.String("target", "", "")
	before := fs.String("before", "", "")
	limit := fs.Int("limit", 0, "")
	if _, err := exactArgs(fs, "admin", args, 0, ""); err != nil {
		return err
	}
	if *limit < 0 {
		return usagef("admin", "--limit 必须是正整数")
	}
	query := url.Values{}
	for k, v := range map[string]string{"action": *action, "actor": *actor, "target": *target, "before": *before} {
		if v != "" {
			query.Set(k, v)
		}
	}
	if *limit > 0 {
		query.Set("limit", strconv.Itoa(*limit))
	}
	s, err := a.session(kindConsole)
	if err != nil {
		return err
	}
	res, m, err := s.object(http.MethodGet, "audit", query, nil)
	if err != nil {
		return err
	}
	if a.jsonOut {
		a.printJSON(res.body)
		return nil
	}
	items := objects(m["entries"])
	if len(items) == 0 {
		fmt.Fprintln(a.stdout, "没有审计记录")
		return nil
	}
	rows := make([][]string, len(items))
	for i, e := range items {
		target := sval(e, "target_type")
		if id := sval(e, "target_id"); id != "" {
			if target != "" {
				target += ":"
			}
			target += id
		}
		meta := "-"
		if mv, ok := e["meta"]; ok && mv != nil {
			if mm, isMap := mv.(map[string]any); !isMap || len(mm) > 0 {
				meta = truncate(scalar(mv), 60)
			}
		}
		rows[i] = []string{fmtVal("at", e["at"]), fmtVal("action", e["action"]), auditActor(e), orDash(target), fmtVal("ip", e["ip"]), meta}
	}
	writeTable(a.stdout, []string{"AT", "ACTION", "ACTOR", "TARGET", "IP", "META"}, rows)
	if nb := sval(m, "next_before"); nb != "" {
		fmt.Fprintf(a.stdout, "更早的记录：--before %s\n", nb)
	}
	return nil
}

func auditActor(e map[string]any) string {
	if v := sval(e, "actor_admin"); v != "" {
		if !strings.HasPrefix(v, "@") {
			v = "@" + v
		}
		return v
	}
	if v := sval(e, "actor_client"); v != "" {
		return "client:" + v
	}
	if v := sval(e, "actor_user_id"); v != "" {
		return "user:" + v
	}
	return "-"
}

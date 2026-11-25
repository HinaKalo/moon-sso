package main

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func (a *app) cmdLogin(args []string) error {
	fs := newFlags("login")
	withToken := fs.Bool("with-token", false, "")
	if _, err := exactArgs(fs, "login", args, 0, ""); err != nil {
		return err
	}
	tok, err := a.readTokenInput(*withToken)
	if err != nil {
		return err
	}
	kind, err := tokenKind(tok)
	if err != nil {
		return err
	}
	cfg, path, err := a.loadConfig()
	if err != nil {
		return err
	}
	name := "developer"
	if kind == kindConsole {
		name = "admin"
	}
	if a.profileSet {
		name = a.profile
	}
	base := a.baseURL
	if base == "" {
		base = a.env(urlEnv(kind))
	}
	if base == "" && cfg.Profiles[name] != nil {
		base = cfg.Profiles[name].URL
	}
	if base == "" {
		base = defaultURL(kind)
	}
	if base, err = normalizeBase(base); err != nil {
		return err
	}
	s := &session{a: a, token: tok, base: base, prefix: apiPrefix(kind), kind: kind, profile: name}
	res, info, err := s.object(http.MethodGet, "token", nil, nil)
	if err != nil {
		var ae *apiError
		if errors.As(err, &ae) && ae.Status == http.StatusUnauthorized {
			fmt.Fprintln(a.stderr, "令牌无效、已过期或已吊销，未保存。")
		}
		return err
	}
	cfg.Profiles[name] = &profile{URL: base, Token: tok}
	if k, _ := tokenKind(cfg.token(cfg.Default)); cfg.Default == "" || cfg.Profiles[cfg.Default] == nil || (kind == kindDeveloper && k != kindDeveloper) {
		cfg.Default = name
	}
	if err := saveConfig(path, cfg); err != nil {
		return err
	}
	if a.jsonOut {
		a.printJSON(res.body)
		fmt.Fprintf(a.stderr, "已保存到 profile %s（%s）\n", name, path)
		return nil
	}
	t, _ := info["token"].(map[string]any)
	fmt.Fprintf(a.stdout, "已登录 %s\n", base)
	writeKV(a.stdout, []kv{
		{"类型", kindLabel(kind)},
		{"所有者", ownerOf(info)},
		{"权限", fmtVal("scopes", t["scopes"])},
		{"过期时间", fmtVal("expires_at", t["expires_at"])},
	})
	fmt.Fprintf(a.stdout, "已保存到 profile %s（%s）\n", name, path)
	return nil
}

// readTokenInput reads the token from stdin (--with-token or piped input), or
// prompts on the terminal without echo.
func (a *app) readTokenInput(withToken bool) (string, error) {
	if !withToken && a.interactive() {
		t, err := a.readSecret("请粘贴 API 令牌（输入不会显示）：")
		if err != nil {
			return "", err
		}
		if t == "" {
			return "", usagef("login", "没有输入令牌")
		}
		return t, nil
	}
	if !withToken {
		fmt.Fprintln(a.stderr, "正在从标准输入读取令牌…")
	}
	b, err := io.ReadAll(io.LimitReader(a.in, 64<<10))
	if err != nil {
		return "", fmt.Errorf("读取标准输入失败：%v", err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		if t := strings.TrimSpace(line); t != "" {
			return t, nil
		}
	}
	return "", usagef("login", "标准输入中没有令牌")
}

func ownerOf(info map[string]any) string {
	if u, ok := info["user"].(map[string]any); ok {
		name, user := sval(u, "display_name"), sval(u, "username")
		switch {
		case name != "" && user != "" && name != user:
			return name + " (" + user + ")"
		case user != "":
			return user
		case name != "":
			return name
		}
	}
	if ad, ok := info["admin"].(map[string]any); ok {
		if u := sval(ad, "username"); u != "" {
			return u + "（超级管理员）"
		}
	}
	if t, ok := info["token"].(map[string]any); ok {
		return fmtVal("owner", t["owner"])
	}
	return "-"
}

func (a *app) cmdLogout(args []string) error {
	fs := newFlags("logout")
	revoke := fs.Bool("revoke", false, "")
	if _, err := exactArgs(fs, "logout", args, 0, ""); err != nil {
		return err
	}
	cfg, path, err := a.loadConfig()
	if err != nil {
		return err
	}
	name := cfg.Default
	if a.profileSet {
		name = a.profile
	}
	if name == "" {
		name = "developer"
	}
	saved := cfg.Profiles[name]
	if saved == nil {
		if !a.profileSet && a.env("MOONSSO_TOKEN") != "" {
			return errors.New("当前令牌来自环境变量 MOONSSO_TOKEN，没有保存的配置可删除")
		}
		return fmt.Errorf("profile %s 没有保存的令牌", name)
	}
	revoked := false
	if *revoke {
		kind, err := tokenKind(saved.Token)
		if err != nil {
			return fmt.Errorf("profile %s：%v", name, err)
		}
		base := a.baseURL
		if base == "" {
			base = saved.URL
		}
		if base == "" {
			base = defaultURL(kind)
		}
		if base, err = normalizeBase(base); err != nil {
			return err
		}
		s := &session{a: a, token: saved.Token, base: base, prefix: apiPrefix(kind), kind: kind, profile: name, quiet: true}
		if _, err := s.call(http.MethodDelete, "token", nil, nil); err != nil {
			var ae *apiError
			if !errors.As(err, &ae) || ae.Status != http.StatusUnauthorized {
				return err
			}
			fmt.Fprintln(a.stderr, "令牌已失效，跳过吊销。")
		} else {
			revoked = true
		}
	}
	delete(cfg.Profiles, name)
	cfg.pickDefault()
	if err := saveConfig(path, cfg); err != nil {
		return err
	}
	if revoked {
		fmt.Fprintf(a.stdout, "令牌已吊销，已退出 profile %s\n", name)
	} else {
		fmt.Fprintf(a.stdout, "已退出 profile %s（令牌仍然有效，如需作废请加 --revoke）\n", name)
	}
	return nil
}

func (a *app) cmdWhoami(args []string, scope, topic string) error {
	if _, err := exactArgs(newFlags(topic), topic, args, 0, ""); err != nil {
		return err
	}
	s, err := a.session(scope)
	if err != nil {
		return err
	}
	res, info, err := s.object(http.MethodGet, "token", nil, nil)
	if err != nil {
		return err
	}
	if a.jsonOut {
		a.printJSON(res.body)
		return nil
	}
	t, _ := info["token"].(map[string]any)
	status := fmtVal("status", t["status"])
	if b, _ := t["expires_soon"].(bool); b {
		status += "（即将过期）"
	}
	ips := fmtVal("allowed_ips", t["allowed_ips"])
	if ips == "-" {
		ips = "不限"
	}
	last := fmtVal("last_used_at", t["last_used_at"])
	if ip := sval(t, "last_used_ip"); ip != "" && last != "-" {
		last += "（" + ip + "）"
	}
	rows := []kv{
		{"名称", fmtVal("name", t["name"])},
		{"类型", kindLabel(s.kind)},
		{"所有者", ownerOf(info)},
		{"令牌", fmtVal("hint", t["hint"])},
		{"权限", fmtVal("scopes", t["scopes"])},
		{"允许 IP", ips},
		{"状态", status},
		{"创建时间", fmtVal("created_at", t["created_at"])},
		{"过期时间", fmtVal("expires_at", t["expires_at"])},
		{"最后使用", last},
	}
	if v := sval(t, "rotated_from"); v != "" {
		rows = append(rows, kv{"轮换自", v})
	}
	if v := sval(t, "replaced_by"); v != "" {
		rows = append(rows, kv{"已被替换为", v})
	}
	if v := sval(t, "revoked_at"); v != "" {
		rows = append(rows, kv{"吊销时间", fmtVal("revoked_at", v)})
	}
	api := sval(info, "api")
	if api == "" {
		api = s.base + s.prefix
	}
	source := "profile " + s.profile
	if s.envVar != "" {
		source = "环境变量 " + s.envVar
	}
	rows = append(rows, kv{"API", api}, kv{"来源", source})
	writeKV(a.stdout, rows)
	return nil
}

func (a *app) cmdToken(args []string) error {
	if len(args) == 0 {
		return usagef("token", "缺少子命令：info、rotate 或 revoke")
	}
	switch args[0] {
	case "info":
		return a.cmdWhoami(args[1:], "", "token")
	case "rotate":
		return a.cmdTokenRotate(args[1:])
	case "revoke":
		return a.cmdTokenRevoke(args[1:])
	}
	return usagef("token", "未知子命令 %q", args[0])
}

// parseGrace accepts 0, plain seconds, Go durations (30m, 1h30m) and days
// (7d, 1d12h).
func parseGrace(s string) (int, error) {
	s = strings.TrimSpace(s)
	if n, err := strconv.Atoi(s); err == nil {
		if n < 0 || n > 604800 {
			return 0, errors.New("宽限期必须在 0 到 7 天之间")
		}
		return n, nil
	}
	var total time.Duration
	rest := s
	if i := strings.IndexByte(rest, 'd'); i >= 0 {
		days, err := strconv.Atoi(rest[:i])
		if err != nil || days < 0 {
			return 0, fmt.Errorf("宽限期格式无效：%s", s)
		}
		total = time.Duration(days) * 24 * time.Hour
		rest = rest[i+1:]
	}
	if rest != "" {
		d, err := time.ParseDuration(rest)
		if err != nil || d < 0 {
			return 0, fmt.Errorf("宽限期格式无效：%s（示例：0、30m、1h、7d）", s)
		}
		total += d
	}
	if s == "" || total%time.Second != 0 {
		return 0, fmt.Errorf("宽限期格式无效：%s（示例：0、30m、1h、7d）", s)
	}
	if total > 7*24*time.Hour {
		return 0, errors.New("宽限期必须在 0 到 7 天之间")
	}
	return int(total / time.Second), nil
}

func (a *app) cmdTokenRotate(args []string) error {
	fs := newFlags("token rotate")
	grace := fs.String("grace", "", "")
	if _, err := exactArgs(fs, "token", args, 0, ""); err != nil {
		return err
	}
	graceSecs := 3600
	var body any
	if *grace != "" {
		n, err := parseGrace(*grace)
		if err != nil {
			return usagef("token", "%v", err)
		}
		graceSecs = n
		body = map[string]int{"grace_seconds": n}
	}
	s, err := a.session("")
	if err != nil {
		return err
	}
	s.quiet = true
	res, m, err := s.object(http.MethodPost, "token/rotate", nil, body)
	if err != nil {
		return err
	}
	newTok := sval(m, "token")
	if k, err := tokenKind(newTok); err != nil || k != s.kind {
		return errors.New("服务器返回的新令牌无效")
	}
	graceText := "已立即失效"
	if graceSecs > 0 {
		graceText = "在 " + fmtDuration(time.Duration(graceSecs)*time.Second) + "内仍可使用"
	}
	if s.envVar == "" {
		cfg, path, err := a.loadConfig()
		if err != nil {
			return err
		}
		saved := cfg.Profiles[s.profile]
		if saved == nil {
			saved = &profile{}
			cfg.Profiles[s.profile] = saved
		}
		saved.Token = newTok
		if err := saveConfig(path, cfg); err != nil {
			return fmt.Errorf("%v；新令牌未保存，旧令牌%s", err, graceText)
		}
		if a.jsonOut {
			a.printJSON(res.body)
		} else {
			fmt.Fprintf(a.stdout, "令牌已轮换，新令牌已保存到 profile %s。旧令牌%s。\n", s.profile, graceText)
			if exp := fmtVal("expires_at", m["expires_at"]); exp != "-" {
				fmt.Fprintf(a.stdout, "新令牌过期时间：%s\n", exp)
			}
		}
		return nil
	}
	if a.jsonOut {
		a.printJSON(res.body)
	} else {
		fmt.Fprintln(a.stdout, newTok)
	}
	fmt.Fprintf(a.stderr, "令牌已轮换。新令牌只显示这一次，请更新环境变量 %s。旧令牌%s。\n", s.envVar, graceText)
	return nil
}

func (a *app) cmdTokenRevoke(args []string) error {
	if _, err := exactArgs(newFlags("token revoke"), "token", args, 0, ""); err != nil {
		return err
	}
	s, err := a.session("")
	if err != nil {
		return err
	}
	s.quiet = true
	if _, err := s.call(http.MethodDelete, "token", nil, nil); err != nil {
		return err
	}
	if s.envVar != "" {
		fmt.Fprintf(a.stdout, "令牌已吊销，请删除环境变量 %s\n", s.envVar)
		return nil
	}
	cfg, path, err := a.loadConfig()
	if err != nil {
		return err
	}
	delete(cfg.Profiles, s.profile)
	cfg.pickDefault()
	if err := saveConfig(path, cfg); err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "令牌已吊销，并已从 profile %s 删除\n", s.profile)
	return nil
}

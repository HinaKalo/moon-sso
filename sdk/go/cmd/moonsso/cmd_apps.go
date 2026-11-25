package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

var appOrder = []string{
	"client_id", "client_name", "status", "verified", "owner", "application_type", "token_endpoint_auth_method",
	"grant_types", "scope", "redirect_uris", "post_logout_redirect_uris", "description", "client_uri",
	"logo_uri", "policy_uri", "tos_uri", "id_token_signed_response_alg", "backchannel_logout_uri",
	"require_dpop", "first_party", "native_login", "skip_consent", "allow_registration", "require_otp",
	"subject_type", "access_token_ttl_seconds", "webhook_url", "webhook_events", "webhook_allow_insecure",
	"webhook_state", "created_at", "updated_at",
}

// clientAPI covers what developer apps and console clients have in common.
type clientAPI struct {
	a     *app
	scope string // kindDeveloper or kindConsole
	base  string // "apps" or "clients"
	topic string // help topic
	admin bool
}

func (a *app) cmdApps(args []string) error {
	c := &clientAPI{a: a, scope: kindDeveloper, base: "apps", topic: "apps"}
	if len(args) == 0 {
		return usagef("apps", "缺少子命令")
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
	case "test-webhook", "webhook-test":
		return c.webhookTest(rest)
	}
	return usagef("apps", "未知子命令 %q", sub)
}

func (c *clientAPI) list(args []string) error {
	fs := newFlags(c.topic + " list")
	var q, status *string
	if c.admin {
		q = fs.String("q", "", "")
		status = fs.String("status", "", "")
	}
	if _, err := exactArgs(fs, c.topic, args, 0, ""); err != nil {
		return err
	}
	query := url.Values{}
	if c.admin {
		if *q != "" {
			query.Set("q", *q)
		}
		if *status != "" {
			switch *status {
			case "active", "pending", "disabled":
			default:
				return usagef(c.topic, "--status 只能是 active、pending 或 disabled")
			}
			query.Set("status", *status)
		}
	}
	s, err := c.a.session(c.scope)
	if err != nil {
		return err
	}
	res, m, err := s.object(http.MethodGet, c.base, query, nil)
	if err != nil {
		return err
	}
	if c.a.jsonOut {
		c.a.printJSON(res.body)
		return nil
	}
	items := objects(m[c.base])
	var rows [][]string
	for _, it := range items {
		row := []string{
			fmtVal("client_id", it["client_id"]),
			fmtVal("client_name", it["client_name"]),
			fmtVal("status", it["status"]),
		}
		if c.admin {
			row = append(row, fmtVal("owner", it["owner"]))
		}
		row = append(row,
			fmtVal("application_type", it["application_type"]),
			fmtVal("token_endpoint_auth_method", it["token_endpoint_auth_method"]),
		)
		if c.admin {
			row = append(row, fmtVal("first_party", it["first_party"]))
		}
		row = append(row, fmtVal("created_at", it["created_at"]))
		rows = append(rows, row)
	}
	headers := []string{"CLIENT_ID", "NAME", "STATUS"}
	if c.admin {
		headers = append(headers, "OWNER")
	}
	headers = append(headers, "TYPE", "AUTH")
	if c.admin {
		headers = append(headers, "FIRST_PARTY")
	}
	headers = append(headers, "CREATED")
	if len(items) == 0 {
		fmt.Fprintln(c.a.stdout, "没有应用")
		return nil
	}
	writeTable(c.a.stdout, headers, rows)
	total := sval(m, "total")
	if total == "" {
		total = fmt.Sprint(len(items))
	}
	fmt.Fprintf(c.a.stdout, "共 %s 个应用\n", total)
	return nil
}

func (c *clientAPI) get(args []string) error {
	pos, err := exactArgs(newFlags(c.topic+" get"), c.topic, args, 1, "应用 ID")
	if err != nil {
		return err
	}
	s, err := c.a.session(c.scope)
	if err != nil {
		return err
	}
	res, m, err := s.object(http.MethodGet, p(c.base, pos[0]), nil, nil)
	if err != nil {
		return err
	}
	if c.a.jsonOut {
		c.a.printJSON(res.body)
		return nil
	}
	writeKV(c.a.stdout, objectKV(m, appOrder))
	return nil
}

// metaFlags are the convenience flags shared by create and update.
type metaFlags struct {
	file       string
	name       string
	typ        string
	scope      string
	webhookURL string
	redirects  stringList
	sets       stringList
}

func (mf *metaFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&mf.file, "f", "", "")
	fs.StringVar(&mf.file, "file", "", "")
	fs.StringVar(&mf.name, "name", "", "")
	fs.StringVar(&mf.typ, "type", "", "")
	fs.StringVar(&mf.scope, "scope", "", "")
	fs.StringVar(&mf.webhookURL, "webhook-url", "", "")
	fs.Var(&mf.redirects, "redirect-uri", "")
	fs.Var(&mf.sets, "set", "")
}

// body builds the request: the -f file first, then flags on top.
func (mf *metaFlags) body(a *app, topic string) (map[string]any, error) {
	body := map[string]any{}
	if mf.file != "" {
		b, err := a.readSource(mf.file)
		if err != nil {
			return nil, err
		}
		d := json.NewDecoder(bytes.NewReader(b))
		d.UseNumber()
		if err := d.Decode(&body); err != nil || body == nil {
			return nil, usagef(topic, "%s 不是有效的 JSON 对象", mf.file)
		}
	}
	if mf.name != "" {
		body["client_name"] = mf.name
	}
	switch mf.typ {
	case "":
	case "web":
		body["application_type"] = "web"
	case "spa":
		body["application_type"] = "web"
		body["token_endpoint_auth_method"] = "none"
	case "native":
		body["application_type"] = "native"
		body["token_endpoint_auth_method"] = "none"
	case "service":
		body["grant_types"] = []string{"client_credentials"}
		body["scope"] = "users:sync"
	default:
		return nil, usagef(topic, "--type 只能是 web、spa、native 或 service")
	}
	if len(mf.redirects) > 0 {
		body["redirect_uris"] = []string(mf.redirects)
	}
	if mf.scope != "" {
		body["scope"] = mf.scope
	}
	if mf.webhookURL != "" {
		body["webhook_url"] = mf.webhookURL
	}
	for _, kvs := range mf.sets {
		k, v, err := parseAssignment(kvs)
		if err != nil {
			return nil, usagef(topic, "%v", err)
		}
		body[k] = v
	}
	return body, nil
}

// parseAssignment splits key=value; the value is JSON when it parses as
// JSON, otherwise a plain string.
func parseAssignment(s string) (string, any, error) {
	k, v, ok := strings.Cut(s, "=")
	k = strings.TrimSpace(k)
	if !ok || k == "" {
		return "", nil, fmt.Errorf("参数 %q 应为 key=value", s)
	}
	return k, parseValue(v), nil
}

func parseValue(v string) any {
	if !json.Valid([]byte(v)) {
		return v
	}
	d := json.NewDecoder(strings.NewReader(v))
	d.UseNumber()
	var x any
	if err := d.Decode(&x); err != nil {
		return v
	}
	return x
}

func (c *clientAPI) create(args []string) error {
	fs := newFlags(c.topic + " create")
	var mf metaFlags
	mf.register(fs)
	if _, err := exactArgs(fs, c.topic, args, 0, ""); err != nil {
		return err
	}
	body, err := mf.body(c.a, c.topic)
	if err != nil {
		return err
	}
	if len(body) == 0 {
		return usagef(c.topic, "需要 -f 文件或 --name 等参数")
	}
	if _, ok := body["client_name"]; !ok {
		return usagef(c.topic, "缺少应用名称：--name 或文件中的 client_name")
	}
	s, err := c.a.session(c.scope)
	if err != nil {
		return err
	}
	res, m, err := s.object(http.MethodPost, c.base, nil, body)
	if err != nil {
		return err
	}
	if c.a.jsonOut {
		c.a.printJSON(res.body)
		if hasSecrets(m) {
			fmt.Fprintln(c.a.stderr, "注意：响应中的密钥只显示这一次，请立即妥善保存。")
		}
		return nil
	}
	fmt.Fprintf(c.a.stdout, "已创建应用 %s\n", sval(m, "client_id"))
	writeKV(c.a.stdout, objectKV(m, appOrder, secretKeys...))
	c.a.printSecrets(m, secretKeys...)
	if sval(m, "status") == "pending_approval" {
		fmt.Fprintln(c.a.stderr, "提示：应用正在等待管理员审批，审批前无法使用。")
	}
	return nil
}

func hasSecrets(m map[string]any) bool {
	for _, k := range secretKeys {
		if sval(m, k) != "" {
			return true
		}
	}
	return false
}

func (c *clientAPI) update(args []string) error {
	fs := newFlags(c.topic + " update")
	var mf metaFlags
	mf.register(fs)
	pos, err := exactArgs(fs, c.topic, args, 1, "应用 ID")
	if err != nil {
		return err
	}
	body, err := mf.body(c.a, c.topic)
	if err != nil {
		return err
	}
	if len(body) == 0 {
		return usagef(c.topic, "没有要修改的内容：使用 -f 文件或 --set key=value")
	}
	s, err := c.a.session(c.scope)
	if err != nil {
		return err
	}
	res, m, err := s.object(http.MethodPatch, p(c.base, pos[0]), nil, body)
	if err != nil {
		return err
	}
	if c.a.jsonOut {
		c.a.printJSON(res.body)
		return nil
	}
	fmt.Fprintf(c.a.stdout, "已更新应用 %s\n", pos[0])
	writeKV(c.a.stdout, objectKV(m, appOrder, secretKeys...))
	c.a.printSecrets(m, secretKeys...)
	return nil
}

func (c *clientAPI) delete(args []string) error {
	fs := newFlags(c.topic + " delete")
	yes := fs.Bool("yes", false, "")
	fs.BoolVar(yes, "y", false, "")
	pos, err := exactArgs(fs, c.topic, args, 1, "应用 ID")
	if err != nil {
		return err
	}
	if err := c.a.canConfirm(*yes, c.topic); err != nil {
		return err
	}
	s, err := c.a.session(c.scope)
	if err != nil {
		return err
	}
	_, m, err := s.object(http.MethodGet, p(c.base, pos[0]), nil, nil)
	if err != nil {
		return err
	}
	id := sval(m, "client_id")
	if id == "" {
		id = pos[0]
	}
	warning := fmt.Sprintf("将永久删除应用 %s（%s），已签发的令牌全部失效，此操作无法撤销。", sval(m, "client_name"), id)
	if err := c.a.confirm(*yes, warning, id); err != nil {
		return err
	}
	var query url.Values
	if c.admin {
		query = url.Values{"confirm": {id}}
	}
	if _, err := s.call(http.MethodDelete, p(c.base, id), query, nil); err != nil {
		return err
	}
	fmt.Fprintf(c.a.stdout, "已删除应用 %s\n", id)
	return nil
}

func (c *clientAPI) rotate(args []string, action, key string) error {
	pos, err := exactArgs(newFlags(c.topic+" "+action), c.topic, args, 1, "应用 ID")
	if err != nil {
		return err
	}
	s, err := c.a.session(c.scope)
	if err != nil {
		return err
	}
	res, m, err := s.object(http.MethodPost, p(c.base, pos[0], action), nil, nil)
	if err != nil {
		return err
	}
	if c.a.jsonOut {
		c.a.printJSON(res.body)
		fmt.Fprintln(c.a.stderr, "注意：新密钥只显示这一次，请立即妥善保存。")
		return nil
	}
	if sval(m, key) == "" {
		return errors.New("服务器没有返回新密钥")
	}
	what := "客户端密钥"
	if key == "webhook_secret" {
		what = "Webhook 签名密钥"
	}
	fmt.Fprintf(c.a.stdout, "已轮换应用 %s 的%s，旧密钥立即失效。\n", pos[0], what)
	c.a.printSecrets(m, key)
	return nil
}

func (c *clientAPI) webhookTest(args []string) error {
	pos, err := exactArgs(newFlags(c.topic+" webhook-test"), c.topic, args, 1, "应用 ID")
	if err != nil {
		return err
	}
	s, err := c.a.session(c.scope)
	if err != nil {
		return err
	}
	res, m, err := s.object(http.MethodPost, p(c.base, pos[0], "webhook-test"), nil, nil)
	if err != nil {
		return err
	}
	delivered, _ := m["delivered"].(bool)
	if c.a.jsonOut {
		c.a.printJSON(res.body)
	} else if delivered {
		fmt.Fprintln(c.a.stdout, "Webhook 测试事件投递成功")
	} else {
		msg := sval(m, "error")
		if msg == "" {
			msg = "未知原因"
		}
		fmt.Fprintf(c.a.stderr, "Webhook 测试事件投递失败：%s\n", msg)
	}
	if !delivered {
		return &exitError{code: 1}
	}
	return nil
}

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// session is an authenticated connection to one API (developer or console).
type session struct {
	a       *app
	token   string
	base    string // scheme://host[/path], no trailing slash
	prefix  string // devAPIPrefix or adminAPIPrefix
	kind    string
	profile string
	envVar  string // set when the token came from an environment variable
	quiet   bool   // suppress token expiry/rotation warnings
}

type response struct {
	status int
	header http.Header
	body   []byte
}

type apiError struct {
	Status      int
	Code        string
	Description string
	Field       string
	RetryAfter  int
}

func (e *apiError) Error() string { return e.render() }

func (e *apiError) render() string {
	if e.Code == "" && e.Description == "" {
		return fmt.Sprintf("错误：服务器返回 HTTP %d %s", e.Status, http.StatusText(e.Status))
	}
	desc := e.Description
	if desc == "" {
		desc = http.StatusText(e.Status)
	}
	code := e.Code
	if code == "" {
		code = "http_" + strconv.Itoa(e.Status)
	}
	s := "错误：" + sanitize(desc) + " (" + sanitize(code)
	if e.Field != "" {
		s += ", 字段 " + sanitize(e.Field)
	}
	return s + ")"
}

func newAPIError(res *response) *apiError {
	var body struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
		Field       string `json:"field"`
	}
	_ = json.Unmarshal(res.body, &body)
	e := &apiError{Status: res.status, Code: body.Error, Description: body.Description, Field: body.Field}
	if res.status == http.StatusTooManyRequests || res.status == http.StatusServiceUnavailable {
		if ra, ok := retryAfter(res.header); ok {
			e.RetryAfter = ra
		}
	}
	return e
}

func tokenKind(t string) (string, error) {
	if t == "" || strings.ContainsFunc(t, func(r rune) bool { return r <= ' ' || r == 0x7f }) {
		return "", errors.New("令牌格式无效")
	}
	switch {
	case strings.HasPrefix(t, devTokenPrefix) && len(t) > len(devTokenPrefix):
		return kindDeveloper, nil
	case strings.HasPrefix(t, admTokenPrefix) && len(t) > len(admTokenPrefix):
		return kindConsole, nil
	}
	return "", errors.New("无法识别的令牌：应以 msso_dev_（开发者）或 msso_adm_（控制台）开头")
}

func kindLabel(kind string) string {
	switch kind {
	case kindDeveloper:
		return "开发者令牌"
	case kindConsole:
		return "控制台令牌"
	}
	return kind
}

func apiPrefix(kind string) string {
	if kind == kindConsole {
		return adminAPIPrefix
	}
	return devAPIPrefix
}

func defaultURL(kind string) string {
	if kind == kindConsole {
		return defaultAdminURL
	}
	return defaultDevURL
}

func urlEnv(kind string) string {
	if kind == kindConsole {
		return "MOONSSO_ADMIN_URL"
	}
	return "MOONSSO_URL"
}

// normalizeBase validates a server URL. Tokens are only ever sent over https,
// except to loopback addresses used for local development.
func normalizeBase(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("服务器地址无效：%s", raw)
	}
	if u.Scheme == "http" && !isLoopback(u.Hostname()) {
		return "", fmt.Errorf("拒绝通过明文 http 发送令牌：%s（只有本机地址允许 http）", raw)
	}
	return strings.TrimRight(u.Scheme+"://"+u.Host+u.EscapedPath(), "/"), nil
}

func isLoopback(host string) bool {
	h := strings.ToLower(host)
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// session resolves the token for a command. scope is kindDeveloper for apps
// commands, kindConsole for admin commands and "" when any kind is accepted.
func (a *app) session(scope string) (*session, error) {
	cfg, _, err := a.loadConfig()
	if err != nil {
		return nil, err
	}
	s := &session{a: a}
	switch scope {
	case kindConsole:
		s.profile = "admin"
		if !a.profileSet {
			if t := strings.TrimSpace(a.env("MOONSSO_ADMIN_TOKEN")); t != "" {
				s.token, s.envVar = t, "MOONSSO_ADMIN_TOKEN"
			}
		}
	default:
		s.profile = cfg.Default
		if scope == kindDeveloper {
			if k, _ := tokenKind(cfg.token(s.profile)); k != kindDeveloper {
				s.profile = "developer"
			}
		}
		if s.profile == "" {
			s.profile = "developer"
		}
		if !a.profileSet {
			if t := strings.TrimSpace(a.env("MOONSSO_TOKEN")); t != "" {
				s.token, s.envVar = t, "MOONSSO_TOKEN"
			} else if t := strings.TrimSpace(a.env("MOONSSO_ADMIN_TOKEN")); t != "" && scope == "" && cfg.token(s.profile) == "" {
				s.token, s.envVar = t, "MOONSSO_ADMIN_TOKEN"
			}
		}
	}
	if a.profileSet {
		s.profile = a.profile
	}
	var saved *profile
	if s.envVar == "" {
		saved = cfg.Profiles[s.profile]
		if saved == nil || saved.Token == "" {
			switch {
			case a.profileSet:
				return nil, fmt.Errorf("profile %s 未登录：请运行 moonsso login --profile %s", s.profile, s.profile)
			case scope == kindConsole:
				return nil, errors.New("未找到控制台令牌：请运行 moonsso login 粘贴 msso_adm_ 令牌，或设置 MOONSSO_ADMIN_TOKEN")
			default:
				return nil, errors.New("未登录：请运行 moonsso login，或设置 MOONSSO_TOKEN")
			}
		}
		s.token = saved.Token
	}
	kind, err := tokenKind(s.token)
	if err != nil {
		if s.envVar != "" {
			return nil, fmt.Errorf("环境变量 %s：%v", s.envVar, err)
		}
		return nil, fmt.Errorf("profile %s：%v", s.profile, err)
	}
	if scope != "" && kind != scope {
		if scope == kindConsole {
			return nil, fmt.Errorf("admin 命令需要控制台令牌（msso_adm_…），当前是%s（msso_dev_…）；请用 moonsso login 保存控制台令牌或设置 MOONSSO_ADMIN_TOKEN", kindLabel(kind))
		}
		return nil, fmt.Errorf("此命令需要开发者令牌（msso_dev_…），当前是%s（msso_adm_…）；控制台操作请使用 moonsso admin", kindLabel(kind))
	}
	s.kind = kind
	s.prefix = apiPrefix(kind)
	base := a.baseURL
	if base == "" {
		base = a.env(urlEnv(kind))
	}
	if base == "" && saved != nil {
		base = saved.URL
	}
	if base == "" {
		base = defaultURL(kind)
	}
	if s.base, err = normalizeBase(base); err != nil {
		return nil, err
	}
	return s, nil
}

// p joins path segments, escaping each one.
func p(segs ...string) string {
	out := make([]string, len(segs))
	for i, s := range segs {
		out[i] = url.PathEscape(s)
	}
	return strings.Join(out, "/")
}

func (s *session) url(path string) string {
	if strings.HasPrefix(path, "/api/") {
		return s.base + path
	}
	return s.base + s.prefix + "/" + strings.TrimPrefix(path, "/")
}

// send performs one request with the retry policy: GET is retried once on
// connection errors, 502 and 503; any method is retried once after a 429
// whose Retry-After is at most 10 seconds.
func (s *session) send(method, path string, query url.Values, body []byte) (*response, error) {
	u := s.url(path)
	if len(query) > 0 {
		sep := "?"
		if strings.Contains(u, "?") {
			sep = "&"
		}
		u += sep + query.Encode()
	}
	retried := false
	for {
		var rdr io.Reader
		if body != nil {
			rdr = bytes.NewReader(body)
		}
		req, err := http.NewRequest(method, u, rdr)
		if err != nil {
			return nil, fmt.Errorf("请求无效：%v", unwrapURLError(err))
		}
		req.Header.Set("Authorization", "Bearer "+s.token)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "moonsso/"+versionString())
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		res, err := s.a.http.Do(req)
		if err != nil {
			if method == http.MethodGet && !retried {
				retried = true
				sleep(time.Second)
				continue
			}
			return nil, fmt.Errorf("无法连接 %s：%v", s.base, unwrapURLError(err))
		}
		b, err := io.ReadAll(io.LimitReader(res.Body, 32<<20))
		res.Body.Close()
		if err != nil {
			if method == http.MethodGet && !retried {
				retried = true
				sleep(time.Second)
				continue
			}
			return nil, fmt.Errorf("读取响应失败：%v", unwrapURLError(err))
		}
		if !retried {
			ra, has := retryAfter(res.Header)
			wait := time.Second
			if has {
				wait = time.Duration(ra) * time.Second
			}
			retry := false
			switch {
			case res.StatusCode == http.StatusTooManyRequests:
				retry = ra <= 10
			case method == http.MethodGet && (res.StatusCode == http.StatusBadGateway || res.StatusCode == http.StatusServiceUnavailable):
				retry = ra <= 10
			}
			if retry {
				retried = true
				sleep(wait)
				continue
			}
		}
		s.checkHeaders(res.Header)
		return &response{status: res.StatusCode, header: res.Header, body: b}, nil
	}
}

// call sends a request with an optional JSON body ([]byte is sent as is) and
// turns error statuses into *apiError.
func (s *session) call(method, path string, query url.Values, body any) (*response, error) {
	var raw []byte
	if body != nil {
		if b, ok := body.([]byte); ok {
			raw = b
		} else {
			var err error
			if raw, err = json.Marshal(body); err != nil {
				return nil, err
			}
		}
	}
	res, err := s.send(method, path, query, raw)
	if err != nil {
		return nil, err
	}
	if res.status >= 400 {
		return res, newAPIError(res)
	}
	return res, nil
}

// object calls and decodes a JSON object response.
func (s *session) object(method, path string, query url.Values, body any) (*response, map[string]any, error) {
	res, err := s.call(method, path, query, body)
	if err != nil {
		return nil, nil, err
	}
	if res.status == http.StatusNoContent || len(bytes.TrimSpace(res.body)) == 0 {
		return res, map[string]any{}, nil
	}
	m, err := decodeObject(res.body)
	if err != nil {
		return nil, nil, fmt.Errorf("无法解析服务器响应：%v", err)
	}
	return res, m, nil
}

func retryAfter(h http.Header) (int, bool) {
	v := strings.TrimSpace(h.Get("Retry-After"))
	if v == "" {
		return 0, false
	}
	if n, err := strconv.Atoi(v); err == nil && n >= 0 {
		return n, true
	}
	if t, err := http.ParseTime(v); err == nil {
		d := int(time.Until(t).Round(time.Second) / time.Second)
		if d < 0 {
			d = 0
		}
		return d, true
	}
	return 0, false
}

func unwrapURLError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

func (s *session) checkHeaders(h http.Header) {
	if s.quiet {
		return
	}
	if strings.EqualFold(strings.TrimSpace(h.Get("Moon-Token-Rotated")), "true") {
		s.a.warn("rotated", "警告：此令牌已被轮换，请改用新令牌")
	}
	v := h.Get("Moon-Token-Expires-At")
	if v == "" {
		return
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return
	}
	left := time.Until(t)
	// The server decides (Moon-Token-Expires-Soon: true|false): less than 7
	// days and less than a quarter of the token's lifetime left. Without the
	// header (older servers) fall back to the plain 7-day rule.
	soon := left < 7*24*time.Hour
	if v := strings.TrimSpace(h.Get("Moon-Token-Expires-Soon")); v != "" {
		soon = strings.EqualFold(v, "true")
	}
	switch {
	case left <= 0:
		s.a.warn("expiry", "警告：令牌已过期")
	case soon:
		s.a.warn("expiry", fmt.Sprintf("警告：令牌将在 %s后过期（%s），可运行 moonsso token rotate 轮换", fmtDuration(left), localTime(t)))
	}
}

func (a *app) warn(key, msg string) {
	if a.warned[key] {
		return
	}
	a.warned[key] = true
	fmt.Fprintln(a.stderr, msg)
}

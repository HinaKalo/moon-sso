package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func init() {
	sleep = func(time.Duration) {}
}

type request struct {
	method, path, query, auth string
	body                      []byte
}

// fakeServer records requests and serves canned handlers keyed by
// "METHOD /path".
type fakeServer struct {
	*httptest.Server
	mu       sync.Mutex
	requests []request
	routes   map[string]http.HandlerFunc
	tokens   map[string]bool
}

func newFakeServer(t *testing.T, tokens ...string) *fakeServer {
	t.Helper()
	f := &fakeServer{routes: map[string]http.HandlerFunc{}, tokens: map[string]bool{}}
	for _, tok := range tokens {
		f.tokens[tok] = true
	}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.requests = append(f.requests, request{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Get("Authorization"), body})
		h := f.routes[r.Method+" "+r.URL.Path]
		ok := f.tokens[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
		f.mu.Unlock()
		if !ok {
			writeJSON(w, 401, map[string]any{"error": "invalid_token", "error_description": "令牌无效"})
			return
		}
		if h == nil {
			writeJSON(w, 404, map[string]any{"error": "not_found", "error_description": "不存在"})
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		h(w, r)
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeServer) handle(route string, h http.HandlerFunc) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.routes[route] = h
}

func (f *fakeServer) allow(tok string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tokens[tok] = true
}

func (f *fakeServer) reqs() []request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]request(nil), f.requests...)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

type cli struct {
	t   *testing.T
	env map[string]string
}

func newCLI(t *testing.T) *cli {
	return &cli{t: t, env: map[string]string{"MOONSSO_CONFIG": filepath.Join(t.TempDir(), "moonsso", "config.json")}}
}

func (c *cli) run(stdin string, args ...string) (int, string, string) {
	c.t.Helper()
	var out, errb bytes.Buffer
	code := run(args, strings.NewReader(stdin), &out, &errb, func(k string) string { return c.env[k] })
	return code, out.String(), errb.String()
}

func (c *cli) config() *config {
	c.t.Helper()
	b, err := os.ReadFile(c.env["MOONSSO_CONFIG"])
	if err != nil {
		c.t.Fatalf("read config: %v", err)
	}
	var cfg config
	if err := json.Unmarshal(b, &cfg); err != nil {
		c.t.Fatalf("parse config: %v", err)
	}
	return &cfg
}

func (c *cli) writeConfig(cfg *config) {
	c.t.Helper()
	if err := saveConfig(c.env["MOONSSO_CONFIG"], cfg); err != nil {
		c.t.Fatal(err)
	}
}

func tokenInfoHandler(kind, owner string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"token": map[string]any{
				"id": "tok1", "kind": kind, "name": "ci", "owner": owner, "hint": "msso_…abcd",
				"scopes": []string{"apps:read", "apps:write"}, "allowed_ips": []string{}, "status": "active",
				"expires_soon": false, "created_at": "2026-01-01T00:00:00Z", "expires_at": "2027-01-01T00:00:00Z",
				"last_used_at": "2026-11-01T00:00:00Z", "last_used_ip": "127.0.0.1",
			},
			"api": "http://example/api",
		}
		if kind == "developer" {
			resp["user"] = map[string]any{"username": owner, "display_name": "Alice", "sub": "u1"}
		} else {
			resp["admin"] = map[string]any{"username": owner}
		}
		writeJSON(w, 200, resp)
	}
}

func TestLoginWithTokenSavesConfig(t *testing.T) {
	dev, adm := "msso_dev_aaaa", "msso_adm_bbbb"
	srv := newFakeServer(t, dev, adm)
	srv.handle("GET /api/v1/developer/token", tokenInfoHandler("developer", "alice"))
	srv.handle("GET /api/v1/token", tokenInfoHandler("console", "root"))
	c := newCLI(t)

	code, out, errs := c.run(dev+"\n", "login", "--with-token", "--url", srv.URL)
	if code != 0 {
		t.Fatalf("login exit %d: %s", code, errs)
	}
	if !strings.Contains(out, "Alice (alice)") || !strings.Contains(out, "apps:read") {
		t.Errorf("login output missing owner/scopes:\n%s", out)
	}
	if strings.Contains(out+errs, dev) {
		t.Error("login printed the token")
	}
	cfg := c.config()
	if cfg.Default != "developer" || cfg.Profiles["developer"] == nil || cfg.Profiles["developer"].Token != dev || cfg.Profiles["developer"].URL != srv.URL {
		t.Fatalf("unexpected config: %+v", cfg)
	}
	if runtime.GOOS != "windows" {
		st, err := os.Stat(c.env["MOONSSO_CONFIG"])
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o600 {
			t.Errorf("config perms = %v, want 0600", st.Mode().Perm())
		}
		dst, _ := os.Stat(filepath.Dir(c.env["MOONSSO_CONFIG"]))
		if dst.Mode().Perm() != 0o700 {
			t.Errorf("config dir perms = %v, want 0700", dst.Mode().Perm())
		}
	}

	// A console token goes to the "admin" profile; the default stays developer.
	code, _, errs = c.run(adm, "login", "--url", srv.URL)
	if code != 0 {
		t.Fatalf("admin login exit %d: %s", code, errs)
	}
	cfg = c.config()
	if cfg.Profiles["admin"] == nil || cfg.Profiles["admin"].Token != adm || cfg.Default != "developer" {
		t.Fatalf("unexpected config after admin login: %+v", cfg)
	}
	if got := srv.reqs(); got[len(got)-1].path != "/api/v1/token" {
		t.Errorf("console token validated at %s", got[len(got)-1].path)
	}
}

func TestLoginRejectsInvalidToken(t *testing.T) {
	srv := newFakeServer(t)
	c := newCLI(t)
	code, _, errs := c.run("msso_dev_bad", "login", "--with-token", "--url", srv.URL)
	if code != 1 || !strings.Contains(errs, "错误：令牌无效 (invalid_token)") {
		t.Fatalf("exit %d, stderr %q", code, errs)
	}
	if _, err := os.Stat(c.env["MOONSSO_CONFIG"]); err == nil {
		t.Error("config written for an invalid token")
	}
	code, _, errs = c.run("ghp_something", "login", "--with-token", "--url", srv.URL)
	if code != 1 || !strings.Contains(errs, "msso_dev_") {
		t.Fatalf("unknown prefix: exit %d, stderr %q", code, errs)
	}
}

func TestPlainHTTPRefusedForRemoteHosts(t *testing.T) {
	c := newCLI(t)
	code, _, errs := c.run("msso_dev_x", "login", "--with-token", "--url", "http://sso.example.com")
	if code != 1 || !strings.Contains(errs, "http") {
		t.Fatalf("exit %d, stderr %q", code, errs)
	}
}

func TestAdminRejectsDeveloperToken(t *testing.T) {
	srv := newFakeServer(t, "msso_dev_aaaa")
	c := newCLI(t)
	c.env["MOONSSO_ADMIN_TOKEN"] = "msso_dev_aaaa"
	c.env["MOONSSO_ADMIN_URL"] = srv.URL
	code, _, errs := c.run("", "admin", "stats")
	if code != 1 || !strings.Contains(errs, "控制台令牌") {
		t.Fatalf("exit %d, stderr %q", code, errs)
	}
	if n := len(srv.reqs()); n != 0 {
		t.Errorf("%d requests sent with the wrong token kind", n)
	}

	// And the reverse: apps with a console token in the developer profile.
	delete(c.env, "MOONSSO_ADMIN_TOKEN")
	c.writeConfig(&config{Default: "developer", Profiles: map[string]*profile{"developer": {URL: srv.URL, Token: "msso_adm_x"}}})
	code, _, errs = c.run("", "apps", "list")
	if code != 1 || !strings.Contains(errs, "开发者令牌") {
		t.Fatalf("apps with console token: exit %d, stderr %q", code, errs)
	}
}

func TestTokenRotateUpdatesSavedToken(t *testing.T) {
	old, fresh := "msso_dev_old", "msso_dev_new"
	srv := newFakeServer(t, old)
	srv.handle("POST /api/v1/developer/token/rotate", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 201, map[string]any{"id": "tok2", "kind": "developer", "status": "active", "expires_at": "2027-06-01T00:00:00Z", "token": fresh})
	})
	c := newCLI(t)
	c.writeConfig(&config{Default: "developer", Profiles: map[string]*profile{"developer": {URL: srv.URL, Token: old}}})

	code, out, errs := c.run("", "token", "rotate", "--grace", "30m")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if got := c.config().Profiles["developer"].Token; got != fresh {
		t.Errorf("saved token = %q, want %q", got, fresh)
	}
	if strings.Contains(out+errs, fresh) {
		t.Error("new token printed although it was saved to the config")
	}
	reqs := srv.reqs()
	var body map[string]int
	json.Unmarshal(reqs[len(reqs)-1].body, &body)
	if body["grace_seconds"] != 1800 {
		t.Errorf("grace body = %s", reqs[len(reqs)-1].body)
	}

	// From an env var the new token is printed once and nothing is saved.
	srv.allow("msso_dev_env")
	c.env["MOONSSO_TOKEN"] = "msso_dev_env"
	c.env["MOONSSO_URL"] = srv.URL
	code, out, errs = c.run("", "token", "rotate")
	if code != 0 {
		t.Fatalf("env rotate exit %d: %s", code, errs)
	}
	if strings.TrimSpace(out) != fresh || !strings.Contains(errs, "MOONSSO_TOKEN") {
		t.Errorf("env rotate stdout %q stderr %q", out, errs)
	}
	if got := c.config().Profiles["developer"].Token; got != fresh {
		t.Errorf("config changed by env rotate: %q", got)
	}
}

func TestParseGrace(t *testing.T) {
	for in, want := range map[string]int{"0": 0, "3600": 3600, "30m": 1800, "1h": 3600, "7d": 604800, "1d12h": 129600} {
		got, err := parseGrace(in)
		if err != nil || got != want {
			t.Errorf("parseGrace(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"8d", "-1", "abc", "1.5s", ""} {
		if _, err := parseGrace(in); err == nil {
			t.Errorf("parseGrace(%q) succeeded", in)
		}
	}
}

func devServer(t *testing.T) (*fakeServer, *cli) {
	tok := "msso_dev_aaaa"
	srv := newFakeServer(t, tok)
	c := newCLI(t)
	c.env["MOONSSO_TOKEN"] = tok
	c.env["MOONSSO_URL"] = srv.URL
	return srv, c
}

func TestAppsListTableAndJSON(t *testing.T) {
	srv, c := devServer(t)
	srv.handle("GET /api/v1/developer/apps", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"total": 2, "apps": []map[string]any{
			{"client_id": "app_one", "client_name": "One", "status": "active", "application_type": "web", "token_endpoint_auth_method": "client_secret_basic", "created_at": "2026-01-01T00:00:00Z"},
			{"client_id": "app_two", "client_name": "Two", "status": "pending_approval", "application_type": "native", "token_endpoint_auth_method": "none", "created_at": "2026-01-02T00:00:00Z"},
		}})
	})
	code, out, errs := c.run("", "apps", "list")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 4 || !strings.HasPrefix(lines[0], "CLIENT_ID") || !strings.Contains(lines[2], "pending_approval") || !strings.Contains(lines[3], "共 2 个应用") {
		t.Fatalf("unexpected table:\n%s", out)
	}
	if strings.Index(lines[0], "NAME") != strings.Index(lines[1], "One") {
		t.Errorf("columns not aligned:\n%s", out)
	}

	code, out, _ = c.run("", "--json", "apps", "list")
	if code != 0 {
		t.Fatalf("--json exit %d", code)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(out), &parsed); err != nil || parsed["total"].(float64) != 2 {
		t.Fatalf("--json output not raw JSON: %v\n%s", err, out)
	}
	if !strings.Contains(out, "\n  \"apps\"") {
		t.Errorf("--json output not pretty-printed:\n%s", out)
	}
	for _, r := range srv.reqs() {
		if r.auth != "Bearer msso_dev_aaaa" {
			t.Errorf("auth header %q", r.auth)
		}
	}
}

func TestAPIRelativeAndAbsolutePaths(t *testing.T) {
	srv, c := devServer(t)
	srv.handle("GET /api/v1/developer/apps", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"apps": []any{}, "total": 0, "q": r.URL.RawQuery})
	})
	srv.handle("PATCH /api/v1/developer/apps/x1", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	})
	code, out, errs := c.run("", "api", "GET", "apps")
	if code != 0 || !strings.Contains(out, "\"total\": 0") {
		t.Fatalf("exit %d stdout %q stderr %q", code, out, errs)
	}
	code, _, _ = c.run("", "api", "get", "/api/v1/developer/apps?limit=1")
	if code != 0 {
		t.Fatalf("absolute path exit %d", code)
	}
	reqs := srv.reqs()
	if reqs[0].path != "/api/v1/developer/apps" || reqs[1].path != "/api/v1/developer/apps" || reqs[1].query != "limit=1" {
		t.Errorf("paths: %+v", reqs)
	}
	code, out, _ = c.run(`{"client_name":"新名字"}`, "api", "PATCH", "apps/x1", "-d", "@-")
	if code != 0 || !strings.Contains(out, "新名字") {
		t.Fatalf("PATCH with stdin body: exit %d, %q", code, out)
	}
	code, out, errs = c.run("", "api", "GET", "nothing")
	if code != 1 || !strings.Contains(out, "not_found") || !strings.Contains(errs, "错误：不存在 (not_found)") {
		t.Fatalf("error status: exit %d stdout %q stderr %q", code, out, errs)
	}
	if code, _, _ = c.run("", "api", "GET", "https://evil.example/x"); code != 2 {
		t.Errorf("full URL accepted, exit %d", code)
	}
}

func TestErrorRenderingAndExitCodes(t *testing.T) {
	srv, c := devServer(t)
	srv.handle("POST /api/v1/developer/apps", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 422, map[string]any{"error": "invalid_client_metadata", "error_description": "回调地址无效", "field": "redirect_uris"})
	})
	code, _, errs := c.run("", "apps", "create", "--name", "X", "--redirect-uri", "nope")
	if code != 1 {
		t.Fatalf("exit %d", code)
	}
	if strings.TrimSpace(errs) != "错误：回调地址无效 (invalid_client_metadata, 字段 redirect_uris)" {
		t.Errorf("stderr = %q", errs)
	}
	var body map[string]any
	json.Unmarshal(srv.reqs()[0].body, &body)
	if body["client_name"] != "X" || body["redirect_uris"].([]any)[0] != "nope" {
		t.Errorf("create body = %v", body)
	}

	if code, _, errs = c.run("", "apps", "frobnicate"); code != 2 || !strings.Contains(errs, "moonsso help apps") {
		t.Errorf("usage error: exit %d stderr %q", code, errs)
	}
	if code, _, _ = c.run(""); code != 2 {
		t.Errorf("no args: exit %d", code)
	}
	if code, out, _ := c.run("", "apps", "--help"); code != 0 || !strings.Contains(out, "rotate-webhook-secret") {
		t.Errorf("help: exit %d", code)
	}
}

func TestDeleteRequiresYesWhenNotInteractive(t *testing.T) {
	srv, c := devServer(t)
	srv.handle("GET /api/v1/developer/apps/app_one", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"client_id": "app_one", "client_name": "One"})
	})
	srv.handle("DELETE /api/v1/developer/apps/app_one", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	code, _, errs := c.run("app_one\n", "apps", "delete", "app_one")
	if code != 2 || !strings.Contains(errs, "--yes") {
		t.Fatalf("exit %d stderr %q", code, errs)
	}
	if n := len(srv.reqs()); n != 0 {
		t.Fatalf("%d requests sent before confirmation", n)
	}
	code, out, errs := c.run("", "apps", "delete", "app_one", "--yes")
	if code != 0 || !strings.Contains(out, "已删除应用 app_one") {
		t.Fatalf("--yes: exit %d stdout %q stderr %q", code, out, errs)
	}

	adm := newFakeServer(t, "msso_adm_root")
	adm.handle("GET /api/v1/users/bob", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"sub": "sub-123", "username": "bob"})
	})
	adm.handle("DELETE /api/v1/users/sub-123", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("confirm") != "bob" {
			writeJSON(w, 400, map[string]any{"error": "confirmation_required", "error_description": "需要确认"})
			return
		}
		w.WriteHeader(204)
	})
	c.env["MOONSSO_ADMIN_TOKEN"] = "msso_adm_root"
	c.env["MOONSSO_ADMIN_URL"] = adm.URL
	if code, _, _ = c.run("", "admin", "users", "delete", "bob"); code != 2 || len(adm.reqs()) != 0 {
		t.Fatalf("admin delete without --yes: exit %d, %d requests", code, len(adm.reqs()))
	}
	code, out, errs = c.run("", "admin", "users", "delete", "bob", "--yes")
	if code != 0 || !strings.Contains(out, "已删除用户 bob") {
		t.Fatalf("admin delete: exit %d stdout %q stderr %q", code, out, errs)
	}
}

func TestSettingsSetParsesJSONValues(t *testing.T) {
	srv := newFakeServer(t, "msso_adm_root")
	var got map[string]any
	srv.handle("PATCH /api/v1/settings", func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&got)
		writeJSON(w, 200, map[string]any{"site_name": "Moon SSO", "registration_open": false, "password_min_length": 10})
	})
	c := newCLI(t)
	c.env["MOONSSO_ADMIN_TOKEN"] = "msso_adm_root"
	c.env["MOONSSO_ADMIN_URL"] = srv.URL
	code, out, errs := c.run("", "admin", "settings", "set", "registration_open=false", "password_min_length=10", "site_name=Moon SSO", "client_registration=approval")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	want := map[string]any{"registration_open": false, "password_min_length": float64(10), "site_name": "Moon SSO", "client_registration": "approval"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %#v, want %#v", k, got[k], v)
		}
	}
	if len(got) != len(want) {
		t.Errorf("body = %v", got)
	}
	if !strings.Contains(out, "password_min_length:") || !strings.Contains(out, "设置已保存") {
		t.Errorf("output:\n%s", out)
	}
	if code, _, _ = c.run("", "admin", "settings", "set", "novalue"); code != 2 {
		t.Errorf("bad assignment: exit %d", code)
	}
}

func TestRetriesAndTokenWarnings(t *testing.T) {
	srv, c := devServer(t)
	calls := 0
	srv.handle("GET /api/v1/developer/token", func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.Header().Set("Retry-After", "1")
			writeJSON(w, 503, map[string]any{"error": "unavailable"})
			return
		}
		w.Header().Set("Moon-Token-Expires-At", time.Now().Add(72*time.Hour).UTC().Format(time.RFC3339))
		w.Header().Set("Moon-Token-Rotated", "true")
		tokenInfoHandler("developer", "alice")(w, r)
	})
	code, out, errs := c.run("", "whoami")
	if code != 0 || calls != 2 {
		t.Fatalf("exit %d after %d calls: %s", code, calls, errs)
	}
	if !strings.Contains(errs, "此令牌已被轮换，请改用新令牌") || !strings.Contains(errs, "后过期") {
		t.Errorf("warnings missing: %q", errs)
	}
	if !strings.Contains(out, "环境变量 MOONSSO_TOKEN") || !strings.Contains(out, "apps:read apps:write") && !strings.Contains(out, "apps:read, apps:write") {
		t.Errorf("whoami output:\n%s", out)
	}

	// The server's Moon-Token-Expires-Soon verdict wins over the 7-day fallback:
	// a short-lived token 3 days from expiry is not "soon" when the server says so.
	for _, tc := range []struct {
		soon string
		want bool
	}{{"false", false}, {"true", true}} {
		srv.handle("GET /api/v1/developer/token", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Moon-Token-Expires-At", time.Now().Add(72*time.Hour).UTC().Format(time.RFC3339))
			w.Header().Set("Moon-Token-Expires-Soon", tc.soon)
			tokenInfoHandler("developer", "alice")(w, r)
		})
		code, _, errs := c.run("", "whoami")
		if code != 0 || strings.Contains(errs, "后过期") != tc.want {
			t.Errorf("Expires-Soon %s: exit %d, stderr %q", tc.soon, code, errs)
		}
	}

	// POST is never retried on 503; 429 with a long Retry-After fails fast.
	posts := 0
	srv.handle("POST /api/v1/developer/apps/a/rotate-secret", func(w http.ResponseWriter, r *http.Request) {
		posts++
		w.Header().Set("Retry-After", "60")
		writeJSON(w, 429, map[string]any{"error": "rate_limited", "error_description": "请求过于频繁"})
	})
	code, _, errs = c.run("", "apps", "rotate-secret", "a")
	if code != 1 || posts != 1 || !strings.Contains(errs, "60 秒后重试") {
		t.Errorf("429: exit %d posts %d stderr %q", code, posts, errs)
	}
}

func TestAppsCreateTypeFlagsAndSecrets(t *testing.T) {
	srv, c := devServer(t)
	var body map[string]any
	srv.handle("POST /api/v1/developer/apps", func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&body)
		writeJSON(w, 201, map[string]any{"client_id": "svc1", "client_name": body["client_name"], "status": "active", "client_secret": "s3cr3t"})
	})
	code, out, errs := c.run("", "apps", "create", "--name", "Sync", "--type", "service", "--set", "require_dpop=true")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if body["scope"] != "users:sync" || body["grant_types"].([]any)[0] != "client_credentials" || body["require_dpop"] != true {
		t.Errorf("body = %v", body)
	}
	if !strings.Contains(out, "client_secret: s3cr3t") || !strings.Contains(errs, "只显示这一次") {
		t.Errorf("secret not shown clearly: stdout %q stderr %q", out, errs)
	}

	code, _, _ = c.run(`{"client_name":"FromFile","redirect_uris":["https://a.example/cb"]}`, "apps", "create", "-f", "-", "--type", "spa")
	if code != 0 || body["client_name"] != "FromFile" || body["token_endpoint_auth_method"] != "none" || body["application_type"] != "web" {
		t.Errorf("create -f -: exit %d body %v", code, body)
	}
}

func TestLogoutRemovesProfile(t *testing.T) {
	srv := newFakeServer(t, "msso_dev_aaaa")
	srv.handle("DELETE /api/v1/developer/token", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	c := newCLI(t)
	c.writeConfig(&config{Default: "developer", Profiles: map[string]*profile{
		"developer": {URL: srv.URL, Token: "msso_dev_aaaa"},
		"admin":     {URL: srv.URL, Token: "msso_adm_bbbb"},
	}})
	code, out, errs := c.run("", "logout", "--revoke")
	if code != 0 || !strings.Contains(out, "已吊销") {
		t.Fatalf("exit %d stdout %q stderr %q", code, out, errs)
	}
	cfg := c.config()
	if cfg.Profiles["developer"] != nil || cfg.Profiles["admin"] == nil || cfg.Default != "admin" {
		t.Errorf("config after logout: %+v", cfg)
	}
}

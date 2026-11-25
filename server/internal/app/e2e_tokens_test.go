package app_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"moon-sso/server/internal/account"
	"moon-sso/server/internal/admin"
	"moon-sso/server/internal/apitoken"
	"moon-sso/server/internal/clients"
	"moon-sso/server/internal/store"
)

var (
	regexpToken        = regexp.MustCompile(`msso_dev_[A-Za-z0-9_-]{43}`)
	regexpConsoleToken = regexp.MustCompile(`msso_adm_[A-Za-z0-9_-]{43}`)
)

type apiResp struct {
	status int
	body   map[string]any
	header http.Header
}

func (r apiResp) str(k string) string { s, _ := r.body[k].(string); return s }

// apiCall performs a JSON request with a bearer token.
func apiCall(t *testing.T, method, u, token string, body any) apiResp {
	t.Helper()
	var rd io.Reader
	if body != nil {
		switch b := body.(type) {
		case string:
			rd = strings.NewReader(b)
		default:
			raw, _ := json.Marshal(b)
			rd = bytes.NewReader(raw)
		}
	}
	req, _ := http.NewRequest(method, u, rd)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	out := apiResp{status: resp.StatusCode, header: resp.Header, body: map[string]any{}}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &out.body); err != nil {
			t.Fatalf("%s %s: non-JSON response %d: %s", method, u, resp.StatusCode, raw)
		}
	}
	return out
}

func issue(t *testing.T, e *env, kind int, owner store.User, name string, scopes []string, life time.Duration, cidrs ...string) string {
	t.Helper()
	plain, _, err := e.app.Tokens.Issue(context.Background(), apitoken.Request{Kind: kind, OwnerID: owner.ID, OwnerName: owner.Username,
		Name: name, Scopes: scopes, Lifetime: life, AllowedCIDRs: cidrs, IP: "test"}, apitoken.Actor{IP: "test"})
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	return plain
}

func TestDeveloperAPITokens(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	a := e.app
	vals := a.Settings.Get()
	vals.ClientRegistration = "open"
	_ = a.Settings.Save(ctx, vals)
	dev, _ := e.user(t, "tok_dev", "Token-Dev-Pass-1", false)
	api := e.base + "/api/v1/developer"
	tok := issue(t, e, store.TokenDeveloper, *dev, "ci", []string{"apps:write"}, 24*time.Hour)
	if !strings.HasPrefix(tok, apitoken.PrefixDeveloper) {
		t.Fatalf("unexpected token prefix %q", tok[:12])
	}

	// Who am I, with the expiry header.
	r := apiCall(t, "GET", api+"/token", tok, nil)
	if r.status != 200 || r.body["user"].(map[string]any)["username"] != "tok_dev" || r.header.Get("Moon-Token-Expires-At") == "" {
		t.Fatalf("token info: %d %v", r.status, r.body)
	}
	// A fresh short-lived token is not "expiring soon" (needs < 1/4 of its lifetime left).
	if r.header.Get("Moon-Token-Expires-Soon") != "false" {
		t.Fatalf("fresh 24h token flagged as expiring: %q", r.header.Get("Moon-Token-Expires-Soon"))
	}
	if r := apiCall(t, "GET", api+"/token", "", nil); r.status != 401 || r.header.Get("WWW-Authenticate") == "" {
		t.Fatalf("missing token: %d", r.status)
	}
	if r := apiCall(t, "GET", api+"/token", tok+"x", nil); r.status != 401 {
		t.Fatalf("tampered token: %d", r.status)
	}

	// App lifecycle; apps:write implies apps:read.
	r = apiCall(t, "POST", api+"/apps", tok, map[string]any{"client_name": "CLI App", "redirect_uris": []string{"https://cli.example/cb"}})
	if r.status != 201 || r.str("client_secret") == "" || r.str("client_id") == "" {
		t.Fatalf("create app: %d %v", r.status, r.body)
	}
	appID := r.str("client_id")
	if r := apiCall(t, "GET", api+"/apps", tok, nil); r.status != 200 || r.body["total"].(float64) != 1 {
		t.Fatalf("list apps: %d %v", r.status, r.body)
	}
	got := apiCall(t, "GET", api+"/apps/"+appID, tok, nil)
	got.body["client_name"] = "Renamed App" // fetched documents can be sent back as is
	if r := apiCall(t, "PATCH", api+"/apps/"+appID, tok, got.body); r.status != 200 || r.str("client_name") != "Renamed App" {
		t.Fatalf("patch app round trip: %d %v", r.status, r.body)
	}
	if r := apiCall(t, "PATCH", api+"/apps/"+appID, tok, map[string]any{"first_party": true}); r.status != 422 || r.str("field") != "first_party" {
		t.Fatalf("developer must not set admin flags: %d %v", r.status, r.body)
	}
	if r := apiCall(t, "POST", api+"/apps/"+appID+"/rotate-secret", tok, nil); r.status != 200 || !strings.HasPrefix(r.str("client_secret"), "mss_") {
		t.Fatalf("rotate secret: %d %v", r.status, r.body)
	}

	// Other people's apps are invisible.
	other, _ := e.user(t, "tok_other", "Token-Other-Pass-1", false)
	ocl, _, err := a.Clients.Create(ctx, clients.Metadata{Name: "Other", RedirectURIs: []string{"https://other.example/cb"}}, nil, &other.ID, false, account.Actor{})
	if err != nil {
		t.Fatal(err)
	}
	if r := apiCall(t, "GET", api+"/apps/"+ocl.ID, tok, nil); r.status != 404 {
		t.Fatalf("foreign app visible: %d", r.status)
	}
	if r := apiCall(t, "DELETE", api+"/apps/"+ocl.ID, tok, nil); r.status != 404 {
		t.Fatalf("foreign app deletable: %d", r.status)
	}

	// Scopes are enforced.
	ro := issue(t, e, store.TokenDeveloper, *dev, "read only", []string{"apps:read"}, 24*time.Hour)
	if r := apiCall(t, "GET", api+"/apps", ro, nil); r.status != 200 {
		t.Fatalf("read-only list: %d", r.status)
	}
	if r := apiCall(t, "POST", api+"/apps", ro, map[string]any{"client_name": "x", "redirect_uris": []string{"https://x.example/cb"}}); r.status != 403 || r.str("error") != "insufficient_scope" {
		t.Fatalf("read-only create: %d %v", r.status, r.body)
	}

	// Kinds never mix: a developer token is useless on the console host.
	if r := apiCall(t, "GET", e.adminBase+"/api/v1/token", tok, nil); r.status != 401 {
		t.Fatalf("developer token accepted by the console: %d", r.status)
	}

	// IP allowlist.
	fenced := issue(t, e, store.TokenDeveloper, *dev, "fenced", []string{"apps:read"}, 24*time.Hour, "203.0.113.0/24")
	if r := apiCall(t, "GET", api+"/apps", fenced, nil); r.status != 403 || r.str("error") != "ip_not_allowed" {
		t.Fatalf("allowlist: %d %v", r.status, r.body)
	}
	local := issue(t, e, store.TokenDeveloper, *dev, "local", []string{"apps:read"}, 24*time.Hour, "127.0.0.1, ::1")
	if r := apiCall(t, "GET", api+"/apps", local, nil); r.status != 200 {
		t.Fatalf("allowlisted ip rejected: %d %v", r.status, r.body)
	}

	// Rotation with a grace period: both work, the old one is flagged.
	r = apiCall(t, "POST", api+"/token/rotate", tok, map[string]any{"grace_seconds": 3600})
	if r.status != 201 || !strings.HasPrefix(r.str("token"), apitoken.PrefixDeveloper) {
		t.Fatalf("rotate: %d %v", r.status, r.body)
	}
	tok2 := r.str("token")
	if r := apiCall(t, "GET", api+"/apps", tok, nil); r.status != 200 || r.header.Get("Moon-Token-Rotated") != "true" {
		t.Fatalf("old token during grace: %d rotated=%q", r.status, r.header.Get("Moon-Token-Rotated"))
	}
	if r := apiCall(t, "GET", api+"/apps", tok2, nil); r.status != 200 || r.header.Get("Moon-Token-Rotated") != "" {
		t.Fatalf("new token: %d", r.status)
	}
	if r := apiCall(t, "POST", api+"/token/rotate", tok, nil); r.status != 409 {
		t.Fatalf("rotating a superseded token twice: %d", r.status)
	}
	// Immediate rotation: the previous token stops at once.
	r = apiCall(t, "POST", api+"/token/rotate", tok2, map[string]any{"grace_seconds": 0})
	tok3 := r.str("token")
	if r.status != 201 || apiCall(t, "GET", api+"/apps", tok2, nil).status != 401 || apiCall(t, "GET", api+"/apps", tok3, nil).status != 200 {
		t.Fatalf("immediate rotation: %d", r.status)
	}
	info := apiCall(t, "GET", api+"/token", tok3, nil).body["token"].(map[string]any)
	if info["scopes"].([]any)[0] != "apps:write" || info["rotated_from"] == "" {
		t.Fatalf("successor lost its scopes: %v", info)
	}
	if r := apiCall(t, "POST", api+"/token/rotate", tok3, map[string]any{"grace_seconds": 999999}); r.status != 422 {
		t.Fatalf("grace beyond 7 days: %d", r.status)
	}

	// Expiry.
	short := issue(t, e, store.TokenDeveloper, *dev, "short", []string{"apps:read"}, time.Hour)
	a.Tokens.Now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	r = apiCall(t, "GET", api+"/apps", short, nil)
	a.Tokens.Now = time.Now
	if r.status != 401 || !strings.Contains(r.str("error_description"), "过期") {
		t.Fatalf("expired token: %d %v", r.status, r.body)
	}

	// Self revocation.
	if r := apiCall(t, "DELETE", api+"/token", tok3, nil); r.status != 204 {
		t.Fatalf("revoke: %d", r.status)
	}
	if r := apiCall(t, "GET", api+"/token", tok3, nil); r.status != 401 {
		t.Fatalf("revoked token works: %d", r.status)
	}

	// Disabling the owner stops their tokens; an admin password reset revokes them.
	if err := a.Accounts.SetStatus(ctx, account.Actor{Admin: true, AdminName: "t"}, dev.ID, store.UserDisabled); err != nil {
		t.Fatal(err)
	}
	if r := apiCall(t, "GET", api+"/apps", ro, nil); r.status != 401 {
		t.Fatalf("disabled owner's token works: %d", r.status)
	}
	_ = a.Accounts.SetStatus(ctx, account.Actor{Admin: true, AdminName: "t"}, dev.ID, store.UserActive)
	if r := apiCall(t, "GET", api+"/apps", ro, nil); r.status != 200 {
		t.Fatalf("re-enabled owner's token: %d", r.status)
	}
	if _, err := a.Accounts.AdminResetPassword(ctx, account.Actor{Admin: true, AdminName: "t"}, dev.ID); err != nil {
		t.Fatal(err)
	}
	if r := apiCall(t, "GET", api+"/apps", ro, nil); r.status != 401 {
		t.Fatalf("token survived an admin password reset: %d", r.status)
	}

	// Actions are audited with the token tag.
	entries, _ := store.ListAudit(ctx, a.DB, store.AuditFilter{ActorID: &dev.ID, Action: "client.created", Limit: 5})
	if len(entries) == 0 || !strings.HasPrefix(entries[0].ActorClientID, "token:") {
		t.Fatalf("API actions not audited with the token: %+v", entries)
	}
	vals.ClientRegistration = "approval"
	_ = a.Settings.Save(ctx, vals)
}

func TestConsoleAPITokens(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	a := e.app
	adm, _, err := admin.CreateAdmin(ctx, a.DB, a.Hasher, "ops_admin", "Ops", "Ops-Admin-Pass-123")
	if err != nil {
		t.Fatal(err)
	}
	owner := store.User{ID: adm.ID, Username: adm.Username}
	tok := issue(t, e, store.TokenConsole, owner, "ops", []string{"users:write", "settings:write", "audit:read", "stats:read", "clients:read"}, 7*24*time.Hour)
	api := e.adminBase + "/api/v1"
	if !strings.HasPrefix(tok, apitoken.PrefixConsole) {
		t.Fatal("console token prefix")
	}
	if r := apiCall(t, "GET", e.base+"/api/v1/developer/token", tok, nil); r.status != 401 {
		t.Fatalf("console token accepted on the SSO host: %d", r.status)
	}
	if r := apiCall(t, "GET", api+"/token", tok, nil); r.status != 200 || r.body["admin"].(map[string]any)["username"] != "ops_admin" {
		t.Fatalf("console token info: %d %v", r.status, r.body)
	}
	if r := apiCall(t, "GET", api+"/stats", tok, nil); r.status != 200 || r.body["users_total"] == nil {
		t.Fatalf("stats: %d %v", r.status, r.body)
	}

	// Users.
	r := apiCall(t, "POST", api+"/users", tok, map[string]any{"username": "api_made", "display_name": "API"})
	if r.status != 201 || r.str("temporary_password") == "" || r.body["must_change_password"] != true {
		t.Fatalf("create user: %d %v", r.status, r.body)
	}
	if r := apiCall(t, "GET", api+"/users?q=api_made", tok, nil); r.status != 200 || r.body["total"].(float64) != 1 {
		t.Fatalf("list users: %d %v", r.status, r.body)
	}
	if r := apiCall(t, "POST", api+"/users/api_made/disable", tok, nil); r.status != 200 || r.str("status") != "disabled" {
		t.Fatalf("disable user: %d %v", r.status, r.body)
	}
	if r := apiCall(t, "POST", api+"/users/api_made/reset-password", tok, nil); r.status != 200 || r.str("temporary_password") == "" {
		t.Fatalf("reset password: %d %v", r.status, r.body)
	}
	if r := apiCall(t, "DELETE", api+"/users/api_made", tok, nil); r.status != 400 || r.str("error") != "confirmation_required" {
		t.Fatalf("delete without confirmation: %d", r.status)
	}
	if r := apiCall(t, "DELETE", api+"/users/api_made?confirm=api_made", tok, nil); r.status != 204 {
		t.Fatalf("delete user: %d %v", r.status, r.body)
	}
	if r := apiCall(t, "GET", api+"/users/api_made", tok, nil); r.status != 404 {
		t.Fatalf("deleted user still found: %d", r.status)
	}

	// Settings: partial update, unknown fields rejected, validation applied.
	if r := apiCall(t, "PATCH", api+"/settings", tok, map[string]any{"registration_open": false}); r.status != 200 || r.body["registration_open"] != false || a.Settings.Get().RegistrationOpen {
		t.Fatalf("patch settings: %d %v", r.status, r.body)
	}
	if r := apiCall(t, "PATCH", api+"/settings", tok, map[string]any{"registraton_open": true}); r.status != 422 {
		t.Fatalf("typo accepted: %d", r.status)
	}
	if r := apiCall(t, "PATCH", api+"/settings", tok, map[string]any{"client_registration": "sometimes"}); r.status != 422 {
		t.Fatalf("invalid value accepted: %d", r.status)
	}
	_ = apiCall(t, "PATCH", api+"/settings", tok, map[string]any{"registration_open": true})

	// Scopes: read-only on clients.
	if r := apiCall(t, "GET", api+"/clients", tok, nil); r.status != 200 {
		t.Fatalf("list clients: %d", r.status)
	}
	if r := apiCall(t, "POST", api+"/clients", tok, map[string]any{"client_name": "x", "redirect_uris": []string{"https://x.example/cb"}}); r.status != 403 {
		t.Fatalf("clients:write not enforced: %d", r.status)
	}
	writer := issue(t, e, store.TokenConsole, owner, "clients", []string{"clients:write"}, 24*time.Hour)
	r = apiCall(t, "POST", api+"/clients", writer, map[string]any{"client_name": "Internal", "redirect_uris": []string{"https://internal.example/cb"},
		"first_party": true, "skip_consent": true, "subject_type": "public"})
	if r.status != 201 || r.body["first_party"] != true || r.str("subject_type") != "public" || r.str("client_secret") == "" {
		t.Fatalf("admin create client with flags: %d %v", r.status, r.body)
	}
	cid := r.str("client_id")
	if r := apiCall(t, "POST", api+"/clients/"+cid+"/disable", writer, nil); r.status != 200 || r.str("status") != "disabled" {
		t.Fatalf("disable client: %d %v", r.status, r.body)
	}
	if r := apiCall(t, "DELETE", api+"/clients/"+cid+"?confirm="+url.QueryEscape(cid), writer, nil); r.status != 204 {
		t.Fatalf("delete client: %d", r.status)
	}
	if r := apiCall(t, "GET", api+"/users", writer, nil); r.status != 403 {
		t.Fatalf("users:read not enforced: %d", r.status)
	}

	// Audit shows the administrator and the token.
	r = apiCall(t, "GET", api+"/audit?actor=@ops_admin&limit=50", tok, nil)
	found := false
	for _, it := range r.body["entries"].([]any) {
		m := it.(map[string]any)
		if m["action"] == "admin.user_deleted" && strings.HasPrefix(m["actor_client"].(string), "token:") {
			found = true
		}
	}
	if r.status != 200 || !found {
		t.Fatalf("audit: %d %v", r.status, r.body)
	}

	// Break-glass reset of the administrator revokes their tokens.
	if _, err := admin.ResetAdmin(ctx, a.DB, a.Hasher, adm, true); err != nil {
		t.Fatal(err)
	}
	if r := apiCall(t, "GET", api+"/token", tok, nil); r.status != 401 {
		t.Fatalf("token survived admin reset: %d", r.status)
	}
}

func TestDeveloperCenterIssuesTokens(t *testing.T) {
	e := setup(t)
	e.user(t, "page_dev", "Page-Dev-Pass-12", false)
	b := e.browser()
	b.login(t, "page_dev", "Page-Dev-Pass-12")
	_, body := b.get(t, "/developer")
	if !strings.Contains(body, "API 令牌") {
		t.Fatal("developer page lacks the API token section")
	}
	csrf := csrfRe.FindStringSubmatch(body)[1]
	resp, body := b.post(t, "/developer/api-tokens", url.Values{"_csrf": {csrf}, "name": {"laptop"}, "scopes": {"apps:read"}, "days": {"30"}})
	m := regexpToken.FindString(body)
	if resp.StatusCode != 200 || m == "" {
		t.Fatalf("issue from page: %d", resp.StatusCode)
	}
	if r := apiCall(t, "GET", e.base+"/api/v1/developer/apps", m, nil); r.status != 200 {
		t.Fatalf("page-issued token: %d", r.status)
	}
	resp, body = b.post(t, "/developer/api-tokens", url.Values{"_csrf": {csrf}, "name": {"bad"}, "scopes": {"users:write"}, "days": {"30"}})
	if resp.StatusCode != 422 || !strings.Contains(body, "不支持的权限") {
		t.Fatalf("console scope accepted for a developer token: %d", resp.StatusCode)
	}
}

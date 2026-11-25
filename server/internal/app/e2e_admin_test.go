package app_test

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"moon-sso/server/internal/admin"
	"moon-sso/server/internal/crypto"
	"moon-sso/server/internal/store"
)

// follow performs GET requests through redirects, across the public and admin hosts.
func (b *browser) follow(t *testing.T, start string, max int) (*http.Response, string) {
	t.Helper()
	u := start
	for i := 0; i < max; i++ {
		resp, body := b.get(t, u)
		if resp.StatusCode < 300 || resp.StatusCode > 399 {
			return resp, body
		}
		next, err := resp.Location()
		if err != nil {
			t.Fatalf("bad redirect from %s", u)
		}
		u = next.String()
	}
	t.Fatalf("too many redirects from %s", start)
	return nil, ""
}

// adminPost posts a form to the console with its own origin.
func (b *browser) adminPost(t *testing.T, base, path string, form url.Values) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, base+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", base)
	resp, err := b.hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	buf := new(strings.Builder)
	_, _ = bufCopy(buf, resp)
	return resp, buf.String()
}

func mustTOTP(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	code, err := crypto.TOTPCode(secret, at)
	if err != nil {
		t.Fatal(err)
	}
	return code
}

var secretRe = regexp.MustCompile(`<code class="mono">([A-Z2-7 ]+)</code>`)

func TestConsoleIsIndependentOfSSO(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	a := e.app
	adm, temp, err := admin.CreateAdmin(ctx, a.DB, a.Hasher, "console_root", "Console Root", "")
	if err != nil || temp == "" {
		t.Fatalf("create admin: %v", err)
	}
	b := e.browser()

	// Anonymous console visitors land on the console's own login page, not the SSO.
	resp, body := b.follow(t, e.adminBase+"/", 4)
	if resp.Request.URL.Host != strings.TrimPrefix(e.adminBase, "http://") || !strings.Contains(body, "超级管理员控制台") {
		t.Fatalf("console login expected, got %s", resp.Request.URL)
	}
	csrf := csrfRe.FindStringSubmatch(body)[1]

	// Step 1: temporary password → forced change.
	resp, _ = b.adminPost(t, e.adminBase, "/login", url.Values{"_csrf": {csrf}, "username": {"console_root"}, "password": {temp}})
	if resp.Header.Get("Location") != "/login/password" {
		t.Fatalf("expected password change step, got %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp, _ = b.adminPost(t, e.adminBase, "/login/password", url.Values{"_csrf": {csrf}, "password": {"Console-Strong-Pass-42"}, "password_confirm": {"Console-Strong-Pass-42"}})
	if resp.Header.Get("Location") != "/login/enroll" {
		t.Fatalf("expected TOTP enrollment, got %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	// Step 2: TOTP enrollment is mandatory.
	_, body = b.get(t, e.adminBase+"/login/enroll")
	m := secretRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatal("no TOTP secret on enrollment page")
	}
	secret := strings.ReplaceAll(m[1], " ", "")
	code, _ := crypto.TOTPCode(secret, time.Now())
	resp, _ = b.adminPost(t, e.adminBase, "/login/enroll", url.Values{"_csrf": {csrf}, "code": {code}})
	if resp.Header.Get("Location") != "/" {
		t.Fatalf("enrollment did not sign in: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp, body = b.get(t, e.adminBase+"/")
	if resp.StatusCode != 200 || !strings.Contains(body, "console-shell") {
		t.Fatalf("dashboard: %d", resp.StatusCode)
	}

	// HTMX search requests get the table fragment, but an htmx history restore
	// (back/forward to a pushed URL) must get the full page with its layout.
	hxGet := func(headers map[string]string) (*http.Response, string) {
		req, _ := http.NewRequest(http.MethodGet, e.adminBase+"/users?q=&status=", nil)
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := b.hc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		buf := new(strings.Builder)
		_, _ = bufCopy(buf, resp)
		return resp, buf.String()
	}
	resp, body = hxGet(map[string]string{"HX-Request": "true"})
	if resp.StatusCode != 200 || strings.Contains(body, "console-shell") || !strings.Contains(body, `id="users-table"`) {
		t.Fatalf("HTMX search should return only the table fragment: %d", resp.StatusCode)
	}
	if !strings.Contains(resp.Header.Get("Vary"), "HX-Request") {
		t.Fatal("pages must vary on HX-Request")
	}
	// Boosted sidebar navigation (hx-boost on <body>) must get full pages too,
	// on every page that has a fragment variant.
	for _, path := range []string{"/", "/users", "/clients", "/audit", "/webhooks", "/settings", "/admins", "/api-tokens", "/profile"} {
		req, _ := http.NewRequest(http.MethodGet, e.adminBase+path, nil)
		req.Header.Set("HX-Request", "true")
		req.Header.Set("HX-Boosted", "true")
		r, err := b.hc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		buf := new(strings.Builder)
		_, _ = bufCopy(buf, r)
		if r.StatusCode != 200 || !strings.Contains(buf.String(), "console-shell") || !strings.Contains(buf.String(), "admin.css") {
			t.Fatalf("boosted navigation to %s returned a fragment (%d)", path, r.StatusCode)
		}
	}
	resp, body = hxGet(map[string]string{"HX-Request": "true", "HX-History-Restore-Request": "true"})
	if resp.StatusCode != 200 || !strings.Contains(body, "console-shell") || !strings.Contains(body, "admin.css") {
		t.Fatalf("history restore must return the full console page: %d", resp.StatusCode)
	}

	// Console actions work with the console's CSRF and are audited as the admin.
	resp, _ = b.adminPost(t, e.adminBase, "/settings/registration", url.Values{"_csrf": {csrf}, "open": {"0"}})
	if resp.StatusCode != 200 || a.Settings.Get().RegistrationOpen {
		t.Fatalf("toggle registration: %d", resp.StatusCode)
	}
	vals := a.Settings.Get()
	vals.RegistrationOpen = true
	_ = a.Settings.Save(ctx, vals)
	entries, _ := store.ListAudit(ctx, a.DB, store.AuditFilter{ActorAdmin: "console_root", Limit: 10})
	if len(entries) == 0 {
		t.Fatal("console actions not audited as the administrator")
	}

	// Next login requires the TOTP code, never the SSO.
	nb := e.browser()
	_, body = nb.follow(t, e.adminBase+"/login", 2)
	csrf2 := csrfRe.FindStringSubmatch(body)[1]
	resp, _ = nb.adminPost(t, e.adminBase, "/login", url.Values{"_csrf": {csrf2}, "username": {"console_root"}, "password": {"Console-Strong-Pass-42"}})
	if resp.Header.Get("Location") != "/login/totp" {
		t.Fatalf("expected TOTP step: %s", resp.Header.Get("Location"))
	}
	code, _ = crypto.TOTPCode(secret, time.Now().Add(30*time.Second))
	if resp, _ = nb.adminPost(t, e.adminBase, "/login/totp", url.Values{"_csrf": {csrf2}, "code": {code}}); resp.Header.Get("Location") != "/" {
		t.Fatalf("totp login failed: %d", resp.StatusCode)
	}

	// Console API tokens are issued from the console with a fresh TOTP code.
	_, body = b.get(t, e.adminBase+"/api-tokens")
	if !strings.Contains(body, "我的控制台令牌") {
		t.Fatal("api token page missing")
	}
	form := url.Values{"_csrf": {csrf}, "name": {"ops laptop"}, "scopes": {"users:read", "audit:read"}, "days": {"7"}, "code": {"000000"}}
	if resp, _ = b.adminPost(t, e.adminBase, "/api-tokens", form); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("token issued without a valid TOTP code: %d", resp.StatusCode)
	}
	_, _ = a.DB.ExecContext(ctx, "UPDATE admin_accounts SET totp_last_step=0 WHERE id=?", adm.ID[:])
	form.Set("code", mustTOTP(t, secret, time.Now()))
	resp, body = b.adminPost(t, e.adminBase, "/api-tokens", form)
	consoleTok := regexpConsoleToken.FindString(body)
	if resp.StatusCode != 200 || consoleTok == "" {
		t.Fatalf("issue console token: %d", resp.StatusCode)
	}
	if r := apiCall(t, "GET", e.adminBase+"/api/v1/users", consoleTok, nil); r.status != 200 {
		t.Fatalf("console token from the page: %d %v", r.status, r.body)
	}
	if r := apiCall(t, "PATCH", e.adminBase+"/api/v1/settings", consoleTok, map[string]any{"registration_open": false}); r.status != 403 {
		t.Fatalf("scope not enforced for page-issued token: %d", r.status)
	}

	// An administrator is not an SSO user: SSO login with the same credentials fails.
	sb := e.browser()
	_, body = sb.get(t, "/login")
	sc := csrfRe.FindStringSubmatch(body)[1]
	if resp, _ := sb.post(t, "/login", url.Values{"_csrf": {sc}, "username": {"console_root"}, "password": {"Console-Strong-Pass-42"}}); resp.StatusCode == http.StatusSeeOther {
		t.Fatal("console administrator signed in to the SSO")
	}

	// An SSO user cannot sign in to the console, and an SSO session grants nothing there.
	e.user(t, "plain_user", "Just-A-User-Here-3", false)
	ub := e.browser()
	ub.login(t, "plain_user", "Just-A-User-Here-3")
	_, body = ub.follow(t, e.adminBase+"/", 4)
	if strings.Contains(body, "console-shell") {
		t.Fatal("SSO session reached the console")
	}
	uc := csrfRe.FindStringSubmatch(body)[1]
	if resp, _ := ub.adminPost(t, e.adminBase, "/login", url.Values{"_csrf": {uc}, "username": {"plain_user"}, "password": {"Just-A-User-Here-3"}}); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("SSO user credentials accepted by the console: %d", resp.StatusCode)
	}

	// The former built-in OIDC client is gone.
	if _, err := store.GetClient(ctx, a.DB, "sso-admin"); err == nil {
		t.Fatal("sso-admin client still exists")
	}
	_ = adm
}

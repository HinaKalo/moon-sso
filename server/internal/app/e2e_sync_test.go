package app_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"moon-sso/server/internal/account"
	"moon-sso/server/internal/store"
)

// loginNative returns tokens for a first-party native client via the challenge flow.
func (e *env) loginNative(t *testing.T, clientID, user, pw, scope string) tokens {
	t.Helper()
	v, ch := pkce()
	r := e.tokenReq(t, "/oauth/authorize-challenge", clientID, "", url.Values{"username": {user}, "password": {pw}, "scope": {scope},
		"code_challenge": {ch}, "code_challenge_method": {"S256"}}, "")
	if r.AuthCode == "" {
		t.Fatalf("challenge: %+v", r)
	}
	tk := e.tokenReq(t, "/oauth/token", clientID, "", url.Values{"grant_type": {"authorization_code"}, "code": {r.AuthCode}, "code_verifier": {v}}, "")
	if tk.AccessToken == "" {
		t.Fatalf("exchange: %+v", tk)
	}
	return tk
}

func (e *env) api(t *testing.T, method, path, token string, body io.Reader, ctype string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(method, e.base+path, body)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	var m map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&m)
	return resp.StatusCode, m
}

type hook struct {
	id, ts, sig string
	body        []byte
}

func TestProfileSyncAcrossApps(t *testing.T) {
	e := setup(t)
	e.user(t, "multi_user", "Multi-App-Sync-4", false)
	// App A (first-party native) edits the profile; app B receives webhook + SSE.
	_, appA := e.client(t, "native-a", true, func(c *store.Client) { c.FirstParty, c.NativeLogin, c.SkipConsent = true, true, true })
	hooks := make(chan hook, 8)
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	go func() {
		_ = http.Serve(l, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			hooks <- hook{r.Header.Get("webhook-id"), r.Header.Get("webhook-timestamp"), r.Header.Get("webhook-signature"), b}
			w.WriteHeader(http.StatusNoContent)
		}))
	}()
	_, appB := e.client(t, "native-b", true, func(c *store.Client) {
		c.FirstParty, c.NativeLogin, c.SkipConsent = true, true, true
		c.WebhookURL, c.WebhookAllowInsecure = "http://"+l.Addr().String()+"/hook", true
	})
	whSecret, enc := e.app.Feed.NewWebhookSecret(appB.ID)
	if _, err := e.app.DB.Exec("UPDATE clients SET webhook_secret_enc=?, webhook_cursor_seq=(SELECT COALESCE(MAX(seq),0) FROM outbox_events) WHERE id=?", enc, appB.ID); err != nil {
		t.Fatal(err)
	}
	e.app.OIDC.InvalidateClient(appB.ID)

	tkA := e.loginNative(t, appA.ID, "multi_user", "Multi-App-Sync-4", "openid profile offline_access profile:write password:write")
	tkB := e.loginNative(t, appB.ID, "multi_user", "Multi-App-Sync-4", "openid profile offline_access")

	// App B opens a live event stream.
	sseReq, _ := http.NewRequest(http.MethodGet, e.base+"/api/v1/me/events", nil)
	sseReq.Header.Set("Authorization", "Bearer "+tkB.AccessToken)
	sseResp, err := http.DefaultClient.Do(sseReq)
	if err != nil {
		t.Fatalf("sse: %v", err)
	}
	if sseResp.StatusCode != 200 {
		t.Fatalf("sse status %d", sseResp.StatusCode)
	}
	defer sseResp.Body.Close()
	blocks := make(chan string, 64)
	go func() {
		buf := make([]byte, 4096)
		var acc string
		for {
			n, err := sseResp.Body.Read(buf)
			acc += string(buf[:n])
			for {
				i := strings.Index(acc, "\n\n")
				if i < 0 {
					break
				}
				blocks <- acc[:i]
				acc = acc[i+2:]
			}
			if err != nil {
				return
			}
		}
	}()
	time.Sleep(300 * time.Millisecond)

	// App A changes nickname and username through the API.
	code, prof := e.api(t, http.MethodPatch, "/api/v1/me", tkA.AccessToken, strings.NewReader(`{"display_name":"新昵称","username":"multi_user2"}`), "application/json")
	if code != 200 || prof["preferred_username"] != "multi_user2" || prof["nickname"] != "新昵称" {
		t.Fatalf("patch: %d %v", code, prof)
	}
	// A token without profile:write is refused.
	if code, _ := e.api(t, http.MethodPatch, "/api/v1/me", tkB.AccessToken, strings.NewReader(`{"display_name":"x"}`), "application/json"); code != http.StatusForbidden {
		t.Fatalf("scope check: %d", code)
	}

	// The webhook reaches app B with a valid Standard Webhooks signature and B's own subject.
	select {
	case h := <-hooks:
		key, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(whSecret, "whsec_"))
		var ts int64
		fmt.Sscan(h.ts, &ts)
		if feedSign(key, h.id, ts, h.body) != h.sig {
			t.Fatal("webhook signature mismatch")
		}
		var ev map[string]any
		_ = json.Unmarshal(h.body, &ev)
		data := ev["data"].(map[string]any)
		subB := e.verifyJWT(t, tkB.IDToken, "")["sub"]
		if ev["type"] != "user.updated" || data["preferred_username"] != "multi_user2" || data["sub"] != subB {
			t.Fatalf("webhook payload %v", ev)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("webhook not delivered")
	}

	// SSE delivers the same event live.
	deadline := time.After(15 * time.Second)
	for got := false; !got; {
		select {
		case blk := <-blocks:
			if strings.Contains(blk, "event: user.updated") && strings.Contains(blk, "multi_user2") {
				got = true
			}
		case <-deadline:
			t.Fatal("no SSE event")
		}
	}

	// Avatar upload through the API yields a picture claim.
	code, prof = e.api(t, http.MethodPut, "/api/v1/me/avatar", tkA.AccessToken, bytes.NewReader(testPNG()), "image/png")
	if code != 200 || prof["picture"] == nil {
		t.Fatalf("avatar: %d %v", code, prof)
	}
	resp, err := http.Get(prof["picture"].(string))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "image/jpeg" {
		t.Fatalf("avatar fetch: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}

	// Password change logs out other devices (app B) and keeps the current one (app A).
	code, _ = e.api(t, http.MethodPost, "/api/v1/me/password", tkA.AccessToken,
		strings.NewReader(`{"current_password":"Multi-App-Sync-4","new_password":"Another-Strong-Pass-9"}`), "application/json")
	if code != 200 {
		t.Fatalf("password change %d", code)
	}
	if r := e.tokenReq(t, "/oauth/token", appB.ID, "", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tkB.RefreshToken}}, ""); r.Error != "invalid_grant" {
		t.Fatalf("other device should be logged out: %+v", r)
	}
	if r := e.tokenReq(t, "/oauth/token", appA.ID, "", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tkA.RefreshToken}}, ""); r.Status != 200 {
		t.Fatalf("current device should stay signed in: %+v", r)
	}
}

func TestChangesFeedAndConsentRevocation(t *testing.T) {
	e := setup(t)
	u, _ := e.user(t, "feed_user", "Feed-Me-Events-6", false)
	secret, cl := e.client(t, "web-feed", false, func(c *store.Client) { c.SkipConsent = true })
	b := e.browser()
	b.login(t, "feed_user", "Feed-Me-Events-6")
	v, ch := pkce()
	cb := b.authorize(t, url.Values{"client_id": {cl.ID}, "redirect_uri": {"https://app.example/cb"}, "response_type": {"code"},
		"scope": {"openid profile"}, "code_challenge": {ch}, "code_challenge_method": {"S256"}})
	if tk := e.tokenReq(t, "/oauth/token", cl.ID, secret, url.Values{"grant_type": {"authorization_code"}, "code": {cb.Query().Get("code")},
		"redirect_uri": {"https://app.example/cb"}, "code_verifier": {v}}, ""); tk.Status != 200 {
		t.Fatalf("exchange %+v", tk)
	}
	svc := e.tokenReq(t, "/oauth/token", cl.ID, secret, url.Values{"grant_type": {"client_credentials"}, "scope": {"users:sync"}}, "")
	if svc.AccessToken == "" {
		t.Fatalf("client credentials: %+v", svc)
	}
	code, page := e.api(t, http.MethodGet, "/api/v1/users", svc.AccessToken, nil, "")
	if code != 200 || len(page["users"].([]any)) != 1 {
		t.Fatalf("bulk users: %d %v", code, page)
	}
	watermark := page["watermark"].(string)
	nick := "feed-nick"
	if _, err := e.app.Accounts.UpdateProfile(context.Background(), account.UserActor(u.ID, "t"), u.ID, account.ProfileUpdate{DisplayName: &nick}); err != nil {
		t.Fatal(err)
	}
	if err := e.app.OIDC.RevokeGrant(context.Background(), u.ID, cl.ID, account.UserActor(u.ID, "t")); err != nil {
		t.Fatal(err)
	}
	var types []string
	deadline := time.Now().Add(10 * time.Second)
	for len(types) < 2 && time.Now().Before(deadline) {
		code, resp := e.api(t, http.MethodGet, "/api/v1/users/changes?cursor="+watermark, svc.AccessToken, nil, "")
		if code != 200 {
			t.Fatalf("changes: %d %v", code, resp)
		}
		types = types[:0]
		for _, ev := range resp["events"].([]any) {
			types = append(types, ev.(map[string]any)["type"].(string))
		}
		time.Sleep(300 * time.Millisecond)
	}
	if len(types) != 2 || types[0] != "user.updated" || types[1] != "consent.revoked" {
		t.Fatalf("changes feed types %v", types)
	}
	if code, page := e.api(t, http.MethodGet, "/api/v1/users", svc.AccessToken, nil, ""); code != 200 || len(page["users"].([]any)) != 0 {
		t.Fatalf("revoked user must disappear from bulk: %v", page)
	}
}

func TestDynamicClientRegistration(t *testing.T) {
	e := setup(t)
	dev, _ := e.user(t, "dev_user", "Developer-Rocks-1", false)
	tok, err := e.app.Clients.NewInitialAccessToken(context.Background(), dev.ID, 1, time.Hour, "test")
	if err != nil {
		t.Fatal(err)
	}
	body := `{"client_name":"DCR App","redirect_uris":["https://dcr.example/cb"],"scope":"openid profile","first_party":true}`
	code, out := e.api(t, http.MethodPost, "/oauth/register", tok, strings.NewReader(body), "application/json")
	if code != http.StatusCreated || out["client_secret"] == nil || out["registration_access_token"] == nil {
		t.Fatalf("register: %d %v", code, out)
	}
	if out["status"] != "pending_approval" {
		t.Fatalf("default mode should require approval: %v", out["status"])
	}
	id := out["client_id"].(string)
	cl, _ := store.GetClient(context.Background(), e.app.DB, id)
	if cl.FirstParty || cl.SkipConsent {
		t.Fatal("DCR must never grant admin flags")
	}
	if code, _ := e.api(t, http.MethodPost, "/oauth/register", tok, strings.NewReader(body), "application/json"); code != http.StatusUnauthorized {
		t.Fatalf("IAT reuse: %d", code)
	}
	rat := out["registration_access_token"].(string)
	if code, got := e.api(t, http.MethodGet, "/oauth/register/"+id, rat, nil, ""); code != 200 || got["client_name"] != "DCR App" {
		t.Fatalf("7592 get: %d %v", code, got)
	}
	tok2, _ := e.app.Clients.NewInitialAccessToken(context.Background(), dev.ID, 1, time.Hour, "test")
	if code, got := e.api(t, http.MethodPost, "/oauth/register", tok2, strings.NewReader(`{"client_name":"x","redirect_uris":["javascript:alert(1)"]}`), "application/json"); code != 400 || got["error"] != "invalid_redirect_uri" {
		t.Fatalf("bad redirect: %d %v", code, got)
	}
}

package moonsso_test

// Integration tests run against the local testbed (docs/sdk-spec.md §8).
// They are skipped when http://127.0.0.1:18601 is not reachable.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	moonsso "sso.moonl.cloud/sdk/go"
)

const testbed = "http://127.0.0.1:18601"

func requireTestbed(t *testing.T) {
	t.Helper()
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get(testbed + "/readyz")
	if err != nil {
		t.Skip("testbed not running")
	}
	resp.Body.Close()
}

func post(t *testing.T, path string, ctype string, body io.Reader) map[string]any {
	t.Helper()
	resp, err := http.Post(testbed+path, ctype, body)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var m map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&m)
	if resp.StatusCode != 200 {
		t.Fatalf("%s: %d %v", path, resp.StatusCode, m)
	}
	return m
}

func freshUser(t *testing.T) (string, string) {
	name := fmt.Sprintf("go_%d", time.Now().UnixNano()%1_000_000_000)
	pw := "Fresh-Go-Pass-" + fmt.Sprint(time.Now().UnixNano()%1000)
	b, _ := json.Marshal(map[string]string{"username": name, "password": pw})
	post(t, "/__test/users", "application/json", bytes.NewReader(b))
	return name, pw
}

// browserAuthorize stands in for the user's browser (testbed helper).
func browserAuthorize(t *testing.T, ar *moonsso.AuthRequest, user, pw string) url.Values {
	t.Helper()
	u, _ := url.Parse(ar.URL)
	form := u.Query()
	form.Set("username", user)
	form.Set("password", pw)
	m := post(t, "/__test/authorize", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	cb, err := url.Parse(m["redirect"].(string))
	if err != nil {
		t.Fatal(err)
	}
	return cb.Query()
}

func webClient(t *testing.T) *moonsso.Client {
	c, err := moonsso.NewClient(moonsso.Config{Issuer: testbed, ClientID: "test-web", ClientSecret: "test-web-secret-0123456789abcdef",
		RedirectURL: "http://127.0.0.1:18700/callback", Scopes: []string{"openid", "profile", "offline_access", "profile:write"}})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestWebLoginRefreshAndAccountAPI(t *testing.T) {
	requireTestbed(t)
	ctx := context.Background()
	c := webClient(t)
	ar, err := c.AuthCodeURL(ctx, moonsso.AuthOptions{})
	if err != nil {
		t.Fatal(err)
	}
	user, pw := freshUser(t)
	tok, claims, err := c.Exchange(ctx, ar, browserAuthorize(t, ar, user, pw))
	if err != nil {
		t.Fatal(err)
	}
	if claims.String("preferred_username") != user {
		t.Fatalf("claims %v", claims)
	}
	// Tampered state and issuer are rejected.
	bad := url.Values{"code": {"x"}, "state": {"nope"}, "iss": {testbed}}
	if _, _, err := c.Exchange(ctx, ar, bad); err == nil {
		t.Fatal("state mismatch accepted")
	}

	sess := c.NewSession(&moonsso.MemoryStore{}, moonsso.SessionOptions{})
	if err := sess.Begin(ctx, tok, claims); err != nil {
		t.Fatal(err)
	}
	// Concurrent forced refreshes converge (single-flight + server grace window).
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- sess.Refresh(ctx) }()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("refresh: %v", err)
		}
	}
	nick := "Go 测试"
	p, err := sess.UpdateProfile(ctx, moonsso.ProfileUpdate{DisplayName: &nick})
	if err != nil {
		t.Fatal(err)
	}
	if p.Nickname != nick {
		t.Fatalf("profile %+v", p)
	}
	img := image.NewRGBA(image.Rect(0, 0, 40, 40))
	for i := range img.Pix {
		img.Pix[i] = 200
	}
	img.Set(3, 3, color.Black)
	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	if p, err = sess.UploadAvatar(ctx, buf.Bytes(), "image/png"); err != nil || p.Picture == nil {
		t.Fatalf("avatar: %v %+v", err, p)
	}
	me, err := sess.GetMe(ctx)
	if err != nil || me.Nickname != nick {
		t.Fatalf("get me: %v %+v", err, me)
	}
	// Access tokens verify locally for a resource server.
	at, _ := sess.AccessToken(ctx)
	if _, err := c.VerifyAccessToken(ctx, at); err != nil {
		t.Fatalf("verify access token: %v", err)
	}
	if _, err := c.VerifyAccessToken(ctx, at, "someone-else"); err == nil {
		t.Fatal("wrong audience accepted")
	}
	if err := sess.Logout(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestFirstPartyDPoPWithOTPAndLiveEvents(t *testing.T) {
	requireTestbed(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	key, _ := moonsso.NewDPoPKey()
	c, err := moonsso.NewClient(moonsso.Config{Issuer: testbed, ClientID: "test-native-dpop", DPoP: key,
		Scopes: []string{"openid", "profile", "offline_access", "profile:write"}})
	if err != nil {
		t.Fatal(err)
	}
	// bob has TOTP.
	_, _, err = c.LoginWithPassword(ctx, "bob", "Builder-Pass-22")
	var otp *moonsso.OTPRequiredError
	if !errors.As(err, &otp) {
		t.Fatalf("expected OTP challenge, got %v", err)
	}
	code := post(t, "/__test/totp?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP", "application/json", nil)["code"].(string)
	tok, claims, err := c.CompleteOTP(ctx, otp.Challenge, code)
	if err != nil {
		t.Fatalf("otp: %v", err)
	}
	if claims.String("preferred_username") != "bob" {
		t.Fatalf("claims %v", claims)
	}
	// The refresh token is bound to our key: another key cannot use it.
	other, _ := moonsso.NewDPoPKey()
	thief, _ := moonsso.NewClient(moonsso.Config{Issuer: testbed, ClientID: "test-native-dpop", DPoP: other})
	if _, err := thief.Refresh(ctx, tok.RefreshToken); err == nil {
		t.Fatal("stolen refresh token accepted with another DPoP key")
	}

	// A fresh user for mutations, signed in through the same client.
	user, pw := freshUser(t)
	tok, claims, err = c.LoginWithPassword(ctx, user, pw)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var got []*moonsso.Profile
	sess := c.NewSession(&moonsso.MemoryStore{}, moonsso.SessionOptions{OnProfile: func(p *moonsso.Profile) {
		mu.Lock()
		got = append(got, p)
		mu.Unlock()
	}})
	if err := sess.Begin(ctx, tok, claims); err != nil {
		t.Fatal(err)
	}
	events := make(chan moonsso.Event, 4)
	lctx, lcancel := context.WithCancel(ctx)
	defer lcancel()
	go func() { _ = sess.Listen(lctx, func(e moonsso.Event) { events <- e }) }()
	time.Sleep(700 * time.Millisecond)
	b, _ := json.Marshal(map[string]string{"display_name": "server-side change"})
	post(t, "/__test/users/"+user+"/profile", "application/json", bytes.NewReader(b))
	select {
	case e := <-events:
		if e.Type != moonsso.EventUserUpdated || e.Data.Nickname != "server-side change" {
			t.Fatalf("event %+v", e)
		}
	case <-ctx.Done():
		t.Fatal("no live event")
	}
	if p := sess.Profile(ctx); p == nil || p.Nickname != "server-side change" {
		t.Fatalf("cached profile not updated: %+v", p)
	}
}

func TestWebhookVectorAndLiveDelivery(t *testing.T) {
	v, err := moonsso.NewWebhookVerifier("whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw")
	if err != nil {
		t.Fatal(err)
	}
	if got := v.Sign("msg_p5jXN8AQM9LWM0D4loKWxJek", 1614265330, []byte(`{"test": 2432232314}`)); got != "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=" {
		t.Fatalf("vector: %s", got)
	}
	requireTestbed(t)
	ctx := context.Background()
	// Register our own client so the shared ones stay untouched.
	iat := post(t, "/__test/iat", "application/json", nil)["token"].(string)
	ci, err := moonsso.RegisterClient(ctx, testbed, iat, moonsso.ClientMetadata{ClientName: "go-sdk-test",
		RedirectURIs: []string{"http://127.0.0.1:18700/callback"}, Scope: "openid profile offline_access users:sync",
		GrantTypes: []string{"authorization_code", "refresh_token", "client_credentials"}})
	if err != nil {
		t.Fatal(err)
	}
	post(t, "/__test/clients/"+ci.ClientID+"/trust", "application/json", nil)

	received := make(chan *moonsso.Event, 4)
	logouts := make(chan [2]string, 2)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	mux := http.NewServeMux()
	var verifier *moonsso.WebhookVerifier
	c, _ := moonsso.NewClient(moonsso.Config{Issuer: testbed, ClientID: ci.ClientID, ClientSecret: ci.ClientSecret,
		RedirectURL: "http://127.0.0.1:18700/callback"})
	mux.HandleFunc("/hook", func(w http.ResponseWriter, r *http.Request) {
		verifier.Handler(func(_ context.Context, e *moonsso.Event) error { received <- e; return nil }).ServeHTTP(w, r)
	})
	mux.Handle("/bc", c.BackchannelLogoutHandler(func(_ context.Context, sub, sid string) error {
		logouts <- [2]string{sub, sid}
		return nil
	}))
	go func() { _ = http.Serve(ln, mux) }()
	base := "http://" + ln.Addr().String()
	hb, _ := json.Marshal(map[string]string{"url": base + "/hook"})
	secret := post(t, "/__test/clients/"+ci.ClientID+"/webhook", "application/json", bytes.NewReader(hb))["secret"].(string)
	if verifier, err = moonsso.NewWebhookVerifier(secret); err != nil {
		t.Fatal(err)
	}
	bb, _ := json.Marshal(map[string]string{"url": base + "/bc"})
	post(t, "/__test/clients/"+ci.ClientID+"/backchannel", "application/json", bytes.NewReader(bb))

	user, pw := freshUser(t)
	ar, _ := c.AuthCodeURL(ctx, moonsso.AuthOptions{})
	u, _ := url.Parse(ar.URL)
	form := u.Query()
	form.Set("username", user)
	form.Set("password", pw)
	m := post(t, "/__test/authorize", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	cb, _ := url.Parse(m["redirect"].(string))
	_, claims, err := c.Exchange(ctx, ar, cb.Query())
	if err != nil {
		t.Fatal(err)
	}
	cursor := "0"
	page, err := c.Users(ctx, "", 0)
	if err != nil || len(page.Users) != 1 {
		t.Fatalf("users: %v %+v", err, page)
	}
	cursor = page.Watermark

	b, _ := json.Marshal(map[string]string{"display_name": "hooked"})
	post(t, "/__test/users/"+user+"/profile", "application/json", bytes.NewReader(b))
	select {
	case e := <-received:
		if e.Type != "user.updated" || e.Data.Sub != claims.Subject() || e.Data.Nickname != "hooked" {
			t.Fatalf("webhook %+v", e)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("webhook not received")
	}
	var seen []moonsso.Event
	next, err := c.Sync(ctx, cursor, func(e moonsso.Event) error { seen = append(seen, e); return nil }, func(moonsso.Profile) error { return nil })
	if err != nil || len(seen) != 1 || next == cursor {
		t.Fatalf("sync: %v %d %s", err, len(seen), next)
	}

	post(t, "/__test/logout?session_token="+url.QueryEscape(m["session_token"].(string)), "application/json", nil)
	select {
	case lo := <-logouts:
		if lo[0] != claims.Subject() || lo[1] != claims.String("sid") {
			t.Fatalf("logout %v vs %s %s", lo, claims.Subject(), claims.String("sid"))
		}
	case <-time.After(20 * time.Second):
		t.Fatal("back-channel logout not received")
	}
}

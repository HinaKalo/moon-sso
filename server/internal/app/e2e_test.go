package app_test

// End-to-end tests of the authorization server against a real MySQL database.
// Set MOON_SSO_TEST_DSN (e.g. via an SSH tunnel to the test database); the
// tests drop and recreate every table in that database.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"

	"moon-sso/server/internal/account"
	"moon-sso/server/internal/app"
	"moon-sso/server/internal/config"
	"moon-sso/server/internal/crypto"
	"moon-sso/server/internal/db"
	"moon-sso/server/internal/settings"
	"moon-sso/server/internal/store"
)

type env struct {
	t         *testing.T
	app       *app.App
	base      string
	adminBase string
	offset    time.Duration
	mu        sync.Mutex
}

var (
	shared     *env
	sharedOnce sync.Once
	sharedErr  error
)

func dsn(t *testing.T) string {
	d := os.Getenv("MOON_SSO_TEST_DSN")
	if d == "" {
		if b, err := os.ReadFile("../../../.secrets/test.dsn"); err == nil {
			d = strings.TrimSpace(string(b))
		}
	}
	if d == "" {
		t.Skip("MOON_SSO_TEST_DSN not set")
	}
	return d
}

func resetDB(ctx context.Context, d *db.DB) error {
	rows, err := d.QueryContext(ctx, "SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE()")
	if err != nil {
		return err
	}
	var tables []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return err
		}
		tables = append(tables, n)
	}
	rows.Close()
	for _, tb := range tables {
		if _, err := d.ExecContext(ctx, "DROP TABLE IF EXISTS `"+tb+"`"); err != nil {
			return err
		}
	}
	return d.Migrate(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func setup(t *testing.T) *env {
	t.Helper()
	d := dsn(t)
	sharedOnce.Do(func() {
		ctx := context.Background()
		raw, err := db.Open(ctx, db.Options{DSN: d, MaxOpenConns: 4, MaxIdleConns: 2, ConnMaxLifetime: time.Minute})
		if err != nil {
			sharedErr = err
			return
		}
		if sharedErr = resetDB(ctx, raw); sharedErr != nil {
			return
		}
		raw.Close()
		dir, _ := os.MkdirTemp("", "moonsso")
		_ = os.WriteFile(dir+"/master.key", []byte(crypto.GenerateMasterKey()), 0o600)
		_ = os.WriteFile(dir+"/db.dsn", []byte(d), 0o600)
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			sharedErr = err
			return
		}
		al, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			sharedErr = err
			return
		}
		base := "http://" + l.Addr().String()
		adminBase := "http://" + al.Addr().String()
		cfg := config.Default()
		cfg.Server.PublicURL, cfg.Server.AdminURL = base, adminBase
		cfg.Server.PublicListen = l.Addr().String()
		cfg.Server.InsecureCookies = true
		cfg.Server.Environment = "test"
		cfg.Database.DSNFile = dir + "/db.dsn"
		cfg.Database.MaxOpenConns = 12
		cfg.Secrets.MasterKeyFile = dir + "/master.key"
		cfg.Security.ArgonMemoryKiB = 8 * 1024
		cfg.Security.ArgonConcurrency = 4
		b, _ := os.ReadFile(cfg.Database.DSNFile)
		cfg.Database.DSN = strings.TrimSpace(string(b))
		log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
		a, err := app.New(ctx, cfg, log)
		if err != nil {
			sharedErr = err
			return
		}
		e := &env{app: a, base: base, adminBase: adminBase}
		go func() { _ = http.Serve(al, a.Admin) }()
		a.OIDC.Now = func() time.Time { e.mu.Lock(); defer e.mu.Unlock(); return time.Now().Add(e.offset) }
		a.BC.HTTP = http.DefaultClient // tests deliver to loopback receivers
		a.StartBackground(ctx)
		go func() { _ = http.Serve(l, a.Public) }()
		shared = e
	})
	if sharedErr != nil {
		t.Fatalf("setup: %v", sharedErr)
	}
	shared.t = t
	shared.mu.Lock()
	shared.offset = 0
	shared.mu.Unlock()
	return shared
}

func (e *env) advance(d time.Duration) {
	e.mu.Lock()
	e.offset += d
	e.mu.Unlock()
}

func (e *env) user(t *testing.T, name, pw string, totp bool) (*store.User, string) {
	t.Helper()
	ctx := context.Background()
	u, err := e.app.Accounts.Register(ctx, account.RegisterInput{Username: name, Password: pw, Via: "test", Force: true})
	if err != nil {
		t.Fatalf("register %s: %v", name, err)
	}
	secret := ""
	if totp {
		secret = crypto.NewTOTPSecret()
		code, _ := crypto.TOTPCode(secret, time.Now().Add(-30*time.Second))
		if err := e.app.Accounts.EnableTOTP(ctx, account.UserActor(u.ID, "test"), u.ID, secret, code); err != nil {
			t.Fatalf("enable totp: %v", err)
		}
	}
	return u, secret
}

type clientOpt func(*store.Client)

func (e *env) client(t *testing.T, id string, public bool, opts ...clientOpt) (string, *store.Client) {
	t.Helper()
	now := time.Now().UTC()
	c := &store.Client{
		ID: id, Name: "Test " + id, Type: store.ClientConfidential, ApplicationType: "web",
		TokenEndpointAuthMethod: "client_secret_basic", RedirectURIs: []string{"https://app.example/cb"},
		PostLogoutRedirectURIs: []string{"https://app.example/bye"},
		GrantTypes:             []string{"authorization_code", "refresh_token", "client_credentials"},
		Scopes:                 []string{"openid", "profile", "offline_access", "profile:write", "password:write", "users:sync"},
		IDTokenAlg:             "RS256", SubjectType: "pairwise", AllowRegistration: true, Status: store.ClientActive,
		WebhookEvents: []string{"*"}, CreatedAt: now, UpdatedAt: now,
	}
	secret := ""
	if public {
		c.Type, c.TokenEndpointAuthMethod, c.ApplicationType = store.ClientPublic, "none", "native"
		c.RedirectURIs = []string{"http://127.0.0.1/callback", "com.example.app:/oauth2redirect"}
		c.GrantTypes = []string{"authorization_code", "refresh_token"}
	} else {
		secret = crypto.RandomToken(32)
		c.SecretHash = e.app.OIDC.HashSecret(secret)
	}
	for _, o := range opts {
		o(c)
	}
	if err := store.InsertClient(context.Background(), e.app.DB, c); err != nil {
		t.Fatalf("insert client: %v", err)
	}
	return secret, c
}

// ---- browser ----

type browser struct {
	e   *env
	jar http.CookieJar
	hc  *http.Client
}

func (e *env) browser() *browser {
	jar, _ := cookiejar.New(nil)
	return &browser{e: e, jar: jar, hc: &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

var csrfRe = regexp.MustCompile(`name="_csrf" value="([^"]+)"`)
var requestRe = regexp.MustCompile(`name="request" value="([^"]+)"`)

func (b *browser) get(t *testing.T, path string) (*http.Response, string) {
	t.Helper()
	u := path
	if strings.HasPrefix(path, "/") {
		u = b.e.base + path
	}
	resp, err := b.hc.Get(u)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(body)
}

func (b *browser) post(t *testing.T, path string, form url.Values) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, b.e.base+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", b.e.base)
	resp, err := b.hc.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(body)
}

func (b *browser) login(t *testing.T, username, password string) {
	t.Helper()
	_, body := b.get(t, "/login")
	m := csrfRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatal("no csrf token on login page")
	}
	resp, body := b.post(t, "/login", url.Values{"_csrf": {m[1]}, "username": {username}, "password": {password}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("login failed: %d %s", resp.StatusCode, body)
	}
}

func pkce() (verifier, challenge string) {
	verifier = crypto.RandomToken(48)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

// authorize drives the browser through /oauth/authorize (and consent) and returns the callback URL.
func (b *browser) authorize(t *testing.T, params url.Values) *url.URL {
	t.Helper()
	resp, body := b.get(t, "/oauth/authorize?"+params.Encode())
	if resp.StatusCode == http.StatusOK && strings.Contains(body, `action="/oauth/consent"`) {
		csrf := csrfRe.FindStringSubmatch(body)[1]
		reqv := requestRe.FindStringSubmatch(body)[1]
		resp, body = b.post(t, "/oauth/consent", url.Values{"_csrf": {csrf}, "request": {reqv}, "decision": {"approve"}})
	}
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize: expected redirect, got %d: %.300s", resp.StatusCode, body)
	}
	u, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// ---- token helpers ----

type tokens struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	Scope        string `json:"scope"`
	Error        string `json:"error"`
	Desc         string `json:"error_description"`
	Status       int    `json:"-"`
	Nonce        string `json:"-"`
	AuthCode     string `json:"authorization_code"`
	AuthSession  string `json:"auth_session"`
}

func (e *env) tokenReq(t *testing.T, path string, clientID, secret string, in url.Values, dpop string) tokens {
	t.Helper()
	form := url.Values{}
	for k, v := range in {
		form[k] = v
	}
	req, _ := http.NewRequest(http.MethodPost, e.base+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if secret != "" {
		req.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(secret))
	} else if form.Get("client_id") == "" {
		form.Set("client_id", clientID)
		req, _ = http.NewRequest(http.MethodPost, e.base+path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if dpop != "" {
		req.Header.Set("DPoP", dpop)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	defer resp.Body.Close()
	var tk tokens
	_ = json.NewDecoder(resp.Body).Decode(&tk)
	tk.Status = resp.StatusCode
	tk.Nonce = resp.Header.Get("DPoP-Nonce")
	return tk
}

func (e *env) jwks(t *testing.T) jose.JSONWebKeySet {
	resp, err := http.Get(e.base + "/.well-known/jwks.json")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var set jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		t.Fatal(err)
	}
	return set
}

func (e *env) verifyJWT(t *testing.T, tok string, wantTyp string) map[string]any {
	t.Helper()
	jws, err := jose.ParseSignedCompact(tok, []jose.SignatureAlgorithm{jose.RS256, jose.ES256})
	if err != nil {
		t.Fatalf("parse jwt: %v", err)
	}
	h := jws.Signatures[0].Header
	if typ, _ := h.ExtraHeaders[jose.HeaderType].(string); wantTyp != "" && typ != wantTyp {
		t.Fatalf("typ = %q, want %q", typ, wantTyp)
	}
	set := e.jwks(t)
	keys := set.Key(h.KeyID)
	if len(keys) != 1 {
		t.Fatalf("kid %s not in JWKS", h.KeyID)
	}
	payload, err := jws.Verify(keys[0].Key)
	if err != nil {
		t.Fatalf("signature: %v", err)
	}
	var m map[string]any
	_ = json.Unmarshal(payload, &m)
	return m
}

// ---- DPoP ----

type dpopKey struct{ k *ecdsa.PrivateKey }

func newDPoPKey() *dpopKey {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return &dpopKey{k}
}

func (d *dpopKey) proof(t *testing.T, htm, htu, nonce string) string {
	opts := (&jose.SignerOptions{EmbedJWK: true}).WithType("dpop+jwt")
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: d.k}, opts)
	if err != nil {
		t.Fatal(err)
	}
	claims := map[string]any{"jti": crypto.RandomToken(12), "htm": htm, "htu": htu, "iat": time.Now().Unix()}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	b, _ := json.Marshal(claims)
	jws, err := s.Sign(b)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := jws.CompactSerialize()
	return out
}

// ================== tests ==================

func TestDiscoveryAndJWKS(t *testing.T) {
	e := setup(t)
	resp, err := http.Get(e.base + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	resp.Body.Close()
	if doc["issuer"] != e.base || doc["authorization_response_iss_parameter_supported"] != true {
		t.Fatalf("bad discovery: %v", doc)
	}
	set := e.jwks(t)
	algs := map[string]bool{}
	for _, k := range set.Keys {
		algs[k.Algorithm] = true
	}
	if !algs["RS256"] || !algs["ES256"] {
		t.Fatalf("jwks algs %v", algs)
	}
}

func TestAuthorizationCodeFlow(t *testing.T) {
	e := setup(t)
	u, _ := e.user(t, "flow_user", "Correct-Horse-91", false)
	secret, cl := e.client(t, "web-flow", false)
	b := e.browser()

	// prompt=none without a session must not show UI.
	v, ch := pkce()
	params := url.Values{"client_id": {cl.ID}, "redirect_uri": {"https://app.example/cb"}, "response_type": {"code"},
		"scope": {"openid profile offline_access"}, "state": {"st1"}, "nonce": {"n-123"}, "code_challenge": {ch},
		"code_challenge_method": {"S256"}}
	pn := url.Values{}
	for k, val := range params {
		pn[k] = val
	}
	pn.Set("prompt", "none")
	resp, _ := b.get(t, "/oauth/authorize?"+pn.Encode())
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if loc.Query().Get("error") != "login_required" || loc.Query().Get("iss") != e.base || loc.Query().Get("state") != "st1" {
		t.Fatalf("prompt=none: %s", resp.Header.Get("Location"))
	}

	// Unregistered redirect URIs never redirect.
	bad := url.Values{}
	for k, val := range params {
		bad[k] = val
	}
	bad.Set("redirect_uri", "https://evil.example/cb")
	if resp, _ := b.get(t, "/oauth/authorize?"+bad.Encode()); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad redirect_uri: status %d", resp.StatusCode)
	}

	b.login(t, "flow_user", "Correct-Horse-91")
	cb := b.authorize(t, params)
	q := cb.Query()
	if q.Get("iss") != e.base || q.Get("state") != "st1" || q.Get("code") == "" {
		t.Fatalf("callback %s", cb)
	}
	code := q.Get("code")

	// Wrong verifier fails; the right one succeeds.
	if tk := e.tokenReq(t, "/oauth/token", cl.ID, secret, url.Values{"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {"https://app.example/cb"}, "code_verifier": {strings.Repeat("a", 43)}}, ""); tk.Error != "invalid_grant" {
		t.Fatalf("expected PKCE failure, got %+v", tk)
	}
	_, ch2 := pkce()
	_ = ch2
	// The failed attempt does not consume the code (row unchanged) — redeem it now.
	tk := e.tokenReq(t, "/oauth/token", cl.ID, secret, url.Values{"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {"https://app.example/cb"}, "code_verifier": {v}}, "")
	if tk.Status != 200 || tk.AccessToken == "" || tk.RefreshToken == "" || tk.IDToken == "" {
		t.Fatalf("token exchange: %+v", tk)
	}
	id := e.verifyJWT(t, tk.IDToken, "JWT")
	if id["nonce"] != "n-123" || id["aud"] != cl.ID || id["iss"] != e.base || id["preferred_username"] != "flow_user" {
		t.Fatalf("id token claims %v", id)
	}
	at := e.verifyJWT(t, tk.AccessToken, "at+jwt")
	if at["client_id"] != cl.ID || at["sub"] != id["sub"] {
		t.Fatalf("access token claims %v", at)
	}
	if id["sub"] == u.PublicSub {
		t.Fatal("third-party client must receive a pairwise subject")
	}

	// Userinfo.
	req, _ := http.NewRequest(http.MethodGet, e.base+"/oauth/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tk.AccessToken)
	r2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var ui map[string]any
	_ = json.NewDecoder(r2.Body).Decode(&ui)
	r2.Body.Close()
	if ui["sub"] != id["sub"] || ui["preferred_username"] != "flow_user" {
		t.Fatalf("userinfo %v", ui)
	}

	// Code replay revokes the family produced by the code.
	if tk2 := e.tokenReq(t, "/oauth/token", cl.ID, secret, url.Values{"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {"https://app.example/cb"}, "code_verifier": {v}}, ""); tk2.Error != "invalid_grant" {
		t.Fatalf("code replay accepted: %+v", tk2)
	}
	if tk3 := e.tokenReq(t, "/oauth/token", cl.ID, secret, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tk.RefreshToken}}, ""); tk3.Error != "invalid_grant" {
		t.Fatalf("family should be revoked after code replay: %+v", tk3)
	}

	// Second login reuses consent (no consent page); without offline_access the
	// family is bound to the browser session.
	v2, ch3 := pkce()
	params.Set("code_challenge", ch3)
	params.Set("scope", "openid profile")
	cb = b.authorize(t, params)
	tk = e.tokenReq(t, "/oauth/token", cl.ID, secret, url.Values{"grant_type": {"authorization_code"}, "code": {cb.Query().Get("code")},
		"redirect_uri": {"https://app.example/cb"}, "code_verifier": {v2}}, "")
	if tk.Status != 200 {
		t.Fatalf("second exchange %+v", tk)
	}

	// Introspection: the owning client sees it active, another client does not.
	secret2, other := e.client(t, "web-other", false)
	insp := func(id, sec string) map[string]any {
		req, _ := http.NewRequest(http.MethodPost, e.base+"/oauth/introspect", strings.NewReader(url.Values{"token": {tk.AccessToken}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(id, sec)
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		var m map[string]any
		_ = json.NewDecoder(r.Body).Decode(&m)
		return m
	}
	if insp(cl.ID, secret)["active"] != true {
		t.Fatal("owner introspection should be active")
	}
	if insp(other.ID, secret2)["active"] != false {
		t.Fatal("foreign introspection must be inactive")
	}

	// RP-initiated logout with a matching hint ends the session and its families.
	resp, _ = b.get(t, "/oauth/end_session?"+url.Values{"id_token_hint": {tk.IDToken}, "post_logout_redirect_uri": {"https://app.example/bye"}, "state": {"x"}}.Encode())
	if resp.StatusCode != http.StatusFound || !strings.HasPrefix(resp.Header.Get("Location"), "https://app.example/bye") {
		t.Fatalf("end_session: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	if tk4 := e.tokenReq(t, "/oauth/token", cl.ID, secret, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tk.RefreshToken}}, ""); tk4.Error != "invalid_grant" {
		t.Fatalf("session-bound family must die with the session: %+v", tk4)
	}
}

func TestRefreshRotationGraceAndReuse(t *testing.T) {
	e := setup(t)
	e.user(t, "rot_user", "Rotate-Me-Please-7", false)
	_, cl := e.client(t, "native-rot", true, func(c *store.Client) {
		c.FirstParty, c.NativeLogin, c.SkipConsent, c.SubjectType = true, true, true, "public"
	})
	v, ch := pkce()
	tk := e.tokenReq(t, "/oauth/authorize-challenge", cl.ID, "", url.Values{"username": {"rot_user"}, "password": {"Rotate-Me-Please-7"},
		"scope": {"openid profile offline_access"}, "code_challenge": {ch}, "code_challenge_method": {"S256"}}, "")
	if tk.AuthCode == "" {
		t.Fatalf("challenge: %+v", tk)
	}
	tk = e.tokenReq(t, "/oauth/token", cl.ID, "", url.Values{"grant_type": {"authorization_code"}, "code": {tk.AuthCode}, "code_verifier": {v}}, "")
	if tk.RefreshToken == "" {
		t.Fatalf("exchange: %+v", tk)
	}
	rt0 := tk.RefreshToken

	// Normal rotation.
	r1 := e.tokenReq(t, "/oauth/token", cl.ID, "", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt0}}, "")
	if r1.Status != 200 || r1.RefreshToken == rt0 {
		t.Fatalf("rotation: %+v", r1)
	}
	// Old token inside the grace window returns the same successor.
	r1b := e.tokenReq(t, "/oauth/token", cl.ID, "", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt0}}, "")
	if r1b.RefreshToken != r1.RefreshToken {
		t.Fatalf("grace replay must return the current token: %q vs %q (%s)", r1b.RefreshToken, r1.RefreshToken, r1b.Desc)
	}

	// Concurrent refreshes with the same current token converge on one successor.
	const n = 12
	results := make([]tokens, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = e.tokenReq(t, "/oauth/token", cl.ID, "", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {r1.RefreshToken}}, "")
		}(i)
	}
	wg.Wait()
	for i := 1; i < n; i++ {
		if results[i].Status != 200 || results[i].RefreshToken != results[0].RefreshToken {
			t.Fatalf("concurrent refresh diverged: %+v vs %+v", results[i], results[0])
		}
	}
	current := results[0].RefreshToken

	// After the grace window, presenting an old token revokes the family.
	e.advance(2 * time.Minute)
	defer e.advance(-2 * time.Minute)
	bad := e.tokenReq(t, "/oauth/token", cl.ID, "", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt0}}, "")
	if bad.Error != "invalid_grant" {
		t.Fatalf("reuse after grace accepted: %+v", bad)
	}
	if after := e.tokenReq(t, "/oauth/token", cl.ID, "", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {current}}, ""); after.Error != "invalid_grant" {
		t.Fatalf("family should be revoked: %+v", after)
	}
}

func TestDPoPBoundRefresh(t *testing.T) {
	e := setup(t)
	e.user(t, "dpop_user", "Dpop-Bound-Key-5", false)
	_, cl := e.client(t, "native-dpop", true, func(c *store.Client) {
		c.FirstParty, c.NativeLogin, c.SkipConsent, c.RequireDPoP = true, true, true, true
	})
	key := newDPoPKey()
	htuC := e.base + "/oauth/authorize-challenge"
	htuT := e.base + "/oauth/token"
	v, ch := pkce()
	// First proof without nonce → use_dpop_nonce with a nonce header.
	r := e.tokenReq(t, "/oauth/authorize-challenge", cl.ID, "", url.Values{"username": {"dpop_user"}, "password": {"Dpop-Bound-Key-5"},
		"scope": {"openid offline_access"}, "code_challenge": {ch}, "code_challenge_method": {"S256"}}, key.proof(t, "POST", htuC, ""))
	if r.Error != "use_dpop_nonce" || r.Nonce == "" {
		t.Fatalf("expected use_dpop_nonce: %+v", r)
	}
	r = e.tokenReq(t, "/oauth/authorize-challenge", cl.ID, "", url.Values{"username": {"dpop_user"}, "password": {"Dpop-Bound-Key-5"},
		"scope": {"openid offline_access"}, "code_challenge": {ch}, "code_challenge_method": {"S256"}}, key.proof(t, "POST", htuC, r.Nonce))
	if r.AuthCode == "" {
		t.Fatalf("challenge with dpop: %+v", r)
	}
	nonce := r.Nonce
	tk := e.tokenReq(t, "/oauth/token", cl.ID, "", url.Values{"grant_type": {"authorization_code"}, "code": {r.AuthCode}, "code_verifier": {v}}, key.proof(t, "POST", htuT, nonce))
	if tk.RefreshToken == "" {
		t.Fatalf("exchange: %+v", tk)
	}
	// Refresh without proof fails; with another key fails; with the bound key succeeds.
	if x := e.tokenReq(t, "/oauth/token", cl.ID, "", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tk.RefreshToken}}, ""); x.Status == 200 {
		t.Fatal("refresh without DPoP accepted")
	}
	other := newDPoPKey()
	if x := e.tokenReq(t, "/oauth/token", cl.ID, "", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tk.RefreshToken}}, other.proof(t, "POST", htuT, tk.Nonce)); x.Status == 200 {
		t.Fatal("refresh with a different DPoP key accepted")
	}
	ok := e.tokenReq(t, "/oauth/token", cl.ID, "", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tk.RefreshToken}}, key.proof(t, "POST", htuT, tk.Nonce))
	if ok.Status != 200 {
		t.Fatalf("bound refresh: %+v", ok)
	}
	// Replaying the same proof is rejected.
	p := key.proof(t, "POST", htuT, ok.Nonce)
	_ = e.tokenReq(t, "/oauth/token", cl.ID, "", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {ok.RefreshToken}}, p)
	if x := e.tokenReq(t, "/oauth/token", cl.ID, "", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {ok.RefreshToken}}, p); x.Error != "invalid_dpop_proof" {
		t.Fatalf("proof replay accepted: %+v", x)
	}
}

func TestFirstPartyChallengeWithTOTP(t *testing.T) {
	e := setup(t)
	_, secret := e.user(t, "otp_user", "Two-Factor-Rocks-3", true)
	_, cl := e.client(t, "native-otp", true, func(c *store.Client) { c.FirstParty, c.NativeLogin, c.SkipConsent = true, true, true })
	_, ch := pkce()
	base := url.Values{"username": {"otp_user"}, "password": {"Two-Factor-Rocks-3"}, "scope": {"openid"}, "code_challenge": {ch}, "code_challenge_method": {"S256"}}
	r := e.tokenReq(t, "/oauth/authorize-challenge", cl.ID, "", base, "")
	if r.Error != "insufficient_authorization" || r.AuthSession == "" {
		t.Fatalf("expected otp step: %+v", r)
	}
	code, _ := crypto.TOTPCode(secret, time.Now())
	r2 := e.tokenReq(t, "/oauth/authorize-challenge", cl.ID, "", url.Values{"auth_session": {r.AuthSession}, "otp": {code},
		"code_challenge": {ch}, "code_challenge_method": {"S256"}, "scope": {"openid"}}, "")
	if r2.AuthCode == "" {
		t.Fatalf("otp step: %+v", r2)
	}
	// Wrong password is rejected; non-first-party clients may not use the endpoint.
	bad := url.Values{}
	for k, v := range base {
		bad[k] = v
	}
	bad.Set("password", "nope-nope-nope")
	if x := e.tokenReq(t, "/oauth/authorize-challenge", cl.ID, "", bad, ""); x.Error != "access_denied" {
		t.Fatalf("bad password: %+v", x)
	}
	_, third := e.client(t, "native-third", true)
	if x := e.tokenReq(t, "/oauth/authorize-challenge", third.ID, "", base, ""); x.Error != "unauthorized_client" {
		t.Fatalf("third-party challenge: %+v", x)
	}
}

func TestNativeRegisterRespectsSwitch(t *testing.T) {
	e := setup(t)
	_, cl := e.client(t, "native-reg", true, func(c *store.Client) { c.FirstParty, c.NativeLogin, c.SkipConsent = true, true, true })
	ctx := context.Background()
	vals := e.app.Settings.Get()
	vals.RegistrationOpen = false
	if err := e.app.Settings.Save(ctx, vals); err != nil {
		t.Fatal(err)
	}
	_, ch := pkce()
	form := url.Values{"username": {"newbie_1"}, "password": {"Brand-New-User-8"}, "code_challenge": {ch}, "code_challenge_method": {"S256"}}
	if r := e.tokenReq(t, "/api/v1/native/register", cl.ID, "", form, ""); r.Error != "registration_closed" {
		t.Fatalf("closed registration accepted: %+v", r)
	}
	vals.RegistrationOpen = true
	_ = e.app.Settings.Save(ctx, vals)
	if r := e.tokenReq(t, "/api/v1/native/register", cl.ID, "", form, ""); r.AuthCode == "" {
		t.Fatalf("open registration failed: %+v", r)
	}
	if r := e.tokenReq(t, "/api/v1/native/register", cl.ID, "", form, ""); r.Status != http.StatusUnprocessableEntity {
		t.Fatalf("duplicate username: %+v", r)
	}
	_ = settings.Defaults
}

func TestProfileChangeIsSequencedAndBackchannelDelivered(t *testing.T) {
	e := setup(t)
	received := make(chan string, 4)
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	go func() {
		_ = http.Serve(l, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = r.ParseForm()
			received <- r.PostForm.Get("logout_token")
			w.WriteHeader(http.StatusOK)
		}))
	}()
	u, _ := e.user(t, "sync_user", "Sync-All-The-Things-2", false)
	secret, cl := e.client(t, "web-sync", false, func(c *store.Client) {
		c.BackchannelLogoutURI = "http://" + l.Addr().String() + "/bc"
		c.SkipConsent = true
	})
	b := e.browser()
	b.login(t, "sync_user", "Sync-All-The-Things-2")
	v, ch := pkce()
	cb := b.authorize(t, url.Values{"client_id": {cl.ID}, "redirect_uri": {"https://app.example/cb"}, "response_type": {"code"},
		"scope": {"openid profile"}, "code_challenge": {ch}, "code_challenge_method": {"S256"}})
	tk := e.tokenReq(t, "/oauth/token", cl.ID, secret, url.Values{"grant_type": {"authorization_code"}, "code": {cb.Query().Get("code")},
		"redirect_uri": {"https://app.example/cb"}, "code_verifier": {v}}, "")
	if tk.Status != 200 {
		t.Fatalf("exchange: %+v", tk)
	}
	sub := e.verifyJWT(t, tk.IDToken, "")["sub"]

	nick := "同步测试"
	if _, err := e.app.Accounts.UpdateProfile(context.Background(), account.UserActor(u.ID, "t"), u.ID, account.ProfileUpdate{DisplayName: &nick}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		var n int
		_ = e.app.DB.QueryRow("SELECT COUNT(*) FROM client_events WHERE client_id=?", cl.ID).Scan(&n)
		if n > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("profile event was not sequenced to the client")
		}
		time.Sleep(200 * time.Millisecond)
	}

	// Logging out notifies the client through back-channel logout.
	_, body := b.get(t, "/logout")
	csrf := csrfRe.FindStringSubmatch(body)[1]
	b.post(t, "/logout", url.Values{"_csrf": {csrf}})
	select {
	case lt := <-received:
		claims := e.verifyJWT(t, lt, "logout+jwt")
		if claims["sub"] != sub || claims["events"] == nil {
			t.Fatalf("logout token claims %v", claims)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("no back-channel logout received")
	}
	_ = uuid.Nil
	_ = fmt.Sprint
}

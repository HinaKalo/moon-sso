// Command testbed runs the complete Moon SSO server locally with fixed test
// fixtures and a few test-only helper endpoints (under /__test/). Every SDK's
// integration tests run against it. Never deploy this binary.
//
//	go run ./cmd/testbed -config ../.secrets/dev/config.toml -reset
//
// Fixtures (see docs/sdk-testbed.md):
//
//	users:   alice / Wonderland-Pass-1          (no TOTP)
//	         bob   / Builder-Pass-22            (TOTP secret JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP)
//	clients: test-web        confidential, secret test-web-secret-0123456789abcdef
//	         test-native     public native, first-party, native login
//	         test-native-dpop  same, DPoP required
//	         test-spa        public browser app, DPoP required
//	         test-third      confidential third-party (consent page, pairwise sub)
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/labstack/echo/v5"

	"moon-sso/server/internal/account"
	"moon-sso/server/internal/app"
	"moon-sso/server/internal/config"
	"moon-sso/server/internal/crypto"
	"moon-sso/server/internal/db"
	"moon-sso/server/internal/settings"
	"moon-sso/server/internal/store"
)

const (
	BobTOTPSecret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	WebSecret     = "test-web-secret-0123456789abcdef"
	ThirdSecret   = "test-third-secret-0123456789abcd"
)

func main() {
	cfgPath := flag.String("config", "../.secrets/dev/config.toml", "config file (test database!)")
	listen := flag.String("listen", "127.0.0.1:18601", "public listen address")
	adminListen := flag.String("admin", "127.0.0.1:18602", "admin listen address")
	reset := flag.Bool("reset", false, "drop all tables and re-create fixtures")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fatal(err)
	}
	cfg.Server.PublicListen, cfg.Server.AdminListen = *listen, *adminListen
	cfg.Server.PublicURL, cfg.Server.AdminURL = "http://"+*listen, "http://"+*adminListen
	cfg.Server.InsecureCookies = true
	cfg.Server.Environment = "testbed"
	cfg.Security.ArgonMemoryKiB = 8 * 1024
	cfg.Security.ArgonConcurrency = 4
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	raw, err := db.Open(ctx, db.Options{DSN: cfg.Database.DSN, MaxOpenConns: 4, MaxIdleConns: 2, ConnMaxLifetime: time.Minute})
	if err != nil {
		fatal(err)
	}
	if *reset {
		if err := dropAll(ctx, raw); err != nil {
			fatal(err)
		}
	}
	if err := raw.Migrate(ctx, log); err != nil {
		fatal(err)
	}
	raw.Close()

	a, err := app.New(ctx, cfg, log)
	if err != nil {
		fatal(err)
	}
	if err := seed(ctx, a); err != nil {
		fatal(err)
	}
	a.BC.HTTP = http.DefaultClient
	a.RelaxLimitsForTests()
	registerTestRoutes(a)
	a.StartBackground(ctx)
	pl, err := net.Listen("tcp", *listen)
	if err != nil {
		fatal(err)
	}
	al, err := net.Listen("tcp", *adminListen)
	if err != nil {
		fatal(err)
	}
	go func() { _ = http.Serve(pl, a.Public) }()
	go func() { _ = http.Serve(al, a.Admin) }()
	fmt.Printf("testbed ready on %s (admin %s)\n", cfg.Server.PublicURL, cfg.Server.AdminURL)
	<-ctx.Done()
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "testbed:", err)
	os.Exit(1)
}

func dropAll(ctx context.Context, d *db.DB) error {
	rows, err := d.QueryContext(ctx, "SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE()")
	if err != nil {
		return err
	}
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return err
		}
		names = append(names, n)
	}
	rows.Close()
	for _, n := range names {
		if _, err := d.ExecContext(ctx, "DROP TABLE IF EXISTS `"+n+"`"); err != nil {
			return err
		}
	}
	return nil
}

func seed(ctx context.Context, a *app.App) error {
	v := settings.Defaults()
	v.RegistrationOpen, v.ClientRegistration = true, settings.ClientRegOpen
	v.UsernameCooldownDays = 0
	v.MaxClientsPerDeveloper = 0 // shared by every SDK test suite
	if err := a.Settings.Save(ctx, v); err != nil {
		return err
	}
	ensureUser := func(name, pw, totp string) error {
		if _, err := store.GetUserByUsername(ctx, a.DB, name); err == nil {
			return nil
		}
		u, err := a.Accounts.Register(ctx, account.RegisterInput{Username: name, Password: pw, Via: "testbed", Force: true})
		if err != nil {
			return err
		}
		if totp != "" {
			return a.Accounts.EnableTOTP(ctx, account.Actor{Admin: true}, u.ID, totp, mustCode(totp))
		}
		return nil
	}
	if err := ensureUser("alice", "Wonderland-Pass-1", ""); err != nil {
		return err
	}
	if err := ensureUser("bob", "Builder-Pass-22", BobTOTPSecret); err != nil {
		return err
	}
	all := []string{"openid", "profile", "offline_access", "profile:write", "password:write"}
	now := time.Now().UTC()
	clients := []*store.Client{
		{ID: "test-web", Name: "Test Web", Type: store.ClientConfidential, ApplicationType: "web", TokenEndpointAuthMethod: "client_secret_basic",
			SecretHash: a.OIDC.HashSecret(WebSecret), RedirectURIs: []string{"http://127.0.0.1:18700/callback", "http://localhost:18700/callback"},
			PostLogoutRedirectURIs: []string{"http://127.0.0.1:18700/"}, GrantTypes: []string{"authorization_code", "refresh_token", "client_credentials"},
			Scopes: append(append([]string{}, all...), "users:sync"), FirstParty: true, SkipConsent: true, Verified: true, SubjectType: "public",
			WebhookAllowInsecure: true},
		{ID: "test-native", Name: "Test Native", Type: store.ClientPublic, ApplicationType: "native", TokenEndpointAuthMethod: "none",
			RedirectURIs: []string{"http://127.0.0.1/callback", "com.example.test:/oauth2redirect"}, GrantTypes: []string{"authorization_code", "refresh_token"},
			Scopes: all, FirstParty: true, NativeLogin: true, SkipConsent: true, Verified: true, SubjectType: "public"},
		{ID: "test-native-dpop", Name: "Test Native DPoP", Type: store.ClientPublic, ApplicationType: "native", TokenEndpointAuthMethod: "none",
			RedirectURIs: []string{"http://127.0.0.1/callback", "com.example.test:/oauth2redirect"}, GrantTypes: []string{"authorization_code", "refresh_token"},
			Scopes: all, FirstParty: true, NativeLogin: true, SkipConsent: true, Verified: true, SubjectType: "public", RequireDPoP: true},
		{ID: "test-spa", Name: "Test SPA", Type: store.ClientPublic, ApplicationType: "web", TokenEndpointAuthMethod: "none",
			RedirectURIs: []string{"http://127.0.0.1:18700/", "http://localhost:18700/"}, GrantTypes: []string{"authorization_code", "refresh_token"},
			Scopes: all, FirstParty: true, NativeLogin: true, SkipConsent: true, Verified: true, SubjectType: "public", RequireDPoP: true},
		{ID: "test-third", Name: "Third Party", Type: store.ClientConfidential, ApplicationType: "web", TokenEndpointAuthMethod: "client_secret_basic",
			SecretHash: a.OIDC.HashSecret(ThirdSecret), RedirectURIs: []string{"http://127.0.0.1:18700/callback"},
			GrantTypes: []string{"authorization_code", "refresh_token"}, Scopes: []string{"openid", "profile", "offline_access"}, SubjectType: "pairwise"},
	}
	for _, c := range clients {
		c.Status, c.AllowRegistration, c.IDTokenAlg, c.CreatedAt, c.UpdatedAt = store.ClientActive, true, "RS256", now, now
		c.WebhookEvents = []string{"*"}
		if _, err := store.GetClient(ctx, a.DB, c.ID); err == nil {
			continue
		}
		if err := store.InsertClient(ctx, a.DB, c); err != nil {
			return err
		}
	}
	return nil
}

func mustCode(secret string) string {
	c, _ := crypto.TOTPCode(secret, time.Now().Add(-30*time.Second))
	return c
}

// registerTestRoutes adds helpers that stand in for a human in a browser.
func registerTestRoutes(a *app.App) {
	g := a.Public.Group("/__test")

	// POST /__test/authorize — form fields of an authorization request plus
	// username/password (and otp). Returns {"redirect": "<callback URL with code, state, iss>"}
	// exactly as the browser would have been redirected after login.
	g.POST("/authorize", func(c *echo.Context) error {
		ctx := c.Request().Context()
		form, _ := c.FormValues()
		u, err := a.Accounts.Authenticate(ctx, form.Get("username"), form.Get("password"))
		if err != nil {
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": err.Error()})
		}
		amr := []string{"pwd"}
		if u.HasTOTP() {
			amr = append(amr, "otp")
		}
		tok, _, err := a.Sessions.Create(ctx, u.ID, amr, c.RealIP(), "testbed")
		if err != nil {
			return err
		}
		q := url.Values{}
		for k, v := range form {
			if k != "username" && k != "password" && k != "otp" {
				q[k] = v
			}
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, a.Cfg.Server.PublicURL+"/oauth/authorize?"+q.Encode(), nil)
		req.AddCookie(&http.Cookie{Name: "sso_sid", Value: tok})
		hc := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		resp, err := hc.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if resp.StatusCode != http.StatusFound {
			return c.JSON(http.StatusBadRequest, map[string]any{"error": "authorize did not redirect", "status": resp.StatusCode, "body": string(body)})
		}
		return c.JSON(http.StatusOK, map[string]string{"redirect": resp.Header.Get("Location"), "session_token": tok})
	})

	// POST /__test/totp?secret=... returns the current TOTP code.
	g.POST("/totp", func(c *echo.Context) error {
		code, err := crypto.TOTPCode(c.QueryParam("secret"), time.Now())
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		return c.JSON(http.StatusOK, map[string]string{"code": code})
	})

	// POST /__test/clients/:id/webhook {"url": "..."} sets the webhook URL and returns a new whsec secret.
	g.POST("/clients/:id/webhook", func(c *echo.Context) error {
		var in struct {
			URL string `json:"url"`
		}
		_ = json.NewDecoder(c.Request().Body).Decode(&in)
		ctx := c.Request().Context()
		secret, enc := a.Feed.NewWebhookSecret(c.Param("id"))
		if _, err := a.DB.ExecContext(ctx, `UPDATE clients SET webhook_url=?, webhook_secret_enc=?, webhook_allow_insecure=1, webhook_disabled_at=NULL,
			webhook_cursor_seq=(SELECT COALESCE(MAX(seq),0) FROM outbox_events), webhook_attempts=0, webhook_next_attempt_at=NULL WHERE id=?`, in.URL, enc, c.Param("id")); err != nil {
			return err
		}
		a.OIDC.InvalidateClient(c.Param("id"))
		return c.JSON(http.StatusOK, map[string]string{"secret": secret})
	})

	// POST /__test/clients/:id/backchannel {"url": "..."} sets the back-channel logout URI.
	g.POST("/clients/:id/backchannel", func(c *echo.Context) error {
		var in struct {
			URL string `json:"url"`
		}
		_ = json.NewDecoder(c.Request().Body).Decode(&in)
		if _, err := a.DB.ExecContext(c.Request().Context(), "UPDATE clients SET backchannel_logout_uri=? WHERE id=?", in.URL, c.Param("id")); err != nil {
			return err
		}
		a.OIDC.InvalidateClient(c.Param("id"))
		return c.JSON(http.StatusOK, map[string]bool{"ok": true})
	})

	// POST /__test/clients/:id/trust marks a (DCR-registered) client first-party:
	// skip consent, native login allowed, verified, public subject.
	g.POST("/clients/:id/trust", func(c *echo.Context) error {
		if _, err := a.DB.ExecContext(c.Request().Context(), `UPDATE clients SET first_party=1, skip_consent=1, native_login=1,
			verified=1, subject_type='public', status=1 WHERE id=?`, c.Param("id")); err != nil {
			return err
		}
		a.OIDC.InvalidateClient(c.Param("id"))
		return c.JSON(http.StatusOK, map[string]bool{"ok": true})
	})

	// POST /__test/logout?session_token=... ends that SSO session (triggers back-channel logout).
	g.POST("/logout", func(c *echo.Context) error {
		ctx := c.Request().Context()
		sess, err := a.Sessions.Lookup(ctx, c.QueryParam("session_token"), "127.0.0.1")
		if err != nil {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "no session"})
		}
		if err := a.OIDC.EndSession(ctx, sess, "logout"); err != nil {
			return err
		}
		return c.JSON(http.StatusOK, map[string]bool{"ok": true})
	})

	// POST /__test/users {"username","password"} creates a fresh user (bypasses rate limits).
	g.POST("/users", func(c *echo.Context) error {
		var in struct {
			Username, Password string
		}
		_ = json.NewDecoder(c.Request().Body).Decode(&in)
		u, err := a.Accounts.Register(c.Request().Context(), account.RegisterInput{Username: in.Username, Password: in.Password, Via: "testbed", Force: true})
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		return c.JSON(http.StatusOK, map[string]string{"public_sub": u.PublicSub, "username": u.Username})
	})

	// POST /__test/users/:username/profile {"display_name"} changes a profile server-side (emits events).
	g.POST("/users/:username/profile", func(c *echo.Context) error {
		var in struct {
			DisplayName string `json:"display_name"`
		}
		_ = json.NewDecoder(c.Request().Body).Decode(&in)
		ctx := c.Request().Context()
		u, err := store.GetUserByUsername(ctx, a.DB, strings.ToLower(c.Param("username")))
		if err != nil {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "no user"})
		}
		if _, err := a.Accounts.UpdateProfile(ctx, account.Actor{Admin: true}, u.ID, account.ProfileUpdate{DisplayName: &in.DisplayName}); err != nil {
			return err
		}
		return c.JSON(http.StatusOK, map[string]bool{"ok": true})
	})

	// POST /__test/iat returns a fresh single-use initial access token for DCR.
	g.POST("/iat", func(c *echo.Context) error {
		ctx := c.Request().Context()
		u, err := store.GetUserByUsername(ctx, a.DB, "alice")
		if err != nil {
			return err
		}
		tok, err := a.Clients.NewInitialAccessToken(ctx, u.ID, 1, time.Hour, "testbed")
		if err != nil {
			return err
		}
		return c.JSON(http.StatusOK, map[string]string{"token": tok})
	})
}

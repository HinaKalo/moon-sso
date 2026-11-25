// Package app wires every subsystem together and owns process lifecycle.
package app

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v5"

	"moon-sso/server/internal/account"
	"moon-sso/server/internal/admin"
	"moon-sso/server/internal/api"
	"moon-sso/server/internal/apitoken"
	"moon-sso/server/internal/auth"
	"moon-sso/server/internal/avatar"
	"moon-sso/server/internal/cache"
	"moon-sso/server/internal/clients"
	"moon-sso/server/internal/config"
	"moon-sso/server/internal/crypto"
	"moon-sso/server/internal/db"
	"moon-sso/server/internal/events"
	"moon-sso/server/internal/feed"
	"moon-sso/server/internal/httpx"
	"moon-sso/server/internal/keys"
	"moon-sso/server/internal/oidc"
	"moon-sso/server/internal/portal"
	"moon-sso/server/internal/sdkdist"
	"moon-sso/server/internal/settings"
	"moon-sso/server/internal/store"
	"moon-sso/server/internal/ui"
	"moon-sso/server/web"
)

var Version = "dev"

type App struct {
	Cfg      *config.Config
	Log      *slog.Logger
	DB       *db.DB
	Keys     *crypto.Keyring
	Signing  *keys.Manager
	Hasher   *crypto.Hasher
	Settings *settings.Service
	Accounts *account.Service
	Sessions *auth.Sessions
	Cookies  auth.Cookies
	Assets   *httpx.Assets
	Renderer *httpx.Renderer
	UI       *ui.Handler
	OIDC     *oidc.Provider
	Bus      *events.Bus
	Seq      *events.Sequencer
	BC       *events.Backchannel
	Feed     *feed.Feed
	API      *api.Handler
	Clients  *clients.Service
	Portal   *portal.Handler
	Avatars  *avatar.Store
	AdminH   *admin.Handler
	Tokens   *apitoken.Service

	Public *echo.Echo
	Admin  *echo.Echo

	limiters []*auth.Limiter
	throttle *auth.Throttle
	bg       sync.WaitGroup
	healthy  func() bool
}

// New builds the application. The database must already be migrated.
func New(ctx context.Context, cfg *config.Config, log *slog.Logger) (*App, error) {
	a := &App{Cfg: cfg, Log: log}
	var err error
	if a.Keys, err = crypto.LoadKeyring(cfg.Secrets.MasterKeyFile); err != nil {
		return nil, err
	}
	a.DB, err = db.Open(ctx, db.Options{
		DSN: cfg.Database.DSN, MaxOpenConns: cfg.Database.MaxOpenConns,
		MaxIdleConns: cfg.Database.MaxIdleConns, ConnMaxLifetime: cfg.Database.ConnMaxLifetime.Duration,
	})
	if err != nil {
		return nil, err
	}
	if err := a.DB.CheckSchema(ctx); err != nil {
		return nil, err
	}
	if a.Settings, err = settings.New(ctx, a.DB, log); err != nil {
		return nil, err
	}
	if a.Signing, err = keys.NewManager(ctx, a.DB, a.Keys.Sealer(crypto.PurposeAtRest), log); err != nil {
		return nil, err
	}
	a.Hasher = crypto.NewHasher(crypto.PasswordParams{
		MemoryKiB: cfg.Security.ArgonMemoryKiB, Time: cfg.Security.ArgonTime, Parallelism: cfg.Security.ArgonParallelism,
	}, cfg.Security.ArgonConcurrency, cfg.Security.ArgonQueueWait.Duration)
	a.Cookies = auth.Cookies{Insecure: cfg.Server.InsecureCookies}
	a.Sessions = auth.NewSessions(a.DB, a.Cookies, func() time.Duration { return a.Settings.Get().SessionIdleTTL() }, cfg.Tokens.SessionAbsoluteTTL.Duration)
	a.Accounts = &account.Service{
		Throttle: auth.NewThrottle(),
		DB:       a.DB, Hasher: a.Hasher, Settings: a.Settings, AtRest: a.Keys.Sealer(crypto.PurposeAtRest), Log: log, Now: time.Now,
	}
	if a.Assets, err = httpx.LoadAssets(web.Static); err != nil {
		return nil, err
	}
	funcs := httpx.Funcs(a.Assets, cfg.Server.PublicURL)
	funcs["uaSummary"] = UASummary
	if a.Renderer, err = httpx.NewRenderer(web.Templates, funcs); err != nil {
		return nil, fmt.Errorf("templates: %w", err)
	}
	a.throttle = auth.NewThrottle()
	loginLimiter := auth.NewLimiter(30, 15)
	registerLimiter := auth.NewLimiter(0.5, 5) // 30/hour per IP
	a.limiters = []*auth.Limiter{loginLimiter, registerLimiter}

	a.UI = &ui.Handler{
		Cfg: cfg, DB: a.DB, Accounts: a.Accounts, Sessions: a.Sessions, Settings: a.Settings,
		CSRF:    &auth.CSRF{Key: a.Keys.Key(crypto.PurposeCSRF), Cookies: a.Cookies, Origin: cfg.Server.PublicURL},
		Cookies: a.Cookies, CookieBox: a.Keys.Sealer(crypto.PurposeCookieAEAD), Log: log,
		Throttle: a.throttle, LoginLimiter: loginLimiter, RegisterLimiter: registerLimiter,
		Users: cache.New[uuid.UUID, *store.User](20_000, 30*time.Second),
	}
	a.OIDC = oidc.New(&oidc.Provider{
		Cfg: cfg, DB: a.DB, Keys: a.Signing, Keyring: a.Keys, Settings: a.Settings, Sessions: a.Sessions,
		Accounts: a.Accounts, UI: a.UI, Log: log,
	})
	a.Bus = events.NewBus()
	a.Seq = events.NewSequencer(a.DB, a.Bus, log)
	a.BC = events.NewBackchannel(a.DB, a.OIDC, log)
	wake := func() { a.Seq.Wake(); a.BC.Wake() }
	a.OIDC.WakeEvents = wake
	a.Accounts.Hooks = account.Hooks{
		UserChanged: func(id uuid.UUID) {
			a.UI.InvalidateUser(id)
			a.Sessions.ForgetUser(id)
		},
		RevokeUserTokens: a.OIDC.RevokeUserTokens,
		EventsWritten:    wake,
	}
	a.Avatars = &avatar.Store{Dir: cfg.Storage.DataDir + "/avatars"}
	a.Feed = feed.New(&feed.Feed{DB: a.DB, OIDC: a.OIDC, Bus: a.Bus, AtRest: a.Keys.Sealer(crypto.PurposeAtRest), Log: log, PublicURL: cfg.Server.PublicURL})
	a.Clients = &clients.Service{DB: a.DB, OIDC: a.OIDC, Feed: a.Feed, Settings: a.Settings, Log: log}
	a.Tokens = apitoken.New(&apitoken.Service{DB: a.DB, Keyring: a.Keys, Log: log})
	a.API = api.New(&api.Handler{DB: a.DB, OIDC: a.OIDC, Accounts: a.Accounts, Avatars: a.Avatars, Feed: a.Feed, Settings: a.Settings, Sessions: a.Sessions, Log: log})
	a.Portal = &portal.Handler{TestLimiter: auth.NewLimiter(6, 3), DB: a.DB, UI: a.UI, OIDC: a.OIDC, Accounts: a.Accounts, Avatars: a.Avatars, Clients: a.Clients, Feed: a.Feed, Settings: a.Settings, Tokens: a.Tokens, Log: log}
	// The console uses its own keys and cookies; nothing is shared with SSO sessions.
	a.AdminH = admin.New(&admin.Handler{
		Cfg: cfg, DB: a.DB, OIDC: a.OIDC, Keys: a.Signing, Accounts: a.Accounts, Clients: a.Clients, Feed: a.Feed,
		Settings: a.Settings, Sessions: a.Sessions, Cookies: a.Cookies, Log: log, Hasher: a.Hasher, Tokens: a.Tokens,
		Box:    a.Keys.Sealer("moon-sso/admin-cookie/v1"),
		AtRest: a.Keys.Sealer(crypto.PurposeAtRest),
		CSRF:   &auth.CSRF{Key: a.Keys.Key("moon-sso/admin-csrf/v1"), Cookies: a.Cookies, Origin: cfg.Server.AdminURL},
	})
	a.limiters = append(a.limiters, a.Portal.TestLimiter)
	httpx.Metrics.Gauge("sse_connections", func() float64 { return float64(a.Feed.Connections()) })
	a.UI.OnLogout = func(ctx context.Context, sess *store.Session, reason string) {
		if err := a.OIDC.EndSession(ctx, sess, reason); err != nil {
			a.Log.Warn("end session failed", "err", err)
		}
	}

	a.Public = httpx.NewEcho(log, a.Renderer, a.errorHandler)
	a.Admin = httpx.NewEcho(log, a.Renderer, a.errorHandler)
	a.routesPublic()
	a.routesAdmin()
	a.healthy = func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		return a.DB.PingContext(ctx) == nil
	}
	return a, nil
}

func (a *App) routesPublic() {
	e := a.Public
	e.GET("/healthz", func(c *echo.Context) error { return c.String(http.StatusOK, "ok") })
	e.GET("/readyz", a.ready)
	e.GET("/static/:hash/*", a.Assets.Handler())
	e.GET("/favicon.ico", func(c *echo.Context) error {
		return c.Redirect(http.StatusMovedPermanently, a.Assets.URL("favicon.svg"))
	})
	e.GET("/robots.txt", func(c *echo.Context) error { return c.String(http.StatusOK, "User-agent: *\nDisallow: /\n") })

	h := a.UI
	pages := e.Group("", httpx.SecurityHeaders(), httpx.HTMXPages(), httpx.NoStore(), httpx.BodyLimit(64<<10), httpx.WriteDeadline(30*time.Second),
		h.LoadSession(), h.CSRF.Middleware())
	pages.GET("/", func(c *echo.Context) error {
		if c.Get("user") != nil {
			return c.Redirect(http.StatusSeeOther, "/account")
		}
		return c.Redirect(http.StatusSeeOther, "/login")
	})
	pages.GET("/login", h.LoginPage)
	pages.POST("/login", h.LoginSubmit)
	pages.GET("/login/totp", h.TOTPPage)
	pages.POST("/login/totp", h.TOTPSubmit)
	pages.GET("/register", h.RegisterPage)
	pages.POST("/register", h.RegisterSubmit)
	pages.GET("/logout", h.LogoutPage)
	pages.POST("/logout", h.LogoutSubmit)

	// OAuth / OIDC
	op := a.OIDC
	e.GET("/.well-known/openid-configuration", op.Discovery, oidc.PublicCORS())
	e.GET("/.well-known/jwks.json", op.JWKS, oidc.PublicCORS())
	oauthPages := e.Group("/oauth", httpx.SecurityHeaders(), httpx.HTMXPages(), httpx.NoStore(), httpx.BodyLimit(64<<10), httpx.WriteDeadline(30*time.Second), h.LoadSession())
	oauthPages.GET("/authorize", op.Authorize)
	oauthPages.POST("/authorize", op.Authorize)
	oauthPages.GET("/end_session", op.EndSessionEndpoint)
	oauthPages.POST("/end_session", op.EndSessionEndpoint)
	oauthPages.POST("/consent", op.ConsentSubmit, h.CSRF.Middleware())
	oauthPages.POST("/switch-account", op.SwitchAccount, h.CSRF.Middleware())
	oauthAPI := e.Group("", httpx.NoStore(), httpx.BodyLimit(64<<10), httpx.WriteDeadline(30*time.Second), a.OIDC.APICORS())
	for path, handler := range map[string]echo.HandlerFunc{
		"/oauth/token": op.Token, "/oauth/revoke": op.Revoke, "/oauth/introspect": op.Introspect,
		"/oauth/authorize-challenge": op.AuthorizeChallenge, "/api/v1/native/register": op.NativeRegister,
	} {
		oauthAPI.POST(path, handler)
		oauthAPI.OPTIONS(path, oidc.Preflight)
	}
	oauthAPI.GET("/oauth/userinfo", op.UserInfo)
	oauthAPI.POST("/oauth/userinfo", op.UserInfo)
	oauthAPI.OPTIONS("/oauth/userinfo", oidc.Preflight)

	// REST API
	ap := a.API
	apiGroup := e.Group("/api/v1", httpx.NoStore(), a.OIDC.APICORS())
	small := []echo.MiddlewareFunc{httpx.BodyLimit(64 << 10), httpx.WriteDeadline(30 * time.Second)}
	apiGroup.GET("/me", ap.GetMe, small...)
	apiGroup.PATCH("/me", ap.PatchMe, small...)
	apiGroup.PUT("/me/avatar", ap.PutAvatar, httpx.BodyLimit(avatar.MaxBytes+(1<<20)), httpx.WriteDeadline(60*time.Second))
	apiGroup.DELETE("/me/avatar", ap.DeleteAvatar, small...)
	apiGroup.POST("/me/password", ap.ChangePassword, small...)
	apiGroup.GET("/me/events", a.Feed.Stream)
	apiGroup.POST("/register", ap.Register, small...)
	apiGroup.GET("/registration", ap.RegistrationInfo, append(small, oidc.PublicCORS())...)
	apiGroup.GET("/users/changes", ap.Changes, small...)
	apiGroup.GET("/users", ap.Users, small...)
	apiGroup.GET("/users/:sub", ap.User, small...)
	for _, p := range []string{"/me", "/me/avatar", "/me/password", "/me/events", "/register", "/registration"} {
		apiGroup.OPTIONS(p, oidc.Preflight)
	}
	// Dynamic client registration (RFC 7591 / 7592)
	cs := a.Clients
	dcr := e.Group("/oauth/register", httpx.NoStore(), httpx.BodyLimit(64<<10), httpx.WriteDeadline(30*time.Second))
	dcr.POST("", cs.Register)
	dcr.GET("/:id", cs.ManageGet)
	dcr.PUT("/:id", cs.ManagePut)
	dcr.DELETE("/:id", cs.ManageDelete)
	// Avatars are normally served by Caddy straight from disk; this is the fallback.
	e.GET("/avatars/:key", func(c *echo.Context) error {
		f, err := a.Avatars.Open(c.Param("key"))
		if err != nil {
			return echo.ErrNotFound
		}
		defer f.Close()
		c.Response().Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		return c.Stream(http.StatusOK, "image/jpeg", f)
	})

	pt := a.Portal
	upload := e.Group("/account", httpx.SecurityHeaders(), httpx.HTMXPages(), httpx.NoStore(), httpx.BodyLimit(avatar.MaxBytes+(1<<20)), httpx.WriteDeadline(60*time.Second),
		h.LoadSession(), h.CSRF.Middleware(), h.RequireLogin())
	upload.POST("/avatar", pt.Avatar)

	dev := pages.Group("/developer", h.RequireLogin())
	dev.GET("", pt.Developer)
	dev.GET("/apps/new", pt.NewApp)
	dev.POST("/apps", pt.CreateApp)
	dev.GET("/apps/:id", pt.App)
	dev.POST("/apps/:id", pt.UpdateApp)
	dev.POST("/apps/:id/secret", pt.RotateSecret)
	dev.POST("/apps/:id/webhook-secret", pt.RotateWebhookSecret)
	dev.POST("/apps/:id/webhook-test", pt.TestWebhook)
	dev.POST("/apps/:id/delete", pt.DeleteApp)
	dev.POST("/tokens", pt.NewToken)
	dev.POST("/api-tokens", pt.CreateAPIToken)
	dev.POST("/api-tokens/:id/rotate", pt.RotateAPIToken)
	dev.POST("/api-tokens/:id/revoke", pt.RevokeAPIToken)

	// Developer API (terminals, scripts, CI) with developer API tokens.
	devAPI := e.Group("/api/v1/developer", httpx.NoStore(), httpx.BodyLimit(64<<10), httpx.WriteDeadline(30*time.Second),
		a.Tokens.Middleware(store.TokenDeveloper))
	devAPI.GET("/token", pt.DevTokenInfo)
	devAPI.POST("/token/rotate", pt.DevTokenRotate)
	devAPI.DELETE("/token", pt.DevTokenRevoke)
	appsRead, appsWrite := apitoken.Require("apps:read"), apitoken.Require("apps:write")
	devAPI.GET("/apps", pt.DevListApps, appsRead)
	devAPI.POST("/apps", pt.DevCreateApp, appsWrite)
	devAPI.GET("/apps/:id", pt.DevGetApp, appsRead)
	devAPI.PATCH("/apps/:id", pt.DevPatchApp, appsWrite)
	devAPI.DELETE("/apps/:id", pt.DevDeleteApp, appsWrite)
	devAPI.POST("/apps/:id/rotate-secret", pt.DevRotateAppSecret, appsWrite)
	devAPI.POST("/apps/:id/rotate-webhook-secret", pt.DevRotateWebhookSecret, appsWrite)
	devAPI.POST("/apps/:id/webhook-test", pt.DevTestWebhook, appsWrite)

	// Documentation and SDK distribution
	sd := &sdkdist.Handler{Dir: a.Cfg.Storage.DataDir + "/sdk", PublicURL: a.Cfg.Server.PublicURL}
	pages.GET("/docs", func(c *echo.Context) error {
		p := h.NewPage(c, "接入文档")
		p.Nav = "docs"
		p.Data["Issuer"] = a.Cfg.Issuer()
		p.Data["AdminURL"] = a.Cfg.Server.AdminURL
		return ui.Render(c, http.StatusOK, "docs", "", p)
	})
	pages.GET("/sdk", func(c *echo.Context) error {
		p := h.NewPage(c, "SDK 下载")
		p.Nav = "docs"
		p.Data["Issuer"] = a.Cfg.Issuer()
		p.Data["Artifacts"] = sd.List()
		p.Data["GoVersions"] = sd.GoVersions()
		p.Data["CLI"] = sd.CLI()
		return ui.Render(c, http.StatusOK, "sdk", "", p)
	})
	e.GET("/openapi.yaml", func(c *echo.Context) error {
		return c.Redirect(http.StatusFound, a.Assets.URL("openapi.yaml"))
	}, oidc.PublicCORS())
	e.GET("/sdk/go", sd.GoImport)
	e.GET("/sdk/go/*", sd.GoImport)
	e.GET("/goproxy/*", sd.File("goproxy"))
	for _, kind := range []string{"maven", "npm", "pypi", "nuget", "cli"} {
		e.GET("/sdk/"+kind+"/*", sd.File(kind))
		e.HEAD("/sdk/"+kind+"/*", sd.File(kind))
	}

	acct := pages.Group("/account", h.RequireLogin())
	acct.GET("/apps", pt.Apps)
	acct.POST("/apps/revoke", pt.RevokeApp)
	acct.GET("", h.AccountPage)
	acct.POST("/profile", h.ProfileSubmit)
	acct.GET("/security", h.SecurityPage)
	acct.POST("/password", h.PasswordSubmit)
	acct.GET("/password/change", h.ForcedPasswordPage)
	acct.POST("/password/change", h.ForcedPasswordSubmit)
	acct.POST("/totp/setup", h.TOTPSetup)
	acct.POST("/totp/confirm", h.TOTPConfirm)
	acct.POST("/totp/disable", h.TOTPDisable)
	acct.POST("/sessions/revoke", h.RevokeSession)
}

func (a *App) routesAdmin() {
	e := a.Admin
	e.GET("/healthz", func(c *echo.Context) error { return c.String(http.StatusOK, "ok") })
	e.GET("/static/:hash/*", a.Assets.Handler())
	e.GET("/favicon.ico", func(c *echo.Context) error {
		return c.Redirect(http.StatusMovedPermanently, a.Assets.URL("favicon.svg"))
	})
	e.GET("/robots.txt", func(c *echo.Context) error { return c.String(http.StatusOK, robotsTxt) })
	e.GET("/openapi.yaml", func(c *echo.Context) error {
		return c.Redirect(http.StatusFound, a.Assets.URL("openapi-console.yaml"))
	})
	// Prometheus metrics: only for direct loopback scrapes, never through the proxy.
	e.GET("/metrics", func(c *echo.Context) error {
		if c.Request().Header.Get("X-Forwarded-For") != "" || !strings.HasPrefix(c.Request().RemoteAddr, "127.0.0.1:") {
			return echo.ErrNotFound
		}
		c.Response().Header().Set("Content-Type", "text/plain; version=0.0.4")
		httpx.Metrics.Write(c.Response())
		return nil
	})
	ad := a.AdminH
	base := e.Group("", httpx.SecurityHeaders(), httpx.HTMXPages(), httpx.NoStore(), httpx.BodyLimit(64<<10), httpx.WriteDeadline(30*time.Second),
		ad.LoadSession(), ad.CSRF.Middleware())
	base.GET("/login", ad.LoginPage)
	base.POST("/login", ad.LoginSubmit)
	base.GET("/login/password", ad.PasswordPage)
	base.POST("/login/password", ad.PasswordSubmit)
	base.GET("/login/enroll", ad.EnrollPage)
	base.POST("/login/enroll", ad.EnrollSubmit)
	base.GET("/login/totp", ad.TOTPPage)
	base.POST("/login/totp", ad.TOTPSubmit)
	base.POST("/logout", ad.Logout)
	g := base.Group("", ad.Require())
	g.GET("/", ad.Dashboard)
	g.GET("/admins", ad.Admins)
	g.POST("/admins", ad.CreateAdminSubmit)
	g.POST("/admins/:id", ad.AdminAction)
	g.GET("/profile", ad.Profile)
	g.POST("/profile/password", ad.ChangeOwnPassword)
	g.POST("/settings/registration", ad.ToggleRegistration)
	g.GET("/users", ad.Users)
	g.GET("/users/new", ad.NewUser)
	g.POST("/users/new", ad.CreateUser)
	g.GET("/users/:sub", ad.User)
	g.POST("/users/:sub", ad.UserAction)
	g.GET("/clients", ad.ClientList)
	g.GET("/clients/new", ad.NewClient)
	g.POST("/clients/new", ad.CreateClient)
	g.GET("/clients/:id", ad.Client)
	g.POST("/clients/:id", ad.UpdateClient)
	g.POST("/clients/:id/action", ad.ClientAction)
	g.GET("/webhooks", ad.Webhooks)
	g.POST("/webhooks/redrive", ad.Redrive)
	g.GET("/settings", ad.SettingsPage)
	g.POST("/settings", ad.SaveSettings)
	g.GET("/keys", ad.KeysPage)
	g.POST("/keys/rotate", ad.RotateKeys)
	g.GET("/audit", ad.Audit)
	g.GET("/api-tokens", ad.APITokens)
	g.POST("/api-tokens", ad.CreateAPIToken)
	g.POST("/api-tokens/:id/rotate", ad.RotateAPIToken)
	g.POST("/api-tokens/:id/revoke", ad.RevokeAPIToken)

	// Console API with console API tokens. No cookies, no CSRF: bearer only.
	api := e.Group("/api/v1", httpx.NoStore(), httpx.BodyLimit(64<<10), httpx.WriteDeadline(30*time.Second),
		a.Tokens.Middleware(store.TokenConsole))
	req := apitoken.Require
	api.GET("/token", ad.APITokenInfo)
	api.POST("/token/rotate", ad.APITokenRotate)
	api.DELETE("/token", ad.APITokenRevoke)
	api.GET("/stats", ad.APIStats, req("stats:read"))
	api.GET("/users", ad.APIUsers, req("users:read"))
	api.POST("/users", ad.APICreateUser, req("users:write"))
	api.GET("/users/:sub", ad.APIUser, req("users:read"))
	api.POST("/users/:sub/:action", ad.APIUserAction, req("users:write"))
	api.DELETE("/users/:sub", ad.APIDeleteUser, req("users:write"))
	api.GET("/clients", ad.APIClients, req("clients:read"))
	api.POST("/clients", ad.APICreateClient, req("clients:write"))
	api.GET("/clients/:id", ad.APIClient, req("clients:read"))
	api.PATCH("/clients/:id", ad.APIPatchClient, req("clients:write"))
	api.POST("/clients/:id/:action", ad.APIClientAction, req("clients:write"))
	api.DELETE("/clients/:id", ad.APIDeleteClient, req("clients:write"))
	api.GET("/webhooks/dead-letters", ad.APIDeadLetters, req("clients:read"))
	api.POST("/webhooks/dead-letters/:id/redrive", ad.APIRedrive, req("clients:write"))
	api.GET("/settings", ad.APISettings, req("settings:read"))
	api.PATCH("/settings", ad.APIPatchSettings, req("settings:write"))
	api.GET("/audit", ad.APIAudit, req("audit:read"))
}

func (a *App) ready(c *echo.Context) error {
	ctx, cancel := context.WithTimeout(c.Request().Context(), 2*time.Second)
	defer cancel()
	if err := a.DB.PingContext(ctx); err != nil {
		return c.String(http.StatusServiceUnavailable, "db unavailable")
	}
	return c.String(http.StatusOK, "ready "+Version)
}

func isAPIPath(p string) bool {
	return strings.HasPrefix(p, "/oauth/") || strings.HasPrefix(p, "/api/") || strings.HasPrefix(p, "/.well-known/") || p == "/userinfo"
}

func (a *App) errorHandler(c *echo.Context, err error) {
	if r, uerr := echo.UnwrapResponse(c.Response()); uerr == nil && r.Committed {
		return
	}
	status := echo.StatusCode(err)
	msg := ""
	var he *echo.HTTPError
	if errors.As(err, &he) {
		msg = he.Message
	}
	if status == 0 {
		status = http.StatusInternalServerError
	}
	if errors.Is(err, crypto.ErrHasherBusy) {
		status, msg = http.StatusServiceUnavailable, "服务器繁忙，请稍后再试"
		c.Response().Header().Set("Retry-After", "5")
	}
	if status >= 500 && msg == "" {
		msg = "服务器内部错误，请稍后再试"
	}
	if msg == "" {
		msg = http.StatusText(status)
	}
	if c.Request().Method == http.MethodHead {
		_ = c.NoContent(status)
		return
	}
	if isAPIPath(c.Request().URL.Path) {
		code := "server_error"
		switch {
		case status == http.StatusNotFound:
			code = "not_found"
		case status == http.StatusTooManyRequests:
			code = "rate_limited"
		case status < 500:
			code = "invalid_request"
		}
		_ = c.JSON(status, map[string]string{"error": code, "error_description": msg})
		return
	}
	heading := "出错了"
	switch status {
	case http.StatusNotFound:
		heading, msg = "页面不存在", "你访问的页面不存在或已被移除。"
	case http.StatusForbidden:
		heading = "无法完成操作"
	}
	p := &ui.Page{Title: heading, Site: a.Settings.Get(), Env: a.Cfg.Server.Environment,
		Data: map[string]any{"Heading": heading, "Message": msg}, Errors: map[string]string{}, Form: map[string]string{}}
	if u, ok := c.Get("user").(*store.User); ok {
		p.User = u
		p.CSRF = a.UI.CSRF.Token(c)
	}
	if s, ok := c.Get("session").(*store.Session); ok {
		p.Session = s
	}
	c.Response().Header().Set("Cache-Control", "no-store")
	name := "error"
	if c.Echo() == a.Admin {
		name = "admin/error"
	}
	if c.Request().Header.Get("HX-Request") == "true" && c.Request().Header.Get("HX-Boosted") != "true" {
		name = "error#error_fragment"
	}
	if rerr := c.Render(status, name, p); rerr != nil {
		a.Log.Error("render error page", "err", rerr)
		_ = c.String(status, msg)
	}
}

// Run serves both listeners until ctx is cancelled.
func (a *App) Run(ctx context.Context) error {
	ls, err := httpx.Listeners(map[string]string{"public": a.Cfg.Server.PublicListen, "admin": a.Cfg.Server.AdminListen})
	if err != nil {
		return err
	}
	a.StartBackground(ctx)
	errCh := make(chan error, 2)
	grace := a.Cfg.Server.ShutdownTimeout.Duration
	go func() { errCh <- httpx.Serve(ctx, ls["public"], a.Public, grace, a.Log) }()
	go func() { errCh <- httpx.Serve(ctx, ls["admin"], a.Admin, grace, a.Log) }()
	_ = httpx.Notify("READY=1\nSTATUS=serving " + Version)
	a.Log.Info("moon-sso started", "version", Version, "public", ls["public"].Addr().String(), "admin", ls["admin"].Addr().String(), "env", a.Cfg.Server.Environment)
	var first error
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil && !errors.Is(err, http.ErrServerClosed) && first == nil {
			first = err
		}
		if i == 0 {
			_ = httpx.Notify("STOPPING=1")
		}
	}
	a.bg.Wait()
	a.DB.Close()
	return first
}

// StartBackground launches maintenance and event workers.
func (a *App) StartBackground(ctx context.Context) {
	a.goBG(func() { a.Settings.Run(ctx) })
	a.goBG(func() { a.Signing.Run(ctx) })
	a.goBG(func() { a.Seq.Run(ctx) })
	a.goBG(func() { a.BC.Run(ctx) })
	a.goBG(func() { a.Feed.RunWebhooks(ctx) })
	a.goBG(func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := a.Feed.Retain(ctx, 30*24*time.Hour); err != nil && ctx.Err() == nil {
					a.Log.Warn("event retention failed", "err", err)
				}
			}
		}
	})
	a.goBG(func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				grace := a.Cfg.Tokens.RefreshGrace.Duration
				if _, err := store.ClearGraceCopies(ctx, a.DB, time.Now().UTC().Add(-grace)); err != nil && ctx.Err() == nil {
					a.Log.Warn("clear grace copies failed", "err", err)
				}
			}
		}
	})
	a.goBG(func() { httpx.Watchdog(ctx, a.healthy) })
	a.goBG(func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				for _, l := range a.limiters {
					l.GC()
				}
				a.throttle.GC()
				a.OIDC.GC()
				a.Accounts.Throttle.GC()
				a.API.GC()
				a.AdminH.GC()
				a.Tokens.GC()
			}
		}
	})
	a.goBG(func() { a.cleanupLoop(ctx) })
}

func (a *App) goBG(f func()) {
	a.bg.Add(1)
	go func() { defer a.bg.Done(); f() }()
}

// cleanupLoop deletes expired rows in small batches to avoid long locks.
func (a *App) cleanupLoop(ctx context.Context) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		now := time.Now().UTC()
		jobs := []struct {
			q    string
			args []any
		}{
			{"DELETE FROM sso_sessions WHERE (idle_expires_at < ? OR revoked_at < ?) LIMIT 1000", []any{now.Add(-7 * 24 * time.Hour), now.Add(-7 * 24 * time.Hour)}},
			{"DELETE FROM auth_codes WHERE expires_at < ? LIMIT 1000", []any{now.Add(-time.Hour)}},
			{"DELETE FROM refresh_token_history WHERE rotated_at < ? LIMIT 5000", []any{now.Add(-14 * 24 * time.Hour)}},
			{"DELETE FROM refresh_families WHERE (idle_expires_at < ? OR revoked_at < ?) LIMIT 1000", []any{now.Add(-7 * 24 * time.Hour), now.Add(-7 * 24 * time.Hour)}},
			{"DELETE FROM username_reservations WHERE expires_at < ? LIMIT 1000", []any{now}},
			{"DELETE FROM admin_sessions WHERE abs_expires_at < ? LIMIT 1000", []any{now.Add(-30 * 24 * time.Hour)}},
			{"DELETE FROM initial_access_tokens WHERE expires_at < ? LIMIT 1000", []any{now}},
			// API tokens stay listed for 30 days after they expire or are revoked.
			{"DELETE FROM api_tokens WHERE expires_at < ? OR revoked_at < ? LIMIT 1000", []any{now.Add(-30 * 24 * time.Hour), now.Add(-30 * 24 * time.Hour)}},
			{"DELETE FROM session_clients WHERE created_at < ? LIMIT 5000", []any{now.Add(-100 * 24 * time.Hour)}},
			{"DELETE FROM audit_log WHERE at < ? LIMIT 5000", []any{now.Add(-365 * 24 * time.Hour)}},
		}
		for _, j := range jobs {
			if ctx.Err() != nil {
				return
			}
			cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			if _, err := a.DB.ExecContext(cctx, j.q, j.args...); err != nil {
				a.Log.Warn("cleanup failed", "err", err, "q", j.q)
			}
			cancel()
		}
	}
}

// UASummary turns a user agent into "Chrome · Windows" style text.
func UASummary(ua string) template.HTML {
	browser, osName := "未知浏览器", ""
	l := strings.ToLower(ua)
	switch {
	case strings.Contains(l, "moon-sso-sdk"):
		browser = "应用 SDK"
	case strings.Contains(l, "edg/"):
		browser = "Edge"
	case strings.Contains(l, "opr/") || strings.Contains(l, "opera"):
		browser = "Opera"
	case strings.Contains(l, "firefox/"):
		browser = "Firefox"
	case strings.Contains(l, "micromessenger"):
		browser = "微信"
	case strings.Contains(l, "chrome/"):
		browser = "Chrome"
	case strings.Contains(l, "safari/"):
		browser = "Safari"
	case strings.Contains(l, "okhttp"):
		browser = "Android 应用"
	}
	switch {
	case strings.Contains(l, "windows"):
		osName = "Windows"
	case strings.Contains(l, "android"):
		osName = "Android"
	case strings.Contains(l, "iphone") || strings.Contains(l, "ipad"):
		osName = "iOS"
	case strings.Contains(l, "mac os"):
		osName = "macOS"
	case strings.Contains(l, "linux"):
		osName = "Linux"
	}
	if osName == "" {
		return template.HTML(template.HTMLEscapeString(browser))
	}
	return template.HTML(template.HTMLEscapeString(browser + " · " + osName))
}

// RelaxLimitsForTests disables rate limiting; used only by the SDK testbed.
func (a *App) RelaxLimitsForTests() {
	a.OIDC.RelaxLimits()
	a.API.RelaxLimits()
	a.Tokens.RelaxLimits()
	a.UI.LoginLimiter = auth.NewLimiter(1e6, 1_000_000)
	a.UI.RegisterLimiter = auth.NewLimiter(1e6, 1_000_000)
	a.limiters = []*auth.Limiter{a.UI.LoginLimiter, a.UI.RegisterLimiter}
}

// RotateKeys publishes new signing keys that activate after keys.PrePublish.
func (a *App) RotateKeys(ctx context.Context) error {
	if err := a.Signing.Rotate(ctx); err != nil {
		return err
	}
	a.Log.Info("new signing keys published", "activate_after", keys.PrePublish.String())
	return nil
}

const robotsTxt = "User-agent: *\nDisallow: /\n"

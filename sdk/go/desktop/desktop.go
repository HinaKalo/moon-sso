// Package desktop signs users into desktop and command-line apps through
// the system browser (RFC 8252 loopback redirect), stores the session in the
// operating system's secure storage and keeps it fresh across restarts and
// multiple running instances.
//
//	app, _ := desktop.Open(ctx, desktop.Config{Issuer: "https://sso.moonl.cloud", ClientID: "ms_...", AppName: "MyTool"})
//	if !app.Session.SignedIn(ctx) {
//	    if err := app.Login(ctx); err != nil { ... }
//	}
//	go app.Session.KeepFresh(ctx)
//	go app.Session.Listen(ctx, onEvent)      // live profile updates
//	resp, _ := app.Session.HTTPClient().Get("https://api.example.com/...")
package desktop

import (
	"context"
	"errors"
	"fmt"
	"html"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	moonsso "sso.moonl.cloud/sdk/go"
)

// Config for a desktop application (a public client registered as "native").
type Config struct {
	Issuer   string
	ClientID string
	// AppName names the storage entry and lock file; keep it stable.
	AppName string
	Scopes  []string
	// DisableDPoP turns off DPoP binding (not recommended).
	DisableDPoP bool
	// Store overrides the OS secure store.
	Store moonsso.Store
	// OnSessionExpired / OnProfile are forwarded to the session.
	OnSessionExpired func()
	OnProfile        func(*moonsso.Profile)
}

// App bundles the client and the persistent session.
type App struct {
	Client  *moonsso.Client
	Session *moonsso.Session
	cfg     Config
}

// Open loads (or creates) the stored session and its DPoP key.
func Open(ctx context.Context, cfg Config) (*App, error) {
	if cfg.AppName == "" {
		return nil, errors.New("desktop: AppName is required")
	}
	store := cfg.Store
	if store == nil {
		var err error
		if store, err = NewSecureStore(cfg.AppName); err != nil {
			return nil, err
		}
	}
	var key *moonsso.DPoPKey
	if !cfg.DisableDPoP {
		if st, err := store.Load(ctx); err == nil && st != nil && st.DPoPKey != "" {
			key, _ = moonsso.ParseDPoPKey(st.DPoPKey)
		}
		if key == nil {
			var err error
			if key, err = moonsso.NewDPoPKey(); err != nil {
				return nil, err
			}
		}
	}
	client, err := moonsso.NewClient(moonsso.Config{Issuer: cfg.Issuer, ClientID: cfg.ClientID, Scopes: cfg.Scopes, DPoP: key,
		UserAgent: "desktop/" + runtime.GOOS})
	if err != nil {
		return nil, err
	}
	lockPath := filepath.Join(appDir(cfg.AppName), "moon-sso.lock")
	sess := client.NewSession(store, moonsso.SessionOptions{Locker: NewFileLock(lockPath),
		OnSessionExpired: cfg.OnSessionExpired, OnProfile: cfg.OnProfile})
	return &App{Client: client, Session: sess, cfg: cfg}, nil
}

// Login opens the system browser and completes the authorization code flow
// on a one-time loopback listener (5-minute timeout).
func (a *App) Login(ctx context.Context) error {
	tok, claims, err := LoginWithBrowser(ctx, a.Client, Options{})
	if err != nil {
		return err
	}
	return a.Session.Begin(ctx, tok, claims)
}

// LoginWithPassword signs in from the app's own form (first-party apps only).
// An *moonsso.OTPRequiredError asks for a TOTP code; finish with CompleteOTP.
func (a *App) LoginWithPassword(ctx context.Context, username, password string) error {
	tok, claims, err := a.Client.LoginWithPassword(ctx, username, password)
	if err != nil {
		return err
	}
	return a.Session.Begin(ctx, tok, claims)
}

// CompleteOTP finishes a password login that required a one-time code.
func (a *App) CompleteOTP(ctx context.Context, ch *moonsso.Challenge, code string) error {
	tok, claims, err := a.Client.CompleteOTP(ctx, ch, code)
	if err != nil {
		return err
	}
	return a.Session.Begin(ctx, tok, claims)
}

// Register creates an account from inside the app and signs it in.
func (a *App) Register(ctx context.Context, username, password, displayName string) error {
	tok, claims, err := a.Client.RegisterNative(ctx, username, password, displayName)
	if err != nil {
		return err
	}
	return a.Session.Begin(ctx, tok, claims)
}

// Logout revokes and forgets the session.
func (a *App) Logout(ctx context.Context) error { return a.Session.Logout(ctx) }

// Options for LoginWithBrowser.
type Options struct {
	Timeout time.Duration          // default 5 minutes
	Open    func(url string) error // default OpenBrowser
	Auth    moonsso.AuthOptions    // prompt, login hint …
}

const successPage = `<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>登录完成</title>
<style>body{font-family:system-ui,sans-serif;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0;background:#f6f7f9;color:#1b1f24}
main{text-align:center}h1{font-size:1.3rem}</style><main><h1>%s</h1><p>%s</p></main></html>`

// LoginWithBrowser runs the RFC 8252 loopback flow and returns tokens.
func LoginWithBrowser(ctx context.Context, c *moonsso.Client, o Options) (*moonsso.Token, moonsso.Claims, error) {
	if o.Timeout <= 0 {
		o.Timeout = 5 * time.Minute
	}
	if o.Open == nil {
		o.Open = OpenBrowser
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, err
	}
	defer ln.Close()
	redirect := fmt.Sprintf("http://127.0.0.1:%d/callback", ln.Addr().(*net.TCPAddr).Port)
	o.Auth.RedirectURL = redirect
	ar, err := c.AuthCodeURL(ctx, o.Auth)
	if err != nil {
		return nil, nil, err
	}
	type result struct {
		q url.Values
	}
	done := make(chan result, 1)
	srv := &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/callback" {
			http.NotFound(w, r)
			return
		}
		q := r.URL.Query()
		if q.Get("state") != ar.State {
			http.Error(w, "state mismatch", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if e := q.Get("error"); e != "" {
			fmt.Fprintf(w, successPage, "登录未完成", html.EscapeString(q.Get("error_description")))
		} else {
			fmt.Fprintf(w, successPage, "登录完成", "可以关闭此页面，返回应用。")
		}
		select {
		case done <- result{q}:
		default:
		}
	})}
	go func() { _ = srv.Serve(ln) }()
	defer func() {
		sctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_ = srv.Shutdown(sctx)
		cancel()
	}()
	if err := o.Open(ar.URL); err != nil {
		return nil, nil, fmt.Errorf("desktop: cannot open browser (%w); open this URL manually: %s", err, ar.URL)
	}
	timer := time.NewTimer(o.Timeout)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	case <-timer.C:
		return nil, nil, errors.New("desktop: login timed out")
	case res := <-done:
		return c.Exchange(ctx, ar, res.q)
	}
}

// OpenBrowser opens url in the user's default browser.
func OpenBrowser(u string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", u)
	case "darwin":
		cmd = exec.Command("open", u)
	default:
		cmd = exec.Command("xdg-open", u)
	}
	return cmd.Start()
}

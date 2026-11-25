// Package ui serves the public HTMX pages on sso.moonl.cloud: login,
// registration, logout and the personal account center.
package ui

import (
	"context"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v5"

	"moon-sso/server/internal/account"
	"moon-sso/server/internal/auth"
	"moon-sso/server/internal/cache"
	"moon-sso/server/internal/config"
	"moon-sso/server/internal/crypto"
	"moon-sso/server/internal/db"
	"moon-sso/server/internal/settings"
	"moon-sso/server/internal/store"
)

type Handler struct {
	Cfg       *config.Config
	DB        *db.DB
	Accounts  *account.Service
	Sessions  *auth.Sessions
	Settings  *settings.Service
	CSRF      *auth.CSRF
	Cookies   auth.Cookies
	CookieBox *crypto.Sealer
	Log       *slog.Logger

	Throttle        *auth.Throttle
	LoginLimiter    *auth.Limiter
	RegisterLimiter *auth.Limiter

	// OnLogout is called after a session is ended (back-channel logout
	// fan-out). reason is "logout" or "device_removed".
	OnLogout func(ctx context.Context, sess *store.Session, reason string)
	// ExtraAccountNav lets later phases add account-center tabs.
	Users *cache.Cache[uuid.UUID, *store.User]
}

// Page is the data every template receives.
type Page struct {
	// Admin is the signed-in console administrator (admin console only).
	Admin   *store.Admin
	Title   string
	Nav     string
	Site    settings.Values
	Env     string
	User    *store.User
	Session *store.Session
	CSRF    string
	Flash   string
	Error   string
	Errors  map[string]string
	Form    map[string]string
	Data    map[string]any
}

func (h *Handler) page(c *echo.Context, title string) *Page {
	p := &Page{Title: title, Site: h.Settings.Get(), Env: h.Cfg.Server.Environment, CSRF: h.CSRF.Token(c),
		Errors: map[string]string{}, Form: map[string]string{}, Data: map[string]any{}}
	if s, ok := c.Get("session").(*store.Session); ok {
		p.Session = s
	}
	if u, ok := c.Get("user").(*store.User); ok {
		p.User = u
	}
	return p
}

// render writes a full page, or only the named block for HTMX requests.
func render(c *echo.Context, status int, page, block string, p *Page) error {
	if block != "" && isHTMX(c) {
		return c.Render(status, page+"#"+block, p)
	}
	return c.Render(status, page, p)
}

func isHTMX(c *echo.Context) bool { return c.Request().Header.Get("HX-Request") == "true" }

// redirect performs a browser redirect that also works for HTMX requests.
func redirect(c *echo.Context, to string) error {
	if isHTMX(c) {
		c.Response().Header().Set("HX-Redirect", to)
		return c.NoContent(http.StatusOK)
	}
	return c.Redirect(http.StatusSeeOther, to)
}

// SafeNext accepts only same-origin relative paths for post-login redirects.
func SafeNext(next string) string {
	if next == "" || len(next) > 4096 || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.HasPrefix(next, "/\\") {
		return ""
	}
	u, err := url.Parse(next)
	if err != nil || u.IsAbs() || u.Host != "" {
		return ""
	}
	return next
}

// ---- session middleware ----

func (h *Handler) currentUser(ctx context.Context, id uuid.UUID) (*store.User, error) {
	if u, ok := h.Users.Get(id); ok {
		return u, nil
	}
	u, err := store.GetUser(ctx, h.DB, id)
	if err != nil {
		return nil, err
	}
	h.Users.Set(id, u)
	return u, nil
}

// LoadSession attaches the session and user (if any) to the context.
func (h *Handler) LoadSession() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			ck, err := c.Cookie(h.Cookies.Name(auth.SessionCookie))
			if err != nil || ck.Value == "" {
				return next(c)
			}
			sess, err := h.Sessions.Lookup(c.Request().Context(), ck.Value, c.RealIP())
			if err != nil {
				if !errors.Is(err, auth.ErrNoSession) {
					return err
				}
				c.SetCookie(h.Cookies.Clear(auth.SessionCookie))
				return next(c)
			}
			u, err := h.currentUser(c.Request().Context(), sess.UserID)
			if errors.Is(err, store.ErrNotFound) {
				return next(c)
			}
			if err != nil {
				return err
			}
			if !u.IsActive() {
				_ = h.Sessions.Revoke(c.Request().Context(), h.DB, sess.SID)
				c.SetCookie(h.Cookies.Clear(auth.SessionCookie))
				return next(c)
			}
			c.Set("session", sess)
			c.Set("user", u)
			return next(c)
		}
	}
}

// RequireLogin redirects anonymous visitors to the login page and users with
// an administrator-issued temporary password to the forced change page.
func (h *Handler) RequireLogin() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			u, ok := c.Get("user").(*store.User)
			if !ok {
				return redirect(c, "/login?next="+url.QueryEscape(c.Request().URL.RequestURI()))
			}
			if u.MustChangePassword && c.Request().URL.Path != "/account/password/change" {
				return redirect(c, "/account/password/change?next="+url.QueryEscape(c.Request().URL.RequestURI()))
			}
			return next(c)
		}
	}
}

func userOf(c *echo.Context) *store.User       { u, _ := c.Get("user").(*store.User); return u }
func sessionOf(c *echo.Context) *store.Session { s, _ := c.Get("session").(*store.Session); return s }

// InvalidateUser drops cached copies of a user after a change.
func (h *Handler) InvalidateUser(id uuid.UUID) { h.Users.Delete(id) }

// StartSession creates a session, sets the cookie and revokes a previous one.
func (h *Handler) StartSession(c *echo.Context, u *store.User, amr []string) (*store.Session, error) {
	ctx := c.Request().Context()
	if old := sessionOf(c); old != nil {
		_ = h.Sessions.Revoke(ctx, h.DB, old.SID)
	}
	tok, sess, err := h.Sessions.Create(ctx, u.ID, amr, c.RealIP(), c.Request().UserAgent())
	if err != nil {
		return nil, err
	}
	c.SetCookie(h.Cookies.New(auth.SessionCookie, tok, sess.AbsExpiresAt))
	c.Set("session", sess)
	c.Set("user", u)
	return sess, nil
}

// fieldErrors maps service errors onto the page.
func fieldErrors(p *Page, err error) bool {
	var fe *account.FieldError
	if errors.As(err, &fe) {
		p.Errors[fe.Field] = fe.Msg
		return true
	}
	switch {
	case errors.Is(err, crypto.ErrHasherBusy):
		p.Error = "服务器繁忙，请稍后再试"
		return true
	case errors.Is(err, account.ErrRegistrationClosed):
		p.Error = "暂未开放注册"
		return true
	case errors.Is(err, account.ErrBadCredentials), errors.Is(err, account.ErrDisabled):
		p.Error = err.Error()
		return true
	}
	return false
}

func formValues(c *echo.Context, keys ...string) map[string]string {
	m := map[string]string{}
	for _, k := range keys {
		m[k] = c.FormValue(k)
	}
	return m
}

func secondsText(d time.Duration) string {
	s := int(d.Seconds()) + 1
	if s >= 60 {
		return itoa(s/60) + " 分钟"
	}
	return itoa(s) + " 秒"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// TemplateURL marks a data: URI generated by the server as safe for img src.
func TemplateURL(s string) template.URL { return template.URL(s) }

// templateURL marks a data: URI generated by us as safe for img src.
func templateURL(s string) template.URL { return template.URL(s) }

// NewPage exposes the common page data to other packages (OIDC pages).
func (h *Handler) NewPage(c *echo.Context, title string) *Page { return h.page(c, title) }

// Render writes a page or, for HTMX requests, one block of it.
func Render(c *echo.Context, status int, page, block string, p *Page) error {
	return render(c, status, page, block, p)
}

// Redirect performs an HTMX-aware redirect.
func Redirect(c *echo.Context, to string) error { return redirect(c, to) }

// UserOf and SessionOf return the authenticated user and session, if any.
func UserOf(c *echo.Context) *store.User       { return userOf(c) }
func SessionOf(c *echo.Context) *store.Session { return sessionOf(c) }

// Audit records an action by the current user.
func (h *Handler) Audit(c *echo.Context, u *store.User, action string, meta map[string]any) {
	h.audit(c, u, action, meta)
}

// CSRFValid checks the CSRF token of a request outside the CSRF middleware.
func (h *Handler) CSRFValid(c *echo.Context) bool { return h.CSRF.Valid(c) }

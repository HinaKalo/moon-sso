// Package admin serves the super-administrator console on sso-admin.moonl.cloud.
//
// The console is deliberately independent of the SSO it manages:
// administrators are separate accounts (admin_accounts) with their own login,
// mandatory TOTP and their own sessions and cookies. They are not SSO users,
// cannot sign in to the SSO or any application, and SSO users cannot sign in
// here.
package admin

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v5"
	"rsc.io/qr"

	"moon-sso/server/internal/account"
	"moon-sso/server/internal/apitoken"
	"moon-sso/server/internal/auth"
	"moon-sso/server/internal/cache"
	"moon-sso/server/internal/clients"
	"moon-sso/server/internal/config"
	"moon-sso/server/internal/crypto"
	"moon-sso/server/internal/db"
	"moon-sso/server/internal/feed"
	"moon-sso/server/internal/keys"
	"moon-sso/server/internal/oidc"
	"moon-sso/server/internal/settings"
	"moon-sso/server/internal/store"
	"moon-sso/server/internal/ui"
)

type Handler struct {
	Cfg      *config.Config
	DB       *db.DB
	OIDC     *oidc.Provider
	Keys     *keys.Manager
	Accounts *account.Service
	Clients  *clients.Service
	Feed     *feed.Feed
	Settings *settings.Service
	Sessions *auth.Sessions // SSO user sessions (managed, never used to log in here)
	Cookies  auth.Cookies
	Box      *crypto.Sealer
	AtRest   *crypto.Sealer
	Hasher   *crypto.Hasher
	CSRF     *auth.CSRF
	Tokens   *apitoken.Service
	Log      *slog.Logger

	sessions *cache.Cache[string, *store.AdminSession]
	admins   *cache.Cache[uuid.UUID, *store.Admin]
	throttle *auth.Throttle
	limiter  *auth.Limiter
}

func New(h *Handler) *Handler {
	h.sessions = cache.New[string, *store.AdminSession](1000, 10*time.Second)
	h.admins = cache.New[uuid.UUID, *store.Admin](1000, 10*time.Second)
	h.throttle = auth.NewThrottle()
	h.limiter = auth.NewLimiter(20, 10)
	return h
}

// GC trims in-memory limiters.
func (h *Handler) GC() { h.throttle.GC(); h.limiter.GC() }

const (
	sessionCookie  = "admin_session"
	pendingCookie  = "admin_pending"
	sessionIdle    = 30 * time.Minute
	sessionAbs     = 12 * time.Hour
	adminMinPwdLen = 12
)

// pending carries a half-finished login between steps.
type pending struct {
	AdminID uuid.UUID `json:"a"`
	Stage   string    `json:"s"` // password | enroll | totp
	Secret  string    `json:"t,omitempty"`
	Exp     int64     `json:"e"`
}

func (h *Handler) sealPending(c *echo.Context, p pending) {
	p.Exp = time.Now().Add(10 * time.Minute).Unix()
	b, _ := json.Marshal(p)
	c.SetCookie(h.Cookies.New(pendingCookie, crypto.B64(h.Box.Seal(b, []byte(pendingCookie))), time.Now().Add(10*time.Minute)))
}

func (h *Handler) openPending(c *echo.Context) (*pending, bool) {
	ck, err := c.Cookie(h.Cookies.Name(pendingCookie))
	if err != nil || len(ck.Value) > 2048 {
		return nil, false
	}
	raw, err := crypto.UnB64(ck.Value)
	if err != nil {
		return nil, false
	}
	pt, err := h.Box.Open(raw, []byte(pendingCookie))
	if err != nil {
		return nil, false
	}
	var p pending
	if json.Unmarshal(pt, &p) != nil || time.Now().Unix() > p.Exp {
		return nil, false
	}
	return &p, true
}

func totpAAD(id uuid.UUID) []byte { return append([]byte("admin-totp:"), id[:]...) }

// ---- page helpers ----

func (h *Handler) authPage(c *echo.Context, title string) *ui.Page {
	return &ui.Page{Title: title, Site: h.Settings.Get(), Env: h.Cfg.Server.Environment, CSRF: h.CSRF.Token(c),
		Errors: map[string]string{}, Form: map[string]string{}, Data: map[string]any{}}
}

func renderAuth(c *echo.Context, status int, page string, p *ui.Page) error {
	block := "admin_auth"
	if c.Request().Header.Get("HX-Request") == "true" && c.Request().Header.Get("HX-Boosted") != "true" {
		block = "auth_form"
	}
	return c.Render(status, "admin/"+page+"#"+block, p)
}

func toLogin(c *echo.Context) error { return ui.Redirect(c, "/login") }

// ---- login steps ----

func (h *Handler) LoginPage(c *echo.Context) error {
	if _, ok := c.Get("admin").(*store.Admin); ok {
		return c.Redirect(http.StatusSeeOther, "/")
	}
	p := h.authPage(c, "管理员登录")
	if c.QueryParam("out") == "1" {
		p.Flash = "已退出控制台"
	}
	return renderAuth(c, http.StatusOK, "login", p)
}

func (h *Handler) LoginSubmit(c *echo.Context) error {
	ctx := c.Request().Context()
	p := h.authPage(c, "管理员登录")
	username := account.NormalizeUsername(c.FormValue("username"))
	password := c.FormValue("password")
	p.Form["username"] = c.FormValue("username")
	ip := c.RealIP()
	fail := func(status int, msg string) error {
		p.Error = msg
		return renderAuth(c, status, "login", p)
	}
	if ok, _ := h.limiter.Allow(auth.IPKey(ip)); !ok {
		return fail(http.StatusTooManyRequests, "尝试过于频繁，请稍后再试")
	}
	ukey := "admin:" + username
	if d := h.throttle.Delay(ukey); d > 0 {
		return fail(http.StatusTooManyRequests, "登录失败次数过多，请稍后再试")
	}
	a, err := store.GetAdminByUsername(ctx, h.DB, username)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	encoded := ""
	if a != nil {
		encoded = a.PasswordHash
	}
	ok, rehash, err := h.Hasher.Verify(ctx, password, encoded)
	if err != nil {
		if errors.Is(err, crypto.ErrHasherBusy) {
			return fail(http.StatusServiceUnavailable, "服务器繁忙，请稍后再试")
		}
		return err
	}
	if !ok || a == nil || !a.IsActive() {
		h.throttle.Fail(ukey)
		h.auditAs(c, username, "admin.login_failed", "admin", username, nil)
		return fail(http.StatusUnauthorized, "用户名或密码错误")
	}
	if rehash {
		if hsh, err := h.Hasher.Hash(ctx, password); err == nil {
			a.PasswordHash = hsh
			a.UpdatedAt = time.Now().UTC()
			_ = store.UpdateAdmin(ctx, h.DB, a)
		}
	}
	return h.nextStage(c, a)
}

// nextStage routes a password-verified admin to the next required step.
func (h *Handler) nextStage(c *echo.Context, a *store.Admin) error {
	switch {
	case a.MustChangePassword:
		h.sealPending(c, pending{AdminID: a.ID, Stage: "password"})
		return ui.Redirect(c, "/login/password")
	case !a.HasTOTP():
		h.sealPending(c, pending{AdminID: a.ID, Stage: "enroll", Secret: crypto.NewTOTPSecret()})
		return ui.Redirect(c, "/login/enroll")
	default:
		h.sealPending(c, pending{AdminID: a.ID, Stage: "totp"})
		return ui.Redirect(c, "/login/totp")
	}
}

func (h *Handler) stageAdmin(c *echo.Context, stage string) (*pending, *store.Admin, bool) {
	pd, ok := h.openPending(c)
	if !ok || pd.Stage != stage {
		return nil, nil, false
	}
	a, err := store.GetAdmin(c.Request().Context(), h.DB, pd.AdminID)
	if err != nil || !a.IsActive() {
		return nil, nil, false
	}
	return pd, a, true
}

func (h *Handler) PasswordPage(c *echo.Context) error {
	if _, _, ok := h.stageAdmin(c, "password"); !ok {
		return toLogin(c)
	}
	return renderAuth(c, http.StatusOK, "login_password", h.authPage(c, "设置新密码"))
}

func (h *Handler) PasswordSubmit(c *echo.Context) error {
	_, a, ok := h.stageAdmin(c, "password")
	if !ok {
		return toLogin(c)
	}
	p := h.authPage(c, "设置新密码")
	pw, pw2 := c.FormValue("password"), c.FormValue("password_confirm")
	if pw != pw2 {
		p.Errors["password_confirm"] = "两次输入的密码不一致"
		return renderAuth(c, http.StatusUnprocessableEntity, "login_password", p)
	}
	if err := h.setPassword(c.Request().Context(), a, pw); err != nil {
		var fe *account.FieldError
		if errors.As(err, &fe) {
			p.Errors["password"] = fe.Msg
			return renderAuth(c, http.StatusUnprocessableEntity, "login_password", p)
		}
		return err
	}
	h.auditAs(c, a.Username, "admin.password_changed", "admin", a.Username, nil)
	return h.nextStage(c, a)
}

func (h *Handler) setPassword(ctx context.Context, a *store.Admin, pw string) error {
	if err := account.ValidatePassword(pw, a.Username, max(adminMinPwdLen, h.Settings.Get().PasswordMinLength)); err != nil {
		return err
	}
	if ok, _, _ := h.Hasher.Verify(ctx, pw, a.PasswordHash); ok {
		return &account.FieldError{Field: "password", Msg: "新密码不能与当前密码相同"}
	}
	hash, err := h.Hasher.Hash(ctx, pw)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	a.PasswordHash, a.PasswordChangedAt, a.MustChangePassword, a.UpdatedAt = hash, now, false, now
	if err := store.UpdateAdmin(ctx, h.DB, a); err != nil {
		return err
	}
	h.admins.Delete(a.ID)
	return nil
}

func qrDataURI(text string) string {
	code, err := qr.Encode(text, qr.M)
	if err != nil {
		return ""
	}
	code.Scale = 6
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(code.PNG())
}

func groupSecret(s string) string {
	var parts []string
	for i := 0; i < len(s); i += 4 {
		parts = append(parts, s[i:min(i+4, len(s))])
	}
	return strings.Join(parts, " ")
}

func (h *Handler) enrollPage(c *echo.Context, a *store.Admin, pd *pending) *ui.Page {
	p := h.authPage(c, "绑定身份验证器")
	issuer := h.Settings.Get().SiteName + " 控制台"
	p.Data["QR"] = ui.TemplateURL(qrDataURI(crypto.TOTPURI(issuer, a.Username, pd.Secret)))
	p.Data["Secret"] = groupSecret(pd.Secret)
	return p
}

func (h *Handler) EnrollPage(c *echo.Context) error {
	pd, a, ok := h.stageAdmin(c, "enroll")
	if !ok {
		return toLogin(c)
	}
	return renderAuth(c, http.StatusOK, "login_enroll", h.enrollPage(c, a, pd))
}

func (h *Handler) EnrollSubmit(c *echo.Context) error {
	ctx := c.Request().Context()
	pd, a, ok := h.stageAdmin(c, "enroll")
	if !ok {
		return toLogin(c)
	}
	step, valid := crypto.VerifyTOTP(pd.Secret, c.FormValue("code"), time.Now(), 0)
	if !valid {
		p := h.enrollPage(c, a, pd)
		p.Errors["code"] = "验证码不正确，请确认手机时间准确后重试"
		return renderAuth(c, http.StatusUnprocessableEntity, "login_enroll", p)
	}
	a.TOTPSecretEnc = h.AtRest.Seal([]byte(pd.Secret), totpAAD(a.ID))
	a.TOTPLastStep, a.UpdatedAt = step, time.Now().UTC()
	if err := store.UpdateAdmin(ctx, h.DB, a); err != nil {
		return err
	}
	h.auditAs(c, a.Username, "admin.totp_enrolled", "admin", a.Username, nil)
	return h.startSession(c, a)
}

func (h *Handler) TOTPPage(c *echo.Context) error {
	if _, _, ok := h.stageAdmin(c, "totp"); !ok {
		return toLogin(c)
	}
	return renderAuth(c, http.StatusOK, "login_totp", h.authPage(c, "两步验证"))
}

func (h *Handler) TOTPSubmit(c *echo.Context) error {
	ctx := c.Request().Context()
	_, a, ok := h.stageAdmin(c, "totp")
	if !ok {
		return toLogin(c)
	}
	p := h.authPage(c, "两步验证")
	key := "admin-otp:" + a.ID.String()
	if d := h.throttle.Delay(key); d > 0 {
		p.Error = "尝试过于频繁，请稍后再试"
		return renderAuth(c, http.StatusTooManyRequests, "login_totp", p)
	}
	secret, err := h.AtRest.Open(a.TOTPSecretEnc, totpAAD(a.ID))
	if err != nil {
		return err
	}
	step, valid := crypto.VerifyTOTP(string(secret), c.FormValue("code"), time.Now(), a.TOTPLastStep)
	if valid {
		valid, err = store.AdvanceAdminTOTP(ctx, h.DB, a.ID, step)
		if err != nil {
			return err
		}
	}
	if !valid {
		h.throttle.Fail(key)
		p.Errors["code"] = "验证码不正确或已使用过"
		return renderAuth(c, http.StatusUnauthorized, "login_totp", p)
	}
	h.throttle.Success(key)
	h.throttle.Success("admin:" + a.UsernameNorm)
	return h.startSession(c, a)
}

func (h *Handler) startSession(c *echo.Context, a *store.Admin) error {
	ctx := c.Request().Context()
	tok := crypto.RandomToken(32)
	now := time.Now().UTC()
	s := &store.AdminSession{ID: crypto.SHA256(tok), AdminID: a.ID, CreatedAt: now, LastSeenAt: now,
		IdleExpiresAt: now.Add(sessionIdle), AbsExpiresAt: now.Add(sessionAbs), IP: c.RealIP(), UserAgent: truncate(c.Request().UserAgent(), 255)}
	if err := store.InsertAdminSession(ctx, h.DB, s); err != nil {
		return err
	}
	a.LastLoginAt, a.LastLoginIP, a.UpdatedAt = &now, c.RealIP(), now
	_ = store.UpdateAdmin(ctx, h.DB, a)
	h.admins.Delete(a.ID)
	c.SetCookie(h.Cookies.Clear(pendingCookie))
	// Session cookie: no Expires, so it dies with the browser as well.
	c.SetCookie(h.Cookies.New(sessionCookie, tok, time.Time{}))
	h.auditAs(c, a.Username, "admin.login", "admin", a.Username, nil)
	return ui.Redirect(c, "/")
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// Logout ends the console session.
func (h *Handler) Logout(c *echo.Context) error {
	if ck, err := c.Cookie(h.Cookies.Name(sessionCookie)); err == nil && ck.Value != "" {
		id := crypto.SHA256(ck.Value)
		_ = store.RevokeAdminSession(c.Request().Context(), h.DB, id, time.Now().UTC())
		h.sessions.Delete(hex.EncodeToString(id))
	}
	if a, ok := c.Get("admin").(*store.Admin); ok {
		h.auditAs(c, a.Username, "admin.logout", "admin", a.Username, nil)
	}
	c.SetCookie(h.Cookies.Clear(sessionCookie))
	return ui.Redirect(c, "/login?out=1")
}

// LoadSession attaches the admin (if any) without requiring one.
func (h *Handler) LoadSession() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			ck, err := c.Cookie(h.Cookies.Name(sessionCookie))
			if err != nil || ck.Value == "" || len(ck.Value) > 100 {
				return next(c)
			}
			ctx := c.Request().Context()
			id := crypto.SHA256(ck.Value)
			key := hex.EncodeToString(id)
			now := time.Now().UTC()
			s, ok := h.sessions.Get(key)
			if !ok {
				s, err = store.GetAdminSession(ctx, h.DB, id)
				if err != nil {
					c.SetCookie(h.Cookies.Clear(sessionCookie))
					return next(c)
				}
				h.sessions.Set(key, s)
			}
			if !s.Valid(now) {
				c.SetCookie(h.Cookies.Clear(sessionCookie))
				return next(c)
			}
			a, ok := h.admins.Get(s.AdminID)
			if !ok {
				if a, err = store.GetAdmin(ctx, h.DB, s.AdminID); err != nil {
					return next(c)
				}
				h.admins.Set(a.ID, a)
			}
			if !a.IsActive() || !a.HasTOTP() || a.MustChangePassword {
				return next(c)
			}
			if now.Sub(s.LastSeenAt) > time.Minute {
				if err := store.TouchAdminSession(ctx, h.DB, id, now, now.Add(sessionIdle), c.RealIP()); err == nil {
					cp := *s
					cp.LastSeenAt, cp.IdleExpiresAt = now, minTime(now.Add(sessionIdle), s.AbsExpiresAt)
					h.sessions.Set(key, &cp)
				}
			}
			c.Set("admin", a)
			c.Set("admin_session", id)
			return next(c)
		}
	}
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// Require sends anonymous requests to the console login.
func (h *Handler) Require() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			if _, ok := c.Get("admin").(*store.Admin); !ok {
				return toLogin(c)
			}
			return next(c)
		}
	}
}

func adminOf(c *echo.Context) *store.Admin { a, _ := c.Get("admin").(*store.Admin); return a }

func (h *Handler) actor(c *echo.Context) account.Actor {
	return account.Actor{IP: c.RealIP(), Admin: true, AdminName: adminOf(c).Username}
}

func (h *Handler) auditAs(c *echo.Context, adminName, action, ttype, tid string, meta map[string]any) {
	_ = store.InsertAudit(c.Request().Context(), h.DB, &store.AuditEntry{At: time.Now().UTC(), ActorAdmin: adminName,
		Action: action, TargetType: ttype, TargetID: tid, IP: c.RealIP(), Meta: meta})
}

// ---- administrator accounts (also used by the CLI) ----

// CreateAdmin adds a console administrator. With an empty password a
// temporary one is generated and returned; the admin must change it and bind
// TOTP at first login.
func CreateAdmin(ctx context.Context, d *db.DB, hasher *crypto.Hasher, username, displayName, password string) (*store.Admin, string, error) {
	username = strings.TrimSpace(username)
	if err := account.ValidateUsername(username); err != nil {
		var fe *account.FieldError
		// Reserved names are fine for administrators (the namespace is separate).
		if !errors.As(err, &fe) || !strings.Contains(fe.Msg, "保留") {
			return nil, "", err
		}
	}
	generated := password == ""
	if generated {
		password = "Tmp-" + crypto.RandomToken(12)
	} else if err := account.ValidatePassword(password, username, adminMinPwdLen); err != nil {
		return nil, "", err
	}
	hash, err := hasher.Hash(ctx, password)
	if err != nil {
		return nil, "", err
	}
	id, _ := uuid.NewV7()
	now := time.Now().UTC()
	a := &store.Admin{ID: id, Username: username, UsernameNorm: account.NormalizeUsername(username), DisplayName: strings.TrimSpace(displayName),
		PasswordHash: hash, PasswordChangedAt: now, MustChangePassword: generated, Status: store.UserActive, CreatedAt: now, UpdatedAt: now}
	if err := store.InsertAdmin(ctx, d, a); err != nil {
		if db.IsDuplicate(err) {
			return nil, "", &account.FieldError{Field: "username", Msg: "该管理员用户名已存在"}
		}
		return nil, "", err
	}
	if !generated {
		password = ""
	}
	return a, password, nil
}

// ResetAdmin issues a new temporary password, clears TOTP and ends sessions
// (break-glass recovery; also exposed on the CLI).
func ResetAdmin(ctx context.Context, d *db.DB, hasher *crypto.Hasher, a *store.Admin, clearTOTP bool) (string, error) {
	temp := "Tmp-" + crypto.RandomToken(12)
	hash, err := hasher.Hash(ctx, temp)
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	a.PasswordHash, a.PasswordChangedAt, a.MustChangePassword, a.UpdatedAt = hash, now, true, now
	if clearTOTP {
		a.TOTPSecretEnc, a.TOTPLastStep = nil, 0
	}
	err = d.Tx(ctx, sql.LevelReadCommitted, func(tx *sql.Tx) error {
		if err := store.UpdateAdmin(ctx, tx, a); err != nil {
			return err
		}
		if _, err := store.RevokeOwnerAPITokens(ctx, tx, store.TokenConsole, a.ID, "admin_reset", now); err != nil {
			return err
		}
		return store.RevokeAdminSessions(ctx, tx, a.ID, nil, now)
	})
	return temp, err
}

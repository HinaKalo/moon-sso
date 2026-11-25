package ui

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v5"

	"moon-sso/server/internal/account"
	"moon-sso/server/internal/auth"
	"moon-sso/server/internal/crypto"
	"moon-sso/server/internal/store"
)

const mfaCookie = "mfa"

type pendingMFA struct {
	UserID uuid.UUID `json:"u"`
	Exp    int64     `json:"e"`
	Next   string    `json:"n"`
	// Stepup is set when an existing session only needs a second factor.
	Stepup bool `json:"s,omitempty"`
}

func (h *Handler) sealCookie(name string, v any, ttl time.Duration) *http.Cookie {
	b, _ := json.Marshal(v)
	sealed := h.CookieBox.Seal(b, []byte(name))
	return h.Cookies.New(name, crypto.B64(sealed), time.Now().Add(ttl))
}

func (h *Handler) openCookie(c *echo.Context, name string, v any) bool {
	ck, err := c.Cookie(h.Cookies.Name(name))
	if err != nil || ck.Value == "" || len(ck.Value) > 2048 {
		return false
	}
	raw, err := crypto.UnB64(ck.Value)
	if err != nil {
		return false
	}
	pt, err := h.CookieBox.Open(raw, []byte(name))
	if err != nil {
		return false
	}
	return json.Unmarshal(pt, v) == nil
}

func (h *Handler) LoginPage(c *echo.Context) error {
	next := SafeNext(c.QueryParam("next"))
	if u := userOf(c); u != nil && c.QueryParam("prompt") != "login" {
		if next == "" {
			next = "/account"
		}
		return c.Redirect(http.StatusSeeOther, next)
	}
	p := h.page(c, "登录")
	p.Form["next"] = next
	p.Form["username"] = c.QueryParam("username")
	if c.QueryParam("logged_out") == "1" {
		p.Flash = "你已安全退出"
	}
	if c.QueryParam("registered") == "1" {
		p.Flash = "注册成功，请登录"
	}
	return render(c, http.StatusOK, "login", "", p)
}

func (h *Handler) LoginSubmit(c *echo.Context) error {
	ctx := c.Request().Context()
	p := h.page(c, "登录")
	p.Form = formValues(c, "username", "next")
	next := SafeNext(p.Form["next"])
	username := account.NormalizeUsername(p.Form["username"])
	password := c.FormValue("password")
	ip := c.RealIP()

	fail := func(msg string, status int) error {
		p.Error = msg
		return render(c, status, "login", "login_form", p)
	}
	if username == "" || password == "" {
		return fail("请输入用户名和密码", http.StatusUnprocessableEntity)
	}
	if ok, wait := h.LoginLimiter.Allow(auth.IPKey(ip)); !ok {
		return fail("尝试过于频繁，请 "+secondsText(wait)+"后再试", http.StatusTooManyRequests)
	}
	ukey, ipkey := "u:"+username+"|"+auth.IPKey(ip), "u:"+username
	if d := max(h.Throttle.Delay(ukey), h.Throttle.Delay(ipkey)/4); d > 0 {
		return fail("登录失败次数过多，请 "+secondsText(d)+"后再试", http.StatusTooManyRequests)
	}
	u, err := h.Accounts.Authenticate(ctx, username, password)
	if err != nil {
		if errors.Is(err, account.ErrBadCredentials) {
			h.Throttle.Fail(ukey)
			h.Throttle.Fail(ipkey)
		}
		if fieldErrors(p, err) {
			return render(c, http.StatusUnauthorized, "login", "login_form", p)
		}
		return err
	}
	h.Throttle.Success(ukey)
	h.Throttle.Success(ipkey)
	if u.HasTOTP() {
		c.SetCookie(h.sealCookie(mfaCookie, pendingMFA{UserID: u.ID, Exp: time.Now().Add(5 * time.Minute).Unix(), Next: next}, 5*time.Minute))
		return redirect(c, "/login/totp")
	}
	if _, err := h.StartSession(c, u, []string{"pwd"}); err != nil {
		return err
	}
	h.audit(c, u, "user.login", map[string]any{"amr": "pwd"})
	if next == "" {
		next = "/account"
	}
	return redirect(c, next)
}

func (h *Handler) TOTPPage(c *echo.Context) error {
	var pm pendingMFA
	if !h.openCookie(c, mfaCookie, &pm) || time.Now().Unix() > pm.Exp {
		return c.Redirect(http.StatusSeeOther, "/login")
	}
	p := h.page(c, "两步验证")
	return render(c, http.StatusOK, "login_totp", "", p)
}

func (h *Handler) TOTPSubmit(c *echo.Context) error {
	ctx := c.Request().Context()
	var pm pendingMFA
	if !h.openCookie(c, mfaCookie, &pm) || time.Now().Unix() > pm.Exp {
		return redirect(c, "/login")
	}
	p := h.page(c, "两步验证")
	key := "totp:" + pm.UserID.String()
	if d := h.Throttle.Delay(key); d > 0 {
		p.Error = "尝试过于频繁，请 " + secondsText(d) + "后再试"
		return render(c, http.StatusTooManyRequests, "login_totp", "totp_form", p)
	}
	u, err := store.GetUser(ctx, h.DB, pm.UserID)
	if err != nil {
		return redirect(c, "/login")
	}
	if !u.IsActive() {
		return redirect(c, "/login")
	}
	if err := h.Accounts.VerifyTOTP(ctx, u, c.FormValue("code")); err != nil {
		h.Throttle.Fail(key)
		if fieldErrors(p, err) {
			return render(c, http.StatusUnauthorized, "login_totp", "totp_form", p)
		}
		return err
	}
	h.Throttle.Success(key)
	c.SetCookie(h.Cookies.Clear(mfaCookie))
	next := SafeNext(pm.Next)
	if next == "" {
		next = "/account"
	}
	if pm.Stepup {
		sess := sessionOf(c)
		if sess == nil || sess.UserID != u.ID {
			return redirect(c, "/login?next="+url.QueryEscape(next))
		}
		if _, err := h.Sessions.StepUp(ctx, sess, "otp"); err != nil {
			return err
		}
		h.audit(c, u, "user.stepup", map[string]any{"amr": "otp"})
		return redirect(c, next)
	}
	if _, err := h.StartSession(c, u, []string{"pwd", "otp"}); err != nil {
		return err
	}
	h.audit(c, u, "user.login", map[string]any{"amr": "pwd otp"})
	return redirect(c, next)
}

// BeginStepUp sends a logged-in user to the TOTP page to add "otp" to the session.
func (h *Handler) BeginStepUp(c *echo.Context, u *store.User, next string) error {
	c.SetCookie(h.sealCookie(mfaCookie, pendingMFA{UserID: u.ID, Exp: time.Now().Add(5 * time.Minute).Unix(), Next: next, Stepup: true}, 5*time.Minute))
	return redirect(c, "/login/totp")
}

func (h *Handler) RegisterPage(c *echo.Context) error {
	p := h.page(c, "注册")
	p.Form["next"] = SafeNext(c.QueryParam("next"))
	return render(c, http.StatusOK, "register", "", p)
}

func (h *Handler) RegisterSubmit(c *echo.Context) error {
	p := h.page(c, "注册")
	p.Form = formValues(c, "username", "display_name", "next")
	if !p.Site.RegistrationOpen {
		p.Error = "暂未开放注册"
		return render(c, http.StatusForbidden, "register", "register_form", p)
	}
	if ok, wait := h.RegisterLimiter.Allow(auth.IPKey(c.RealIP())); !ok {
		p.Error = "注册过于频繁，请 " + secondsText(wait) + "后再试"
		return render(c, http.StatusTooManyRequests, "register", "register_form", p)
	}
	pw, pw2 := c.FormValue("password"), c.FormValue("password_confirm")
	if pw != pw2 {
		p.Errors["password_confirm"] = "两次输入的密码不一致"
		return render(c, http.StatusUnprocessableEntity, "register", "register_form", p)
	}
	u, err := h.Accounts.Register(c.Request().Context(), account.RegisterInput{
		Username: p.Form["username"], Password: pw, DisplayName: p.Form["display_name"], Via: "web",
		Actor: account.Actor{IP: c.RealIP()},
	})
	if err != nil {
		if fieldErrors(p, err) {
			return render(c, http.StatusUnprocessableEntity, "register", "register_form", p)
		}
		return err
	}
	if _, err := h.StartSession(c, u, []string{"pwd"}); err != nil {
		return err
	}
	next := SafeNext(p.Form["next"])
	if next == "" {
		next = "/account?welcome=1"
	}
	return redirect(c, next)
}

func (h *Handler) LogoutPage(c *echo.Context) error {
	if userOf(c) == nil {
		return c.Redirect(http.StatusSeeOther, "/login")
	}
	p := h.page(c, "退出登录")
	p.Form["next"] = SafeNext(c.QueryParam("next"))
	return render(c, http.StatusOK, "logout", "", p)
}

func (h *Handler) LogoutSubmit(c *echo.Context) error {
	if sess := sessionOf(c); sess != nil {
		ctx := c.Request().Context()
		if err := h.Sessions.Revoke(ctx, h.DB, sess.SID); err != nil {
			return err
		}
		if h.OnLogout != nil {
			h.OnLogout(ctx, sess, "logout")
		}
		h.audit(c, userOf(c), "user.logout", nil)
	}
	c.SetCookie(h.Cookies.Clear(auth.SessionCookie))
	if next := SafeNext(c.FormValue("next")); next != "" {
		return redirect(c, next)
	}
	return redirect(c, "/login?logged_out=1")
}

func (h *Handler) audit(c *echo.Context, u *store.User, action string, meta map[string]any) {
	e := &store.AuditEntry{At: time.Now().UTC(), Action: action, IP: c.RealIP(), Meta: meta}
	if u != nil {
		id := u.ID
		e.ActorUserID = &id
		e.TargetType, e.TargetID = "user", u.PublicSub
	}
	if err := store.InsertAudit(c.Request().Context(), h.DB, e); err != nil {
		h.Log.Warn("audit write failed", "err", err, "action", action)
	}
}

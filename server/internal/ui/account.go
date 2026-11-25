package ui

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v5"
	"rsc.io/qr"

	"moon-sso/server/internal/account"
	"moon-sso/server/internal/auth"
	"moon-sso/server/internal/crypto"
	"moon-sso/server/internal/store"
)

func (h *Handler) actor(c *echo.Context) account.Actor {
	return account.UserActor(userOf(c).ID, c.RealIP())
}

func (h *Handler) AccountPage(c *echo.Context) error {
	p := h.page(c, "个人资料")
	p.Nav = "profile"
	u := userOf(c)
	p.Form["display_name"] = u.DisplayName
	p.Form["username"] = u.Username
	if c.QueryParam("welcome") == "1" {
		p.Flash = "欢迎加入！你的账号已创建。"
	}
	return render(c, http.StatusOK, "account", "", p)
}

func (h *Handler) ProfileSubmit(c *echo.Context) error {
	p := h.page(c, "个人资料")
	p.Nav = "profile"
	p.Form = formValues(c, "display_name", "username")
	u := userOf(c)
	dn, un := p.Form["display_name"], p.Form["username"]
	updated, err := h.Accounts.UpdateProfile(c.Request().Context(), h.actor(c), u.ID, account.ProfileUpdate{DisplayName: &dn, Username: &un})
	if err != nil {
		if fieldErrors(p, err) {
			return render(c, http.StatusUnprocessableEntity, "account", "profile_form", p)
		}
		return err
	}
	p.User = updated
	c.Set("user", updated)
	p.Form["display_name"], p.Form["username"] = updated.DisplayName, updated.Username
	p.Flash = "资料已保存，并会同步到你使用的所有应用"
	return render(c, http.StatusOK, "account", "profile_form", p)
}

func (h *Handler) SecurityPage(c *echo.Context) error {
	p, err := h.securityPage(c)
	if err != nil {
		return err
	}
	return render(c, http.StatusOK, "security", "", p)
}

func (h *Handler) securityPage(c *echo.Context) (*Page, error) {
	p := h.page(c, "账号安全")
	p.Nav = "security"
	sessions, err := store.ListActiveSessions(c.Request().Context(), h.DB, userOf(c).ID, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	p.Data["Sessions"] = sessions
	return p, nil
}

func (h *Handler) PasswordSubmit(c *echo.Context) error {
	p := h.page(c, "账号安全")
	p.Nav = "security"
	u, sess := userOf(c), sessionOf(c)
	cur, next, next2 := c.FormValue("current_password"), c.FormValue("password"), c.FormValue("password_confirm")
	if next != next2 {
		p.Errors["password_confirm"] = "两次输入的密码不一致"
		return render(c, http.StatusUnprocessableEntity, "security", "password_form", p)
	}
	err := h.Accounts.ChangePassword(c.Request().Context(), h.actor(c), u.ID, cur, next, sess.SID)
	if err != nil {
		if fieldErrors(p, err) {
			return render(c, http.StatusUnprocessableEntity, "security", "password_form", p)
		}
		return err
	}
	h.Sessions.ForgetUser(u.ID)
	p.Flash = "密码已修改，其他设备上的登录已全部退出"
	return render(c, http.StatusOK, "security", "password_form", p)
}

// ForcedPasswordPage handles the change required after an administrator reset.
func (h *Handler) ForcedPasswordPage(c *echo.Context) error {
	p := h.page(c, "设置新密码")
	p.Form["next"] = SafeNext(c.QueryParam("next"))
	return render(c, http.StatusOK, "password_change", "", p)
}

func (h *Handler) ForcedPasswordSubmit(c *echo.Context) error {
	p := h.page(c, "设置新密码")
	p.Form = formValues(c, "next")
	u, sess := userOf(c), sessionOf(c)
	cur, next, next2 := c.FormValue("current_password"), c.FormValue("password"), c.FormValue("password_confirm")
	if next != next2 {
		p.Errors["password_confirm"] = "两次输入的密码不一致"
		return render(c, http.StatusUnprocessableEntity, "password_change", "forced_form", p)
	}
	if err := h.Accounts.ChangePassword(c.Request().Context(), h.actor(c), u.ID, cur, next, sess.SID); err != nil {
		if fieldErrors(p, err) {
			return render(c, http.StatusUnprocessableEntity, "password_change", "forced_form", p)
		}
		return err
	}
	h.Sessions.ForgetUser(u.ID)
	to := SafeNext(p.Form["next"])
	if to == "" {
		to = "/account"
	}
	return redirect(c, to)
}

// ---- TOTP ----

const totpSetupCookie = "totp_setup"

type totpSetup struct {
	Secret string `json:"s"`
	Exp    int64  `json:"e"`
}

func qrDataURI(text string) (string, error) {
	code, err := qr.Encode(text, qr.M)
	if err != nil {
		return "", err
	}
	code.Scale = 6
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(code.PNG()), nil
}

func (h *Handler) TOTPSetup(c *echo.Context) error {
	p, err := h.securityPage(c)
	if err != nil {
		return err
	}
	u := userOf(c)
	if u.HasTOTP() {
		return render(c, http.StatusOK, "security", "totp_section", p)
	}
	secret := crypto.NewTOTPSecret()
	c.SetCookie(h.sealCookie(totpSetupCookie, totpSetup{Secret: secret, Exp: time.Now().Add(10 * time.Minute).Unix()}, 10*time.Minute))
	uri := crypto.TOTPURI(p.Site.SiteName, u.Username, secret)
	img, err := qrDataURI(uri)
	if err != nil {
		return err
	}
	p.Data["TOTPSecret"] = groupSecret(secret)
	p.Data["TOTPQR"] = templateURL(img)
	p.Data["TOTPSetup"] = true
	return render(c, http.StatusOK, "security", "totp_section", p)
}

func (h *Handler) TOTPConfirm(c *echo.Context) error {
	p, err := h.securityPage(c)
	if err != nil {
		return err
	}
	u := userOf(c)
	var st totpSetup
	if !h.openCookie(c, totpSetupCookie, &st) || time.Now().Unix() > st.Exp {
		p.Error = "绑定已超时，请重新开始"
		return render(c, http.StatusUnprocessableEntity, "security", "totp_section", p)
	}
	if err := h.Accounts.EnableTOTP(c.Request().Context(), h.actor(c), u.ID, st.Secret, c.FormValue("code")); err != nil {
		if fieldErrors(p, err) {
			img, _ := qrDataURI(crypto.TOTPURI(p.Site.SiteName, u.Username, st.Secret))
			p.Data["TOTPSecret"] = groupSecret(st.Secret)
			p.Data["TOTPQR"] = templateURL(img)
			p.Data["TOTPSetup"] = true
			return render(c, http.StatusUnprocessableEntity, "security", "totp_section", p)
		}
		return err
	}
	c.SetCookie(h.Cookies.Clear(totpSetupCookie))
	// Possession was just proven: record otp in the current session as well.
	if sess := sessionOf(c); sess != nil {
		_, _ = h.Sessions.StepUp(c.Request().Context(), sess, "otp")
	}
	fresh, err := store.GetUser(c.Request().Context(), h.DB, u.ID)
	if err != nil {
		return err
	}
	p.User = fresh
	p.Flash = "两步验证已开启"
	return render(c, http.StatusOK, "security", "totp_section", p)
}

func (h *Handler) TOTPDisable(c *echo.Context) error {
	p, err := h.securityPage(c)
	if err != nil {
		return err
	}
	u := userOf(c)
	if err := h.Accounts.DisableTOTP(c.Request().Context(), h.actor(c), u.ID, c.FormValue("password")); err != nil {
		if errors.Is(err, account.ErrWrongPassword) {
			p.Errors["totp_password"] = "密码不正确"
			return render(c, http.StatusUnprocessableEntity, "security", "totp_section", p)
		}
		return err
	}
	fresh, err := store.GetUser(c.Request().Context(), h.DB, u.ID)
	if err != nil {
		return err
	}
	p.User = fresh
	p.Flash = "两步验证已关闭"
	return render(c, http.StatusOK, "security", "totp_section", p)
}

func (h *Handler) RevokeSession(c *echo.Context) error {
	ctx := c.Request().Context()
	u, cur := userOf(c), sessionOf(c)
	sid := c.FormValue("sid")
	target, err := store.GetSessionBySID(ctx, h.DB, sid)
	if err != nil || target.UserID != u.ID {
		return echo.NewHTTPError(http.StatusNotFound, "会话不存在")
	}
	if err := h.Sessions.Revoke(ctx, h.DB, sid); err != nil {
		return err
	}
	if h.OnLogout != nil {
		h.OnLogout(ctx, target, "device_removed")
	}
	h.audit(c, u, "user.session_revoked", map[string]any{"sid": sid})
	if sid == cur.SID {
		c.SetCookie(h.Cookies.Clear(auth.SessionCookie))
		return redirect(c, "/login?logged_out=1")
	}
	p, err := h.securityPage(c)
	if err != nil {
		return err
	}
	p.Flash = "已让该设备退出登录"
	return render(c, http.StatusOK, "security", "sessions_section", p)
}

func groupSecret(s string) string {
	var parts []string
	for i := 0; i < len(s); i += 4 {
		end := min(i+4, len(s))
		parts = append(parts, s[i:end])
	}
	return strings.Join(parts, " ")
}

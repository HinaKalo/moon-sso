package admin

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v5"

	"moon-sso/server/internal/account"
	"moon-sso/server/internal/apitoken"
	"moon-sso/server/internal/crypto"
	"moon-sso/server/internal/store"
	"moon-sso/server/internal/ui"
)

// Console page "API 令牌": administrators issue console tokens for
// themselves (TOTP required), and can review and revoke every console and
// developer token.

func (h *Handler) tokensPage(c *echo.Context) (*ui.Page, error) {
	ctx := c.Request().Context()
	now := time.Now().UTC()
	me := adminOf(c)
	p := h.page(c, "API 令牌", "api_tokens")
	mine, err := store.ListAPITokens(ctx, h.DB, store.APITokenFilter{Kind: store.TokenConsole, Owner: &me.ID, IncludeClosed: true, Limit: 50}, now)
	if err != nil {
		return nil, err
	}
	all, err := store.ListAPITokens(ctx, h.DB, store.APITokenFilter{Kind: store.TokenConsole, Limit: 200}, now)
	if err != nil {
		return nil, err
	}
	var others []*store.APIToken
	for _, t := range all {
		if t.OwnerID != me.ID {
			others = append(others, t)
		}
	}
	devUser := strings.TrimSpace(c.QueryParam("user"))
	dev, err := store.ListAPITokens(ctx, h.DB, store.APITokenFilter{Kind: store.TokenDeveloper, OwnerName: account.NormalizeUsername(devUser), Limit: 100}, now)
	if err != nil {
		return nil, err
	}
	p.Data["Mine"] = apitoken.Views(mine, now)
	p.Data["Others"] = apitoken.Views(others, now)
	p.Data["Developer"] = apitoken.Views(dev, now)
	p.Data["TokenScopes"] = apitoken.ConsoleScopes
	p.Data["TokenLifetimes"] = apitoken.ConsoleLifetimes
	p.Data["GraceChoices"] = apitoken.GraceChoices
	p.Data["AdminAPI"] = h.Cfg.Server.AdminURL + "/api/v1"
	p.Data["DocsURL"] = h.Cfg.Server.PublicURL + "/docs#api-tokens"
	if _, ok := p.Data["SelectedTokenScopes"].([]string); !ok {
		p.Data["SelectedTokenScopes"] = []string{}
	}
	p.Form = map[string]string{"user": devUser, "days": "30"}
	return p, nil
}

// APITokens: GET /api-tokens
func (h *Handler) APITokens(c *echo.Context) error {
	p, err := h.tokensPage(c)
	if err != nil {
		return err
	}
	return render(c, http.StatusOK, "api_tokens", "", p)
}

// verifyStepUp checks a fresh TOTP code of the signed-in administrator.
func (h *Handler) verifyStepUp(c *echo.Context, code string) (bool, error) {
	a := adminOf(c)
	key := "admin-otp:" + a.ID.String()
	if d := h.throttle.Delay(key); d > 0 {
		return false, nil
	}
	fresh, err := store.GetAdmin(c.Request().Context(), h.DB, a.ID)
	if err != nil {
		return false, err
	}
	secret, err := h.AtRest.Open(fresh.TOTPSecretEnc, totpAAD(fresh.ID))
	if err != nil {
		return false, err
	}
	step, ok := crypto.VerifyTOTP(string(secret), strings.TrimSpace(code), time.Now(), fresh.TOTPLastStep)
	if ok {
		if ok, err = store.AdvanceAdminTOTP(c.Request().Context(), h.DB, fresh.ID, step); err != nil {
			return false, err
		}
	}
	if !ok {
		h.throttle.Fail(key)
		return false, nil
	}
	h.throttle.Success(key)
	return true, nil
}

// CreateAPIToken: POST /api-tokens
func (h *Handler) CreateAPIToken(c *echo.Context) error {
	me := adminOf(c)
	form, _ := c.FormValues()
	fail := func(status int, field, msg string) error {
		p, err := h.tokensPage(c)
		if err != nil {
			return err
		}
		p.Error = msg
		if field != "" {
			p.Errors[field] = msg
		}
		p.Form["name"], p.Form["days"], p.Form["allowed_ips"] = c.FormValue("name"), c.FormValue("days"), c.FormValue("allowed_ips")
		p.Data["SelectedTokenScopes"] = form["scopes"]
		return render(c, status, "api_tokens", "", p)
	}
	req := apitoken.RequestFromForm(store.TokenConsole, me.ID, me.Username, form, c.RealIP())
	if err := req.Normalize(); err != nil {
		var fe *apitoken.FieldError
		if errors.As(err, &fe) {
			return fail(http.StatusUnprocessableEntity, fe.Field, fe.Msg)
		}
		return err
	}
	ok, err := h.verifyStepUp(c, c.FormValue("code"))
	if err != nil {
		return err
	}
	if !ok {
		return fail(http.StatusUnauthorized, "code", "身份验证器验证码不正确、已使用过或尝试过于频繁")
	}
	plain, t, err := h.Tokens.Issue(c.Request().Context(), req, apitoken.Actor{Admin: me.Username, IP: c.RealIP()})
	if err != nil {
		var fe *apitoken.FieldError
		switch {
		case errors.As(err, &fe):
			return fail(http.StatusUnprocessableEntity, fe.Field, fe.Msg)
		case errors.Is(err, apitoken.ErrLimit):
			return fail(http.StatusUnprocessableEntity, "", err.Error())
		}
		return err
	}
	p, err := h.tokensPage(c)
	if err != nil {
		return err
	}
	p.Data["NewToken"] = plain
	p.Flash = "已创建「" + t.Name + "」。"
	return render(c, http.StatusOK, "api_tokens", "", p)
}

func (h *Handler) tokenByParam(c *echo.Context) (*store.APIToken, error) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return nil, echo.NewHTTPError(http.StatusNotFound, "令牌不存在")
	}
	t, err := store.GetAPIToken(c.Request().Context(), h.DB, id)
	if err != nil {
		return nil, echo.NewHTTPError(http.StatusNotFound, "令牌不存在")
	}
	return t, nil
}

// RotateAPIToken: POST /api-tokens/:id/rotate (own console tokens only)
func (h *Handler) RotateAPIToken(c *echo.Context) error {
	me := adminOf(c)
	t, err := h.tokenByParam(c)
	if err != nil {
		return err
	}
	if t.Kind != store.TokenConsole || t.OwnerID != me.ID {
		return echo.NewHTTPError(http.StatusForbidden, "只能轮换自己的控制台令牌")
	}
	grace, _ := strconv.Atoi(c.FormValue("grace"))
	plain, _, err := h.Tokens.Rotate(c.Request().Context(), t.ID, time.Duration(grace)*time.Second, apitoken.Actor{Admin: me.Username, IP: c.RealIP()})
	p, perr := h.tokensPage(c)
	if perr != nil {
		return perr
	}
	if err != nil {
		var fe *apitoken.FieldError
		if errors.As(err, &fe) || errors.Is(err, apitoken.ErrNotActive) {
			p.Error = err.Error()
			return render(c, http.StatusConflict, "api_tokens", "", p)
		}
		return err
	}
	p.Data["NewToken"] = plain
	p.Flash = "已轮换「" + t.Name + "」。"
	return render(c, http.StatusOK, "api_tokens", "", p)
}

// RevokeAPIToken: POST /api-tokens/:id/revoke (any console or developer token)
func (h *Handler) RevokeAPIToken(c *echo.Context) error {
	me := adminOf(c)
	t, err := h.tokenByParam(c)
	if err != nil {
		return err
	}
	reason := "owner"
	if t.Kind != store.TokenConsole || t.OwnerID != me.ID {
		reason = "admin"
	}
	if err := h.Tokens.Revoke(c.Request().Context(), t.ID, reason, apitoken.Actor{Admin: me.Username, IP: c.RealIP()}); err != nil && !errors.Is(err, apitoken.ErrNotActive) {
		return err
	}
	p, err := h.tokensPage(c)
	if err != nil {
		return err
	}
	p.Flash = "已吊销「" + t.Name + "」（" + t.OwnerName + "）。"
	return render(c, http.StatusOK, "api_tokens", "", p)
}

package portal

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v5"

	"moon-sso/server/internal/apitoken"
	"moon-sso/server/internal/store"
	"moon-sso/server/internal/ui"
)

// Developer API tokens on the developer center page (block "api_tokens").

func (h *Handler) tokenData(c *echo.Context, p *ui.Page) error {
	u := ui.UserOf(c)
	list, err := store.ListAPITokens(c.Request().Context(), h.DB, store.APITokenFilter{Kind: store.TokenDeveloper, Owner: &u.ID,
		IncludeClosed: true, Limit: 50}, time.Now().UTC())
	if err != nil {
		return err
	}
	p.Data["APITokens"] = apitoken.Views(list, time.Now())
	p.Data["TokenScopes"] = apitoken.DeveloperScopes
	p.Data["TokenLifetimes"] = apitoken.DeveloperLifetimes
	p.Data["GraceChoices"] = apitoken.GraceChoices
	p.Data["Issuer"] = h.OIDC.Issuer()
	if _, ok := p.Data["SelectedTokenScopes"].([]string); !ok {
		p.Data["SelectedTokenScopes"] = []string{}
	}
	return nil
}

func (h *Handler) renderTokens(c *echo.Context, status int, p *ui.Page) error {
	if err := h.tokenData(c, p); err != nil {
		return err
	}
	if p.Form["days"] == "" {
		p.Form["days"] = "90"
	}
	// Without JavaScript the full developer page is rendered, which also lists apps.
	u := ui.UserOf(c)
	apps, _, err := store.ListClients(c.Request().Context(), h.DB, store.ClientFilter{Owner: &u.ID, Limit: 200})
	if err != nil {
		return err
	}
	p.Data["Apps"] = apps
	return ui.Render(c, status, "developer", "api_tokens", p)
}

// CreateAPIToken: POST /developer/api-tokens
func (h *Handler) CreateAPIToken(c *echo.Context) error {
	p := h.devPage(c, "开发者中心")
	u := ui.UserOf(c)
	form, _ := c.FormValues()
	req := apitoken.RequestFromForm(store.TokenDeveloper, u.ID, u.Username, form, c.RealIP())
	plain, t, err := h.Tokens.Issue(c.Request().Context(), req, apitoken.Actor{UserID: &u.ID, IP: c.RealIP()})
	if err != nil {
		var fe *apitoken.FieldError
		switch {
		case errors.As(err, &fe):
			p.Errors[fe.Field] = fe.Msg
			p.Error = fe.Msg
		case errors.Is(err, apitoken.ErrLimit):
			p.Error = err.Error()
		default:
			return err
		}
		p.Form = map[string]string{"name": c.FormValue("name"), "days": c.FormValue("days"), "allowed_ips": c.FormValue("allowed_ips")}
		p.Data["SelectedTokenScopes"] = form["scopes"]
		return h.renderTokens(c, http.StatusUnprocessableEntity, p)
	}
	p.Data["NewToken"] = plain
	p.Data["NewTokenView"] = apitoken.ViewOf(t, time.Now())
	return h.renderTokens(c, http.StatusOK, p)
}

// ownToken loads a developer token owned by the signed-in user.
func (h *Handler) ownToken(c *echo.Context) (*store.APIToken, error) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return nil, echo.NewHTTPError(http.StatusNotFound, "令牌不存在")
	}
	t, err := store.GetAPIToken(c.Request().Context(), h.DB, id)
	if err != nil || t.Kind != store.TokenDeveloper || t.OwnerID != ui.UserOf(c).ID {
		return nil, echo.NewHTTPError(http.StatusNotFound, "令牌不存在")
	}
	return t, nil
}

// RotateAPIToken: POST /developer/api-tokens/:id/rotate
func (h *Handler) RotateAPIToken(c *echo.Context) error {
	t, err := h.ownToken(c)
	if err != nil {
		return err
	}
	p := h.devPage(c, "开发者中心")
	u := ui.UserOf(c)
	grace, _ := strconv.Atoi(c.FormValue("grace"))
	plain, nt, err := h.Tokens.Rotate(c.Request().Context(), t.ID, time.Duration(grace)*time.Second, apitoken.Actor{UserID: &u.ID, IP: c.RealIP()})
	if err != nil {
		var fe *apitoken.FieldError
		if errors.As(err, &fe) || errors.Is(err, apitoken.ErrNotActive) {
			p.Error = err.Error()
			return h.renderTokens(c, http.StatusConflict, p)
		}
		return err
	}
	p.Data["NewToken"] = plain
	p.Data["NewTokenView"] = apitoken.ViewOf(nt, time.Now())
	p.Flash = "已轮换「" + t.Name + "」。"
	if grace > 0 {
		p.Flash += "旧令牌将在宽限期结束后失效。"
	} else {
		p.Flash += "旧令牌已立即失效。"
	}
	return h.renderTokens(c, http.StatusOK, p)
}

// RevokeAPIToken: POST /developer/api-tokens/:id/revoke
func (h *Handler) RevokeAPIToken(c *echo.Context) error {
	t, err := h.ownToken(c)
	if err != nil {
		return err
	}
	p := h.devPage(c, "开发者中心")
	u := ui.UserOf(c)
	if err := h.Tokens.Revoke(c.Request().Context(), t.ID, "owner", apitoken.Actor{UserID: &u.ID, IP: c.RealIP()}); err != nil {
		if !errors.Is(err, apitoken.ErrNotActive) {
			return err
		}
	}
	p.Flash = "已吊销「" + t.Name + "」，使用它的请求将立即被拒绝。"
	return h.renderTokens(c, http.StatusOK, p)
}

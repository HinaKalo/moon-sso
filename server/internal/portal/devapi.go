package portal

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/labstack/echo/v5"

	"moon-sso/server/internal/account"
	"moon-sso/server/internal/apitoken"
	"moon-sso/server/internal/clients"
	"moon-sso/server/internal/store"
)

// Developer API: /api/v1/developer/*, authenticated with developer API
// tokens (msso_dev_…). Every app operation is limited to apps the token's
// owner created, exactly like the developer center pages.

func devActor(c *echo.Context) account.Actor {
	p := apitoken.PrincipalOf(c)
	id := p.Token.OwnerID
	return account.Actor{UserID: &id, ClientID: p.Tag(), IP: c.RealIP()}
}

func tokenActor(c *echo.Context) apitoken.Actor {
	p := apitoken.PrincipalOf(c)
	id := p.Token.OwnerID
	return apitoken.Actor{UserID: &id, Via: p.Tag(), IP: c.RealIP()}
}

func apiFail(c *echo.Context, status int, code, desc string) error {
	return c.JSON(status, map[string]string{"error": code, "error_description": desc})
}

// APIError maps service errors to JSON responses shared by the token APIs.
func APIError(c *echo.Context, err error) error {
	var fe *account.FieldError
	var te *apitoken.FieldError
	switch {
	case errors.As(err, &fe):
		return c.JSON(http.StatusUnprocessableEntity, map[string]string{"error": "validation_failed", "error_description": fe.Msg, "field": fe.Field})
	case errors.As(err, &te):
		return c.JSON(http.StatusUnprocessableEntity, map[string]string{"error": "validation_failed", "error_description": te.Msg, "field": te.Field})
	case errors.Is(err, clients.ErrQuota), errors.Is(err, apitoken.ErrLimit):
		return apiFail(c, http.StatusForbidden, "quota_exceeded", err.Error())
	case errors.Is(err, apitoken.ErrNotActive):
		return apiFail(c, http.StatusConflict, "token_not_active", "令牌已吊销、已过期或已被轮换")
	case errors.Is(err, store.ErrNotFound):
		return apiFail(c, http.StatusNotFound, "not_found", "资源不存在")
	}
	return err
}

// RotateBody is the optional body of POST …/token/rotate.
type RotateBody struct {
	GraceSeconds *int `json:"grace_seconds"`
}

// DefaultGrace keeps a rotated token valid long enough for other machines
// that share it to pick up the new one.
const DefaultGrace = time.Hour

// GraceFrom parses the rotation grace period from a JSON body.
func GraceFrom(c *echo.Context) (time.Duration, error) {
	var b RotateBody
	if err := json.NewDecoder(io.LimitReader(c.Request().Body, 4<<10)).Decode(&b); err != nil && !errors.Is(err, io.EOF) {
		return 0, &account.FieldError{Field: "", Msg: "请求体必须是 JSON，例如 {\"grace_seconds\":3600}"}
	}
	if b.GraceSeconds == nil {
		return DefaultGrace, nil
	}
	return time.Duration(*b.GraceSeconds) * time.Second, nil
}

// DevTokenInfo: GET /api/v1/developer/token
func (h *Handler) DevTokenInfo(c *echo.Context) error {
	p := apitoken.PrincipalOf(c)
	u, err := store.GetUser(c.Request().Context(), h.DB, p.Token.OwnerID)
	if err != nil {
		return APIError(c, err)
	}
	return c.JSON(http.StatusOK, map[string]any{
		"token": apitoken.ViewOf(p.Token, time.Now()),
		"user":  map[string]any{"username": u.Username, "display_name": u.DisplayName, "sub": u.PublicSub},
		"api":   h.OIDC.Issuer() + "/api/v1/developer",
	})
}

// DevTokenRotate: POST /api/v1/developer/token/rotate
func (h *Handler) DevTokenRotate(c *echo.Context) error {
	grace, err := GraceFrom(c)
	if err != nil {
		return APIError(c, err)
	}
	p := apitoken.PrincipalOf(c)
	plain, t, err := h.Tokens.Rotate(c.Request().Context(), p.Token.ID, grace, tokenActor(c))
	if err != nil {
		return APIError(c, err)
	}
	return c.JSON(http.StatusCreated, apitoken.IssuedView{View: apitoken.ViewOf(t, time.Now()), Token: plain})
}

// DevTokenRevoke: DELETE /api/v1/developer/token
func (h *Handler) DevTokenRevoke(c *echo.Context) error {
	p := apitoken.PrincipalOf(c)
	if err := h.Tokens.Revoke(c.Request().Context(), p.Token.ID, "self", tokenActor(c)); err != nil {
		return APIError(c, err)
	}
	return c.NoContent(http.StatusNoContent)
}

// apiApp loads an app owned by the token's owner (404 otherwise).
func (h *Handler) apiApp(c *echo.Context) (*store.Client, error) {
	p := apitoken.PrincipalOf(c)
	cl, err := store.GetClient(c.Request().Context(), h.DB, c.Param("id"))
	if err != nil || cl.OwnerUserID == nil || *cl.OwnerUserID != p.Token.OwnerID {
		return nil, store.ErrNotFound
	}
	return cl, nil
}

// DevListApps: GET /api/v1/developer/apps
func (h *Handler) DevListApps(c *echo.Context) error {
	owner := apitoken.PrincipalOf(c).Token.OwnerID
	list, total, err := store.ListClients(c.Request().Context(), h.DB, store.ClientFilter{Owner: &owner, Limit: 200})
	if err != nil {
		return err
	}
	out := make([]map[string]any, 0, len(list))
	for _, cl := range list {
		out = append(out, h.Clients.Describe(cl, nil))
	}
	return c.JSON(http.StatusOK, map[string]any{"apps": out, "total": total})
}

// DevCreateApp: POST /api/v1/developer/apps (RFC 7591 metadata)
func (h *Handler) DevCreateApp(c *echo.Context) error {
	m, _, err := clients.DecodeJSON(c.Request().Body, nil, false)
	if err != nil {
		return APIError(c, err)
	}
	owner := apitoken.PrincipalOf(c).Token.OwnerID
	cl, creds, err := h.Clients.Create(c.Request().Context(), m, nil, &owner, false, devActor(c))
	if err != nil {
		return APIError(c, err)
	}
	return c.JSON(http.StatusCreated, h.Clients.Describe(cl, creds))
}

// DevGetApp: GET /api/v1/developer/apps/:id
func (h *Handler) DevGetApp(c *echo.Context) error {
	cl, err := h.apiApp(c)
	if err != nil {
		return APIError(c, err)
	}
	return c.JSON(http.StatusOK, h.Clients.Describe(cl, nil))
}

// DevPatchApp: PATCH /api/v1/developer/apps/:id (partial RFC 7591 metadata)
func (h *Handler) DevPatchApp(c *echo.Context) error {
	cl, err := h.apiApp(c)
	if err != nil {
		return APIError(c, err)
	}
	m, _, err := clients.DecodeJSON(c.Request().Body, cl, false)
	if err != nil {
		return APIError(c, err)
	}
	updated, whSecret, err := h.Clients.Update(c.Request().Context(), cl.ID, m, nil, devActor(c))
	if err != nil {
		return APIError(c, err)
	}
	return c.JSON(http.StatusOK, h.Clients.Describe(updated, &clients.Credentials{WebhookSecret: whSecret}))
}

// DevDeleteApp: DELETE /api/v1/developer/apps/:id
func (h *Handler) DevDeleteApp(c *echo.Context) error {
	cl, err := h.apiApp(c)
	if err != nil {
		return APIError(c, err)
	}
	if err := h.Clients.Delete(c.Request().Context(), cl.ID, devActor(c)); err != nil {
		return APIError(c, err)
	}
	return c.NoContent(http.StatusNoContent)
}

// DevRotateAppSecret: POST /api/v1/developer/apps/:id/rotate-secret
func (h *Handler) DevRotateAppSecret(c *echo.Context) error {
	cl, err := h.apiApp(c)
	if err != nil {
		return APIError(c, err)
	}
	secret, err := h.Clients.RotateSecret(c.Request().Context(), cl.ID, devActor(c))
	if err != nil {
		return APIError(c, err)
	}
	return c.JSON(http.StatusOK, map[string]any{"client_id": cl.ID, "client_secret": secret})
}

// DevRotateWebhookSecret: POST /api/v1/developer/apps/:id/rotate-webhook-secret
func (h *Handler) DevRotateWebhookSecret(c *echo.Context) error {
	cl, err := h.apiApp(c)
	if err != nil {
		return APIError(c, err)
	}
	if cl.WebhookURL == "" {
		return apiFail(c, http.StatusConflict, "webhook_not_configured", "尚未配置 Webhook 地址")
	}
	secret, err := h.Clients.RotateWebhookSecret(c.Request().Context(), cl.ID, devActor(c))
	if err != nil {
		return APIError(c, err)
	}
	return c.JSON(http.StatusOK, map[string]any{"client_id": cl.ID, "webhook_secret": secret})
}

// DevTestWebhook: POST /api/v1/developer/apps/:id/webhook-test
func (h *Handler) DevTestWebhook(c *echo.Context) error {
	cl, err := h.apiApp(c)
	if err != nil {
		return APIError(c, err)
	}
	if allowed, _ := h.TestLimiter.Allow("whtest:" + apitoken.PrincipalOf(c).Token.OwnerID.String()); !allowed {
		c.Response().Header().Set("Retry-After", "30")
		return apiFail(c, http.StatusTooManyRequests, "rate_limited", "测试过于频繁，请稍后再试")
	}
	if cl.WebhookURL == "" {
		return apiFail(c, http.StatusConflict, "webhook_not_configured", "尚未配置 Webhook 地址")
	}
	if err := h.Feed.TestDelivery(c.Request().Context(), cl); err != nil {
		return c.JSON(http.StatusOK, map[string]any{"delivered": false, "error": err.Error()})
	}
	return c.JSON(http.StatusOK, map[string]any{"delivered": true})
}

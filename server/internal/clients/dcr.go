package clients

import (
	"crypto/hmac"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/labstack/echo/v5"

	"moon-sso/server/internal/account"
	"moon-sso/server/internal/oidc"
	"moon-sso/server/internal/store"
)

// RFC 7591 client metadata. Only these fields are accepted; flags such as
// first_party or skip_consent can never be set through dynamic registration.
type dcrMetadata struct {
	ClientName              string   `json:"client_name"`
	Description             string   `json:"description,omitempty"`
	ClientURI               string   `json:"client_uri,omitempty"`
	LogoURI                 string   `json:"logo_uri,omitempty"`
	PolicyURI               string   `json:"policy_uri,omitempty"`
	TOSURI                  string   `json:"tos_uri,omitempty"`
	RedirectURIs            []string `json:"redirect_uris"`
	PostLogoutRedirectURIs  []string `json:"post_logout_redirect_uris,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	ApplicationType         string   `json:"application_type,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
	IDTokenSignedAlg        string   `json:"id_token_signed_response_alg,omitempty"`
	BackchannelLogoutURI    string   `json:"backchannel_logout_uri,omitempty"`
	DPoPBoundAccessTokens   bool     `json:"dpop_bound_access_tokens,omitempty"`
	RequireDPoP             *bool    `json:"require_dpop,omitempty"` // alias used by the management API; wins when present
	WebhookURL              string   `json:"webhook_url,omitempty"`
	WebhookEvents           []string `json:"webhook_events,omitempty"`
}

func (d *dcrMetadata) toMetadata() (Metadata, error) {
	for _, rt := range d.ResponseTypes {
		if rt != "code" {
			return Metadata{}, ferr("response_types", "仅支持 response_types=[\"code\"]")
		}
	}
	dpop := d.DPoPBoundAccessTokens
	if d.RequireDPoP != nil {
		dpop = *d.RequireDPoP
	}
	return Metadata{Name: d.ClientName, Description: d.Description, ClientURI: d.ClientURI, LogoURI: d.LogoURI, PolicyURI: d.PolicyURI,
		TOSURI: d.TOSURI, RedirectURIs: d.RedirectURIs, PostLogoutRedirectURIs: d.PostLogoutRedirectURIs, GrantTypes: d.GrantTypes,
		AuthMethod: d.TokenEndpointAuthMethod, ApplicationType: d.ApplicationType, Scopes: strings.Fields(d.Scope),
		IDTokenAlg: d.IDTokenSignedAlg, BackchannelLogoutURI: d.BackchannelLogoutURI, RequireDPoP: dpop,
		WebhookURL: d.WebhookURL, WebhookEvents: d.WebhookEvents}, nil
}

func (s *Service) describe(c *store.Client, creds *Credentials) map[string]any {
	iss := s.OIDC.Issuer()
	out := map[string]any{
		"client_id": c.ID, "client_id_issued_at": c.CreatedAt.Unix(), "client_name": c.Name, "redirect_uris": c.RedirectURIs,
		"post_logout_redirect_uris": c.PostLogoutRedirectURIs, "grant_types": c.GrantTypes, "response_types": []string{"code"},
		"token_endpoint_auth_method": c.TokenEndpointAuthMethod, "application_type": c.ApplicationType,
		"scope": strings.Join(c.Scopes, " "), "id_token_signed_response_alg": c.IDTokenAlg, "subject_type": c.SubjectType,
		"backchannel_logout_uri": c.BackchannelLogoutURI, "dpop_bound_access_tokens": false, "require_dpop": c.RequireDPoP,
		"webhook_url": c.WebhookURL, "webhook_events": c.WebhookEvents, "registration_client_uri": iss + "/oauth/register/" + c.ID,
		"status": map[int]string{store.ClientActive: "active", store.ClientPending: "pending_approval", store.ClientDisabled: "disabled"}[c.Status],
	}
	for k, v := range map[string]string{"client_uri": c.ClientURI, "logo_uri": c.LogoURI, "policy_uri": c.PolicyURI, "tos_uri": c.TOSURI, "description": c.Description} {
		if v != "" {
			out[k] = v
		}
	}
	if creds != nil {
		if creds.ClientSecret != "" {
			out["client_secret"] = creds.ClientSecret
			out["client_secret_expires_at"] = 0
		}
		if creds.RegistrationToken != "" {
			out["registration_access_token"] = creds.RegistrationToken
		}
		if creds.WebhookSecret != "" {
			out["webhook_secret"] = creds.WebhookSecret
		}
	}
	return out
}

func dcrError(c *echo.Context, status int, code, desc string) error {
	c.Response().Header().Set("Cache-Control", "no-store")
	return c.JSON(status, map[string]string{"error": code, "error_description": desc})
}

func (s *Service) dcrErr(c *echo.Context, err error) error {
	var fe *account.FieldError
	switch {
	case errors.As(err, &fe):
		code := "invalid_client_metadata"
		if fe.Field == "redirect_uris" {
			code = "invalid_redirect_uri"
		}
		return dcrError(c, http.StatusBadRequest, code, fe.Msg)
	case errors.Is(err, ErrQuota):
		return dcrError(c, http.StatusForbidden, "access_denied", err.Error())
	case errors.Is(err, store.ErrNotFound):
		return dcrError(c, http.StatusUnauthorized, "invalid_token", "注册凭证无效")
	}
	return err
}

func decodeDCR(c *echo.Context) (*dcrMetadata, error) {
	var d dcrMetadata
	dec := json.NewDecoder(io.LimitReader(c.Request().Body, 32<<10))
	if err := dec.Decode(&d); err != nil {
		return nil, ferr("", "请求体必须是 JSON 格式的客户端元数据")
	}
	return &d, nil
}

// Register implements POST /oauth/register (RFC 7591). It requires an
// initial access token issued from the developer portal or by an admin.
func (s *Service) Register(c *echo.Context) error {
	tok := oidc.BearerToken(c.Request())
	if tok == "" {
		return dcrError(c, http.StatusUnauthorized, "invalid_token", "需要 initial access token（在开发者中心生成）")
	}
	ctx := c.Request().Context()
	creator, err := s.consumeIAT(ctx, tok)
	if err != nil {
		return dcrError(c, http.StatusUnauthorized, "invalid_token", "initial access token 无效、已过期或已用完")
	}
	d, err := decodeDCR(c)
	if err != nil {
		return s.dcrErr(c, err)
	}
	m, err := d.toMetadata()
	if err != nil {
		return s.dcrErr(c, err)
	}
	actor := account.Actor{UserID: &creator.ID, IP: c.RealIP()}
	cl, creds, err := s.Create(ctx, m, nil, &creator.ID, false, actor)
	if err != nil {
		return s.dcrErr(c, err)
	}
	c.Response().Header().Set("Cache-Control", "no-store")
	return c.JSON(http.StatusCreated, s.describe(cl, creds))
}

// managed authenticates RFC 7592 requests with the registration access token.
func (s *Service) managed(c *echo.Context) (*store.Client, error) {
	tok := oidc.BearerToken(c.Request())
	cl, err := store.GetClient(c.Request().Context(), s.DB, c.Param("id"))
	if err != nil || tok == "" || len(cl.RATHash) == 0 || !hmac.Equal(s.OIDC.HashSecret(tok), cl.RATHash) {
		return nil, dcrError(c, http.StatusUnauthorized, "invalid_token", "注册访问令牌无效")
	}
	return cl, nil
}

func (s *Service) ManageGet(c *echo.Context) error {
	cl, err := s.managed(c)
	if err != nil {
		return err
	}
	c.Response().Header().Set("Cache-Control", "no-store")
	return c.JSON(http.StatusOK, s.describe(cl, nil))
}

func (s *Service) ManagePut(c *echo.Context) error {
	cl, err := s.managed(c)
	if err != nil {
		return err
	}
	d, err := decodeDCR(c)
	if err != nil {
		return s.dcrErr(c, err)
	}
	m, err := d.toMetadata()
	if err != nil {
		return s.dcrErr(c, err)
	}
	updated, whSecret, err := s.Update(c.Request().Context(), cl.ID, m, nil, account.Actor{ClientID: cl.ID, IP: c.RealIP()})
	if err != nil {
		return s.dcrErr(c, err)
	}
	c.Response().Header().Set("Cache-Control", "no-store")
	return c.JSON(http.StatusOK, s.describe(updated, &Credentials{WebhookSecret: whSecret}))
}

func (s *Service) ManageDelete(c *echo.Context) error {
	cl, err := s.managed(c)
	if err != nil {
		return err
	}
	if err := s.Delete(c.Request().Context(), cl.ID, account.Actor{ClientID: cl.ID, IP: c.RealIP()}); err != nil {
		return err
	}
	return c.NoContent(http.StatusNoContent)
}

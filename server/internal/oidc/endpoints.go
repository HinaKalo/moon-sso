package oidc

import (
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/labstack/echo/v5"

	"moon-sso/server/internal/auth"
	"moon-sso/server/internal/crypto"
	"moon-sso/server/internal/httpx"
	"moon-sso/server/internal/store"
	"moon-sso/server/internal/ui"
)

// Discovery serves /.well-known/openid-configuration.
func (p *Provider) Discovery(c *echo.Context) error {
	iss := p.Issuer()
	var scopes []string
	for _, s := range Scopes {
		scopes = append(scopes, s.Name)
	}
	doc := map[string]any{
		"issuer":                                        iss,
		"authorization_endpoint":                        iss + "/oauth/authorize",
		"token_endpoint":                                iss + "/oauth/token",
		"userinfo_endpoint":                             iss + "/oauth/userinfo",
		"jwks_uri":                                      iss + "/.well-known/jwks.json",
		"registration_endpoint":                         iss + "/oauth/register",
		"revocation_endpoint":                           iss + "/oauth/revoke",
		"introspection_endpoint":                        iss + "/oauth/introspect",
		"end_session_endpoint":                          iss + "/oauth/end_session",
		"authorization_challenge_endpoint":              iss + "/oauth/authorize-challenge",
		"scopes_supported":                              scopes,
		"response_types_supported":                      []string{"code"},
		"response_modes_supported":                      []string{"query", "form_post"},
		"grant_types_supported":                         []string{GrantAuthCode, GrantRefresh, GrantClientCredentials},
		"subject_types_supported":                       []string{"public", "pairwise"},
		"id_token_signing_alg_values_supported":         []string{"RS256", "ES256"},
		"token_endpoint_auth_methods_supported":         []string{"client_secret_basic", "client_secret_post", "none"},
		"revocation_endpoint_auth_methods_supported":    []string{"client_secret_basic", "client_secret_post", "none"},
		"introspection_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"code_challenge_methods_supported":              []string{"S256"},
		"claims_supported": []string{"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "sid", "amr", "azp", "at_hash",
			"preferred_username", "name", "nickname", "picture", "updated_at", "profile_version"},
		"prompt_values_supported":                        []string{"none", "login", "consent", "select_account"},
		"authorization_response_iss_parameter_supported": true,
		"backchannel_logout_supported":                   true,
		"backchannel_logout_session_supported":           true,
		"frontchannel_logout_supported":                  false,
		"dpop_signing_alg_values_supported":              []string{"ES256", "ES384", "RS256", "PS256", "EdDSA"},
		"request_parameter_supported":                    false,
		"request_uri_parameter_supported":                false,
		"claims_parameter_supported":                     false,
		"ui_locales_supported":                           []string{"zh-CN"},
		"service_documentation":                          iss + "/docs",
		"moon_api_audience":                              p.APIAudience(),
		"moon_events_endpoint":                           iss + "/api/v1/me/events",
	}
	c.Response().Header().Set("Cache-Control", "public, max-age=3600")
	return c.JSON(http.StatusOK, doc)
}

// JWKS serves the published signing keys with ETag support.
func (p *Provider) JWKS(c *echo.Context) error {
	body, etag := p.Keys.JWKS()
	h := c.Response().Header()
	h.Set("ETag", etag)
	h.Set("Cache-Control", "public, max-age=900, stale-while-revalidate=300")
	if c.Request().Header.Get("If-None-Match") == etag {
		return c.NoContent(http.StatusNotModified)
	}
	return c.Blob(http.StatusOK, "application/jwk-set+json", body)
}

// BearerToken extracts a bearer access token from the Authorization header.
func BearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "Bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

// bearerError writes a 401 and returns httpx.ErrResponded so callers stop.
func bearerError(c *echo.Context, code, desc string) error {
	c.Response().Header().Set("WWW-Authenticate", `Bearer error="`+code+`", error_description="`+strings.ReplaceAll(desc, `"`, "'")+`"`)
	if err := c.JSON(http.StatusUnauthorized, map[string]string{"error": code, "error_description": desc}); err != nil {
		return err
	}
	return httpx.ErrResponded
}

// Authenticated resolves a bearer token to claims, client and user. It is
// shared by userinfo and /api/v1.
type Authenticated struct {
	Claims *AccessClaims
	Client *store.Client
	User   *store.User // nil for client_credentials tokens
}

// unavailable answers 503 for infrastructure failures so clients retry later
// instead of treating the token as invalid (which would trigger refreshes).
func unavailable(c *echo.Context) error {
	c.Response().Header().Set("Retry-After", "2")
	if err := c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "temporarily_unavailable", "error_description": "服务暂时不可用，请稍后重试"}); err != nil {
		return err
	}
	return httpx.ErrResponded
}

func (p *Provider) Authenticate(c *echo.Context) (*Authenticated, error) {
	tok := BearerToken(c.Request())
	if tok == "" {
		return nil, bearerError(c, "invalid_request", "缺少 Bearer 令牌")
	}
	cl, err := p.VerifyAccess(tok)
	if err != nil {
		if errors.Is(err, errTokenExpired) {
			return nil, bearerError(c, "invalid_token", "令牌已过期")
		}
		return nil, bearerError(c, "invalid_token", "令牌无效")
	}
	ctx := c.Request().Context()
	client, err := p.Client(ctx, cl.ClientID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, unavailable(c)
	}
	if err != nil || !client.IsActive() {
		return nil, bearerError(c, "invalid_token", "应用不可用")
	}
	a := &Authenticated{Claims: cl, Client: client}
	if cl.Sub == cl.ClientID && cl.SID == "" && cl.AuthTime == 0 {
		return a, nil // client_credentials
	}
	uid, err := p.UserIDForSubject(ctx, client.ID, cl.Sub)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, unavailable(c)
	}
	if err != nil {
		return nil, bearerError(c, "invalid_token", "授权已被撤销")
	}
	u, err := p.loadUser(c, uid)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, unavailable(c)
	}
	if err != nil || !u.IsActive() {
		return nil, bearerError(c, "invalid_token", "用户不可用")
	}
	a.User = u
	return a, nil
}

func (p *Provider) loadUser(c *echo.Context, id [16]byte) (*store.User, error) {
	if u, ok := p.UI.Users.Get(id); ok {
		return u, nil
	}
	u, err := store.GetUser(c.Request().Context(), p.DB, id)
	if err != nil {
		return nil, err
	}
	p.UI.Users.Set(id, u)
	return u, nil
}

// UserInfo serves claims about the authenticated user.
func (p *Provider) UserInfo(c *echo.Context) error {
	c.Response().Header().Set("Cache-Control", "no-store")
	a, err := p.Authenticate(c)
	if err != nil {
		return err
	}
	p.setCORS(c, a.Client)
	if a.User == nil || !a.Claims.HasScope(ScopeOpenID) {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "insufficient_scope", "error_description": "需要 openid scope"})
	}
	out := map[string]any{"sub": a.Claims.Sub}
	if a.Claims.HasScope(ScopeProfile) {
		for k, v := range p.ProfileClaims(a.User) {
			out[k] = v
		}
	}
	return c.JSON(http.StatusOK, out)
}

// Revoke implements RFC 7009. It always answers 200 for unknown tokens.
func (p *Provider) Revoke(c *echo.Context) error {
	cl, e := p.AuthenticateClient(c)
	if e != nil {
		return writeError(c, e)
	}
	p.setCORS(c, cl)
	tok := c.FormValue("token")
	if tok == "" {
		return writeError(c, errInvalidRequest("缺少 token"))
	}
	ctx := c.Request().Context()
	if strings.Count(tok, ".") == 2 {
		if claims, err := p.VerifyAccess(tok); err == nil && claims.ClientID == cl.ID {
			p.revokedJTI.SetTTL(claims.Jti, struct{}{}, time.Until(time.Unix(claims.Exp, 0))+time.Minute)
		}
		return c.NoContent(http.StatusOK)
	}
	h := crypto.SHA256(tok)
	fid, err := store.FamilyIDByCurrentHash(ctx, p.DB, h)
	if errors.Is(err, store.ErrNotFound) {
		fid, _, err = store.HistoryLookup(ctx, p.DB, h)
	}
	if err == nil {
		if f, err := store.GetFamily(ctx, p.DB, fid); err == nil && f.ClientID == cl.ID {
			if err := store.RevokeFamily(ctx, p.DB, f.ID, "client_revoked", p.now()); err != nil {
				return err
			}
		}
	}
	return c.NoContent(http.StatusOK)
}

// Introspect implements RFC 7662 for confidential clients. A token is only
// reported active to the client it was issued to or a listed audience.
func (p *Provider) Introspect(c *echo.Context) error {
	cl, e := p.AuthenticateClient(c)
	if e != nil {
		return writeError(c, e)
	}
	if cl.IsPublic() {
		return writeError(c, errInvalidClient("内省需要机密客户端"))
	}
	inactive := map[string]any{"active": false}
	tok := c.FormValue("token")
	ctx := c.Request().Context()
	now := p.now()
	if strings.Count(tok, ".") == 2 {
		claims, err := p.VerifyAccess(tok)
		if err != nil || (claims.ClientID != cl.ID && !slices.Contains(claims.Aud, cl.ID)) {
			return writeJSON(c, http.StatusOK, inactive)
		}
		if claims.Sub != claims.ClientID {
			tokClient, err := p.Client(ctx, claims.ClientID)
			if err != nil {
				return writeJSON(c, http.StatusOK, inactive)
			}
			uid, err := p.UserIDForSubject(ctx, tokClient.ID, claims.Sub)
			if err != nil {
				return writeJSON(c, http.StatusOK, inactive)
			}
			if u, err := store.GetUser(ctx, p.DB, uid); err != nil || !u.IsActive() {
				return writeJSON(c, http.StatusOK, inactive)
			}
		}
		return writeJSON(c, http.StatusOK, map[string]any{
			"active": true, "token_type": "Bearer", "scope": claims.Scope, "client_id": claims.ClientID, "sub": claims.Sub,
			"aud": claims.Aud, "iss": claims.Iss, "exp": claims.Exp, "iat": claims.Iat, "jti": claims.Jti, "sid": claims.SID,
		})
	}
	fid, err := store.FamilyIDByCurrentHash(ctx, p.DB, crypto.SHA256(tok))
	if err != nil {
		return writeJSON(c, http.StatusOK, inactive)
	}
	f, err := store.GetFamily(ctx, p.DB, fid)
	if err != nil || f.ClientID != cl.ID || f.RevokedAt != nil || now.After(f.IdleExpiresAt) || now.After(f.AbsExpiresAt) {
		return writeJSON(c, http.StatusOK, inactive)
	}
	g, err := store.GetGrant(ctx, p.DB, f.UserID, cl.ID)
	if err != nil || g.RevokedAt != nil {
		return writeJSON(c, http.StatusOK, inactive)
	}
	return writeJSON(c, http.StatusOK, map[string]any{
		"active": true, "token_type": "refresh_token", "scope": strings.Join(f.Scopes, " "), "client_id": f.ClientID,
		"sub": g.Sub, "exp": f.IdleExpiresAt.Unix(), "iat": f.CurrentIssuedAt.Unix(), "iss": p.Issuer(),
	})
}

// EndSession implements OIDC RP-Initiated Logout 1.0.
func (p *Provider) EndSessionEndpoint(c *echo.Context) error {
	q := rawParams(c)
	hintTok := q.Get("id_token_hint")
	clientID := q.Get("client_id")
	var hint *idHint
	if hintTok != "" {
		h, ok := p.parseIDTokenHint(hintTok)
		if !ok {
			return p.authzPageError(c, "id_token_hint 无效")
		}
		hint = h
		if clientID == "" {
			clientID = h.firstAud()
		} else if !h.hasAud(clientID) {
			return p.authzPageError(c, "client_id 与 id_token_hint 不一致")
		}
	}
	redirect := q.Get("post_logout_redirect_uri")
	var cl *store.Client
	if clientID != "" {
		var err error
		if cl, err = p.Client(c.Request().Context(), clientID); err != nil {
			return p.authzPageError(c, "应用不存在")
		}
	}
	if redirect != "" && (cl == nil || !slices.Contains(cl.PostLogoutRedirectURIs, redirect)) {
		return p.authzPageError(c, "退出后的回调地址未登记")
	}
	finalURL := ""
	if redirect != "" {
		u, _ := url.Parse(redirect)
		if st := q.Get("state"); st != "" {
			qv := u.Query()
			qv.Set("state", st)
			u.RawQuery = qv.Encode()
		}
		finalURL = u.String()
	}
	sess, user := ui.SessionOf(c), ui.UserOf(c)
	if sess == nil {
		if finalURL != "" {
			return c.Redirect(http.StatusFound, finalURL)
		}
		return c.Redirect(http.StatusFound, "/login?logged_out=1")
	}
	// A valid hint for the current session lets us skip the confirmation step.
	confirmed := c.Request().Method == http.MethodPost && c.FormValue("confirm") == "1" && p.UI.CSRFValid(c)
	if hint != nil && cl != nil && hint.Sub == p.Subject(cl, user) && (hint.SID == "" || hint.SID == sess.SID) {
		confirmed = true
	}
	if !confirmed {
		pg := p.UI.NewPage(c, "退出登录")
		pg.Data["Client"] = cl
		pg.Data["Params"] = map[string]string{"client_id": clientID, "post_logout_redirect_uri": redirect, "state": q.Get("state")}
		return ui.Render(c, http.StatusOK, "end_session", "", pg)
	}
	if err := p.EndSession(c.Request().Context(), sess, "logout"); err != nil {
		return err
	}
	p.UI.Audit(c, user, "user.logout", map[string]any{"via": "end_session", "client": clientID})
	c.SetCookie(p.UI.Cookies.Clear(auth.SessionCookie))
	if finalURL != "" {
		return c.Redirect(http.StatusFound, finalURL)
	}
	return c.Redirect(http.StatusFound, "/login?logged_out=1")
}

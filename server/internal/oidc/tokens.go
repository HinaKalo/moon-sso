package oidc

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"moon-sso/server/internal/crypto"
	"moon-sso/server/internal/keys"
	"moon-sso/server/internal/store"
)

// AccessClaims follow RFC 9068 (JWT profile for OAuth access tokens).
type AccessClaims struct {
	Iss      string   `json:"iss"`
	Sub      string   `json:"sub"`
	Aud      []string `json:"aud"`
	Exp      int64    `json:"exp"`
	Iat      int64    `json:"iat"`
	Nbf      int64    `json:"nbf"`
	Jti      string   `json:"jti"`
	ClientID string   `json:"client_id"`
	Scope    string   `json:"scope,omitempty"`
	SID      string   `json:"sid,omitempty"`
	AuthTime int64    `json:"auth_time,omitempty"`
	PV       uint64   `json:"pv,omitempty"`
	Cnf      *struct {
		JKT string `json:"jkt"`
	} `json:"cnf,omitempty"`
}

func (a *AccessClaims) HasScope(s string) bool { return slices.Contains(strings.Fields(a.Scope), s) }

type tokenInput struct {
	client   *store.Client
	user     *store.User // nil for client_credentials
	sub      string
	scopes   []string
	sid      string
	authTime time.Time
	amr      []string
	nonce    string
	resource string
}

func (p *Provider) accessTTL(c *store.Client) time.Duration {
	if c.AccessTokenTTLSeconds != nil && *c.AccessTokenTTLSeconds >= 60 && *c.AccessTokenTTLSeconds <= 3600 {
		return time.Duration(*c.AccessTokenTTLSeconds) * time.Second
	}
	return p.Settings.Get().AccessTTL()
}

func (p *Provider) audience(in tokenInput) []string {
	aud := []string{in.client.ID}
	if in.resource != "" && in.resource != in.client.ID {
		aud = append(aud, in.resource)
	}
	if hasAny(in.scopes, APIScopes) && !slices.Contains(aud, p.APIAudience()) {
		aud = append(aud, p.APIAudience())
	}
	return aud
}

func (p *Provider) mintAccess(in tokenInput) (string, time.Duration, *AccessClaims, error) {
	now := p.now()
	ttl := p.accessTTL(in.client)
	cl := &AccessClaims{
		Iss: p.Issuer(), Sub: in.sub, Aud: p.audience(in), Exp: now.Add(ttl).Unix(), Iat: now.Unix(), Nbf: now.Unix() - 5,
		Jti: crypto.RandomToken(16), ClientID: in.client.ID, Scope: strings.Join(in.scopes, " "), SID: in.sid,
	}
	if in.user != nil {
		cl.AuthTime = in.authTime.Unix()
		cl.PV = in.user.ProfileVersion
	}
	tok, err := p.Keys.Sign(keys.AlgES256, "at+jwt", cl)
	return tok, ttl, cl, err
}

// ProfileClaims returns the standard claims released with the "profile" scope.
func (p *Provider) ProfileClaims(u *store.User) map[string]any {
	m := map[string]any{
		"preferred_username": u.Username,
		"name":               u.Name(),
		"nickname":           u.DisplayName,
		"updated_at":         u.UpdatedAt.Unix(),
		"profile_version":    u.ProfileVersion,
	}
	if u.AvatarKey != "" {
		m["picture"] = p.Cfg.Server.PublicURL + "/avatars/" + u.AvatarKey
	}
	return m
}

func atHash(at string) string {
	sum := sha256.Sum256([]byte(at))
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}

func (p *Provider) mintID(in tokenInput, accessToken string) (string, error) {
	now := p.now()
	ttl := p.Cfg.Tokens.IDTokenTTL.Duration
	claims := map[string]any{
		"iss": p.Issuer(), "sub": in.sub, "aud": in.client.ID, "azp": in.client.ID,
		"exp": now.Add(ttl).Unix(), "iat": now.Unix(), "auth_time": in.authTime.Unix(),
	}
	if in.nonce != "" {
		claims["nonce"] = in.nonce
	}
	if in.sid != "" {
		claims["sid"] = in.sid
	}
	if len(in.amr) > 0 {
		claims["amr"] = in.amr
	}
	if accessToken != "" {
		claims["at_hash"] = atHash(accessToken)
	}
	if slices.Contains(in.scopes, ScopeProfile) && in.user != nil {
		for k, v := range p.ProfileClaims(in.user) {
			claims[k] = v
		}
	}
	alg := in.client.IDTokenAlg
	if alg != keys.AlgES256 {
		alg = keys.AlgRS256
	}
	return p.Keys.Sign(alg, "JWT", claims)
}

// mintLogoutToken builds an OIDC Back-Channel Logout token.
func (p *Provider) mintLogoutToken(c *store.Client, sub, sid string) (string, error) {
	now := p.now()
	claims := map[string]any{
		"iss": p.Issuer(), "aud": c.ID, "iat": now.Unix(), "exp": now.Add(2 * time.Minute).Unix(),
		"jti": crypto.RandomToken(16), "sub": sub,
		"events": map[string]any{"http://schemas.openid.net/event/backchannel-logout": map[string]any{}},
	}
	if sid != "" {
		claims["sid"] = sid
	}
	alg := c.IDTokenAlg
	if alg != keys.AlgES256 {
		alg = keys.AlgRS256
	}
	return p.Keys.Sign(alg, "logout+jwt", claims)
}

var (
	errTokenInvalid = errors.New("invalid token")
	errTokenExpired = errors.New("token expired")
)

// VerifyAccess validates an access token issued by this server.
func (p *Provider) VerifyAccess(tok string) (*AccessClaims, error) {
	if len(tok) > 8192 {
		return nil, errTokenInvalid
	}
	payload, err := p.Keys.Verify(tok, "at+jwt")
	if err != nil {
		return nil, errTokenInvalid
	}
	var cl AccessClaims
	if err := json.Unmarshal(payload, &cl); err != nil {
		return nil, errTokenInvalid
	}
	now := p.now().Unix()
	if cl.Iss != p.Issuer() {
		return nil, errTokenInvalid
	}
	if now >= cl.Exp {
		return nil, errTokenExpired
	}
	if cl.Nbf > now+30 {
		return nil, errTokenInvalid
	}
	if _, revoked := p.revokedJTI.Get(cl.Jti); revoked {
		return nil, errTokenInvalid
	}
	return &cl, nil
}

// idTokenHint parses an ID token we issued, ignoring expiry (OIDC Core §3.1.2.1).
type idHint struct {
	Sub string `json:"sub"`
	Aud any    `json:"aud"`
	SID string `json:"sid"`
}

func (p *Provider) parseIDTokenHint(tok string) (*idHint, bool) {
	if tok == "" || len(tok) > 8192 {
		return nil, false
	}
	payload, err := p.Keys.Verify(tok, "")
	if err != nil {
		return nil, false
	}
	var h idHint
	var iss struct {
		Iss string `json:"iss"`
	}
	if json.Unmarshal(payload, &h) != nil || json.Unmarshal(payload, &iss) != nil || iss.Iss != p.Issuer() {
		return nil, false
	}
	return &h, true
}

func (h *idHint) hasAud(clientID string) bool {
	switch v := h.Aud.(type) {
	case string:
		return v == clientID
	case []any:
		for _, a := range v {
			if s, _ := a.(string); s == clientID {
				return true
			}
		}
	}
	return false
}

func (h *idHint) firstAud() string {
	switch v := h.Aud.(type) {
	case string:
		return v
	case []any:
		if len(v) > 0 {
			s, _ := v[0].(string)
			return s
		}
	}
	return ""
}

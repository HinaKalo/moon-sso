package moonsso

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Token is a token response plus its computed expiry.
type Token struct {
	AccessToken  string    `json:"access_token"`
	TokenType    string    `json:"token_type"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	IDToken      string    `json:"id_token,omitempty"`
	Scope        string    `json:"scope,omitempty"`
	ExpiresIn    int64     `json:"expires_in,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
	IssuedAt     time.Time `json:"issued_at"`
}

// Lifetime returns the total validity of the access token.
func (t *Token) Lifetime() time.Duration { return t.ExpiresAt.Sub(t.IssuedAt) }

// Remaining returns how long the access token stays valid.
func (t *Token) Remaining() time.Duration { return time.Until(t.ExpiresAt) }

func randomString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// PKCE is a code verifier with its S256 challenge.
type PKCE struct {
	Verifier  string
	Challenge string
}

// NewPKCE returns a random 64-character verifier and its challenge.
func NewPKCE() PKCE {
	v := randomString(48)
	sum := sha256.Sum256([]byte(v))
	return PKCE{Verifier: v, Challenge: base64.RawURLEncoding.EncodeToString(sum[:])}
}

// AuthRequest holds the per-login secrets the caller must keep (in the user
// session or local state) until the callback arrives.
type AuthRequest struct {
	URL         string `json:"-"`
	State       string `json:"state"`
	Nonce       string `json:"nonce"`
	Verifier    string `json:"verifier"`
	RedirectURL string `json:"redirect_url"`
}

// AuthOptions customizes an authorization request.
type AuthOptions struct {
	RedirectURL string   // overrides Config.RedirectURL (desktop loopback)
	Scopes      []string // overrides Config.Scopes
	Prompt      string   // none | login | consent | select_account
	LoginHint   string
	MaxAge      *int
	Extra       url.Values
}

// AuthCodeURL builds the authorization URL with PKCE, state, nonce and,
// when DPoP is configured, dpop_jkt.
func (c *Client) AuthCodeURL(ctx context.Context, o AuthOptions) (*AuthRequest, error) {
	ep, err := c.endpoint(ctx, func(d *Discovery) string { return d.AuthorizationEndpoint }, "/oauth/authorize")
	if err != nil {
		return nil, err
	}
	redirect := o.RedirectURL
	if redirect == "" {
		redirect = c.cfg.RedirectURL
	}
	if redirect == "" {
		return nil, errors.New("moonsso: RedirectURL is required")
	}
	scopes := o.Scopes
	if len(scopes) == 0 {
		scopes = c.cfg.Scopes
	}
	p := NewPKCE()
	ar := &AuthRequest{State: randomString(24), Nonce: randomString(24), Verifier: p.Verifier, RedirectURL: redirect}
	q := url.Values{
		"client_id": {c.cfg.ClientID}, "redirect_uri": {redirect}, "response_type": {"code"},
		"scope": {strings.Join(scopes, " ")}, "state": {ar.State}, "nonce": {ar.Nonce},
		"code_challenge": {p.Challenge}, "code_challenge_method": {"S256"},
	}
	if o.Prompt != "" {
		q.Set("prompt", o.Prompt)
	}
	if o.LoginHint != "" {
		q.Set("login_hint", o.LoginHint)
	}
	if o.MaxAge != nil {
		q.Set("max_age", strconv.Itoa(*o.MaxAge))
	}
	if c.dpop != nil {
		q.Set("dpop_jkt", c.dpop.key.Thumbprint())
	}
	for k, v := range o.Extra {
		q[k] = v
	}
	ar.URL = ep + "?" + q.Encode()
	return ar, nil
}

// Exchange validates the callback parameters (state, iss, error) and redeems
// the code. It verifies the ID token (nonce, at_hash) when present.
func (c *Client) Exchange(ctx context.Context, ar *AuthRequest, callback url.Values) (*Token, Claims, error) {
	if e := callback.Get("error"); e != "" {
		return nil, nil, &Error{Code: e, Description: callback.Get("error_description")}
	}
	if callback.Get("state") == "" || callback.Get("state") != ar.State {
		return nil, nil, errors.New("moonsso: state mismatch")
	}
	if callback.Get("iss") != c.cfg.Issuer {
		return nil, nil, errors.New("moonsso: authorization response issuer mismatch")
	}
	code := callback.Get("code")
	if code == "" {
		return nil, nil, errors.New("moonsso: missing authorization code")
	}
	return c.redeem(ctx, url.Values{"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {ar.RedirectURL}, "code_verifier": {ar.Verifier}}, ar.Nonce)
}

func (c *Client) redeem(ctx context.Context, form url.Values, nonce string) (*Token, Claims, error) {
	tok, err := c.tokenRequest(ctx, form)
	if err != nil {
		return nil, nil, err
	}
	var claims Claims
	if tok.IDToken != "" {
		if claims, err = c.VerifyIDToken(ctx, tok.IDToken, nonce, tok.AccessToken); err != nil {
			return nil, nil, err
		}
	}
	return tok, claims, nil
}

// Refresh redeems a refresh token. The returned token carries the rotated
// refresh token, which must replace the old one immediately. A rejected
// refresh token yields an error wrapping ErrSessionExpired.
func (c *Client) Refresh(ctx context.Context, refreshToken string) (*Token, error) {
	tok, err := c.tokenRequest(ctx, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}})
	if IsCode(err, "invalid_grant") {
		return nil, errors.Join(ErrSessionExpired, err)
	}
	return tok, err
}

// ClientCredentials returns a cached client_credentials token for scope.
func (c *Client) ClientCredentials(ctx context.Context, scope string) (*Token, error) {
	c.ccMu.Lock()
	defer c.ccMu.Unlock()
	if t := c.ccTok[scope]; t != nil && t.Remaining() > time.Minute {
		return t, nil
	}
	t, err := c.tokenRequest(ctx, url.Values{"grant_type": {"client_credentials"}, "scope": {scope}})
	if err != nil {
		return nil, err
	}
	c.ccTok[scope] = t
	return t, nil
}

// tokenRequest posts to the token endpoint with client authentication,
// DPoP (nonce-aware) and one retry for transient failures.
func (c *Client) tokenRequest(ctx context.Context, form url.Values) (*Token, error) {
	ep, err := c.endpoint(ctx, func(d *Discovery) string { return d.TokenEndpoint }, "/oauth/token")
	if err != nil {
		return nil, err
	}
	var tok Token
	issued := time.Now()
	if err := c.postForm(ctx, ep, form, true, &tok); err != nil {
		return nil, err
	}
	if tok.AccessToken == "" {
		return nil, &Error{Code: "invalid_response", Description: "no access_token in response"}
	}
	tok.IssuedAt = issued
	tok.ExpiresAt = issued.Add(time.Duration(tok.ExpiresIn) * time.Second)
	return &tok, nil
}

// postForm sends an authenticated form POST. withAuth adds client
// credentials (Basic for confidential clients, client_id for public ones).
func (c *Client) postForm(ctx context.Context, u string, form url.Values, withAuth bool, out any) error {
	attempt := func() error {
		body := url.Values{}
		for k, v := range form {
			body[k] = v
		}
		if withAuth && c.IsPublic() {
			body.Set("client_id", c.cfg.ClientID)
		}
		req, err := c.newRequest(ctx, http.MethodPost, u, strings.NewReader(body.Encode()))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if withAuth && !c.IsPublic() {
			req.SetBasicAuth(url.QueryEscape(c.cfg.ClientID), url.QueryEscape(c.cfg.ClientSecret))
		}
		if c.dpop != nil {
			proof, err := c.dpop.proof(http.MethodPost, u)
			if err != nil {
				return err
			}
			req.Header.Set("DPoP", proof)
		}
		resp, err := c.http.Do(req)
		if err != nil {
			return &Error{Code: "network", Description: err.Error()}
		}
		defer resp.Body.Close()
		if c.dpop != nil {
			c.dpop.setNonce(resp.Header.Get("DPoP-Nonce"))
		}
		return decodeResponse(resp, out)
	}
	err := attempt()
	if IsCode(err, "use_dpop_nonce") {
		err = attempt()
	}
	// Authorization codes are single-use: a replay revokes what the code
	// produced, so only refresh and client_credentials requests are retried.
	// Registration is not idempotent either (a retry would report the
	// username as taken), so requests carrying a password are not retried.
	if isRetryable(err) && form.Get("code") == "" && form.Get("password") == "" {
		select {
		case <-ctx.Done():
			return err
		case <-time.After(300 * time.Millisecond):
		}
		err = attempt()
		if IsCode(err, "use_dpop_nonce") {
			err = attempt()
		}
	}
	return err
}

// Revoke revokes a refresh or access token (RFC 7009). Errors are returned
// but callers usually ignore them when signing out.
func (c *Client) Revoke(ctx context.Context, token string) error {
	ep, err := c.endpoint(ctx, func(d *Discovery) string { return d.RevocationEndpoint }, "/oauth/revoke")
	if err != nil {
		return err
	}
	return c.postForm(ctx, ep, url.Values{"token": {token}}, true, nil)
}

// EndSessionURL builds an RP-initiated logout URL.
func (c *Client) EndSessionURL(ctx context.Context, idTokenHint, postLogoutRedirect, state string) (string, error) {
	ep, err := c.endpoint(ctx, func(d *Discovery) string { return d.EndSessionEndpoint }, "/oauth/end_session")
	if err != nil {
		return "", err
	}
	q := url.Values{"client_id": {c.cfg.ClientID}}
	if idTokenHint != "" {
		q.Set("id_token_hint", idTokenHint)
	}
	if postLogoutRedirect != "" {
		q.Set("post_logout_redirect_uri", postLogoutRedirect)
	}
	if state != "" {
		q.Set("state", state)
	}
	return ep + "?" + q.Encode(), nil
}

// ---- first-party (in-app) login and registration ----

// Challenge carries state between the password step and the OTP step.
type Challenge struct {
	AuthSession string
	Verifier    string
	Challenge   string
	Scopes      []string
}

type challengeResp struct {
	AuthorizationCode string `json:"authorization_code"`
}

// LoginWithPassword signs a user in from inside a first-party app (the client
// must be flagged first_party + native_login by an administrator). If the
// account uses two-factor authentication an *OTPRequiredError is returned;
// pass its Challenge to CompleteOTP with the user's code.
func (c *Client) LoginWithPassword(ctx context.Context, username, password string, scopes ...string) (*Token, Claims, error) {
	if len(scopes) == 0 {
		scopes = c.cfg.Scopes
	}
	p := NewPKCE()
	ch := &Challenge{Verifier: p.Verifier, Challenge: p.Challenge, Scopes: scopes}
	return c.challengeStep(ctx, ch, url.Values{"username": {username}, "password": {password}})
}

// CompleteOTP finishes a login that returned *OTPRequiredError.
func (c *Client) CompleteOTP(ctx context.Context, ch *Challenge, otp string) (*Token, Claims, error) {
	return c.challengeStep(ctx, ch, url.Values{"auth_session": {ch.AuthSession}, "otp": {strings.TrimSpace(otp)}})
}

func (c *Client) challengeStep(ctx context.Context, ch *Challenge, extra url.Values) (*Token, Claims, error) {
	ep, err := c.endpoint(ctx, func(d *Discovery) string { return d.AuthorizationChallengeEndpoint }, "/oauth/authorize-challenge")
	if err != nil {
		return nil, nil, err
	}
	form := url.Values{"scope": {strings.Join(ch.Scopes, " ")}, "code_challenge": {ch.Challenge}, "code_challenge_method": {"S256"}}
	for k, v := range extra {
		form[k] = v
	}
	var out challengeResp
	if err := c.postForm(ctx, ep, form, true, &out); err != nil {
		var e *Error
		if errors.As(err, &e) && e.Code == "insufficient_authorization" {
			as, _ := e.Extra["auth_session"].(string)
			ch.AuthSession = as
			return nil, nil, &OTPRequiredError{Challenge: ch}
		}
		return nil, nil, err
	}
	return c.redeem(ctx, url.Values{"grant_type": {"authorization_code"}, "code": {out.AuthorizationCode}, "code_verifier": {ch.Verifier}}, "")
}

// RegisterNative creates an account from inside a first-party app and signs
// the new user in. Registration must be open (see RegistrationInfo).
func (c *Client) RegisterNative(ctx context.Context, username, password, displayName string, scopes ...string) (*Token, Claims, error) {
	if len(scopes) == 0 {
		scopes = c.cfg.Scopes
	}
	p := NewPKCE()
	form := url.Values{"username": {username}, "password": {password}, "display_name": {displayName},
		"scope": {strings.Join(scopes, " ")}, "code_challenge": {p.Challenge}, "code_challenge_method": {"S256"}}
	var out challengeResp
	if err := c.postForm(ctx, c.cfg.Issuer+"/api/v1/native/register", form, true, &out); err != nil {
		return nil, nil, err
	}
	return c.redeem(ctx, url.Values{"grant_type": {"authorization_code"}, "code": {out.AuthorizationCode}, "code_verifier": {p.Verifier}}, "")
}

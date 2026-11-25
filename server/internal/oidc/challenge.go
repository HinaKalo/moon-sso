package oidc

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v5"

	"moon-sso/server/internal/account"
	"moon-sso/server/internal/auth"
	"moon-sso/server/internal/crypto"
	"moon-sso/server/internal/store"
)

// First-party apps (draft-ietf-oauth-first-party-apps): an admin-flagged
// native client collects the username and password itself, receives an
// authorization code and then redeems it at the token endpoint with PKCE,
// exactly like the browser flow. A second factor is requested with an
// "insufficient_authorization" error carrying an auth_session.

type challengeSession struct {
	ClientID  string    `json:"c"`
	UserID    uuid.UUID `json:"u"`
	Scopes    []string  `json:"s"`
	Challenge string    `json:"cc"`
	JKT       string    `json:"j,omitempty"`
	Exp       int64     `json:"e"`
}

func (p *Provider) sealChallenge(cs challengeSession) string {
	cs.Exp = p.now().Add(5 * time.Minute).Unix()
	b, _ := json.Marshal(cs)
	return crypto.B64(p.requestBox.Seal(b, []byte("auth-session")))
}

func (p *Provider) openChallenge(s string) (*challengeSession, bool) {
	raw, err := crypto.UnB64(s)
	if err != nil || len(raw) > 4096 {
		return nil, false
	}
	pt, err := p.requestBox.Open(raw, []byte("auth-session"))
	if err != nil {
		return nil, false
	}
	var cs challengeSession
	if json.Unmarshal(pt, &cs) != nil || p.now().Unix() > cs.Exp {
		return nil, false
	}
	return &cs, true
}

type challengeReq struct {
	cl        *store.Client
	scopes    []string
	challenge string
	jkt       string
}

func (p *Provider) parseChallengeReq(c *echo.Context, path string) (*challengeReq, *Error) {
	c.Response().Header().Set("DPoP-Nonce", p.dpop.Nonce())
	cl, e := p.AuthenticateClient(c)
	if e != nil {
		return nil, e
	}
	p.setCORS(c, cl)
	if !cl.FirstParty || !cl.NativeLogin {
		return nil, errUnauthorizedClient("该应用未被允许使用应用内登录")
	}
	r := &challengeReq{cl: cl, scopes: parseScopes(c.FormValue("scope")), challenge: c.FormValue("code_challenge")}
	if len(r.scopes) == 0 {
		r.scopes = []string{ScopeOpenID, ScopeProfile, ScopeOffline}
	}
	if e := checkUserScopes(cl, r.scopes); e != nil {
		return nil, e
	}
	if c.FormValue("code_challenge_method") != "S256" || len(r.challenge) < 43 || len(r.challenge) > 128 {
		return nil, errInvalidRequest("必须使用 PKCE S256")
	}
	jkt, e := p.dpop.Verify(c.Request(), p.Issuer()+path)
	if e != nil {
		return nil, e
	}
	if cl.RequireDPoP && jkt == "" {
		return nil, errInvalidDPoP("该应用要求 DPoP 证明")
	}
	r.jkt = jkt
	return r, nil
}

// AuthorizeChallenge handles credential and OTP steps.
func (p *Provider) AuthorizeChallenge(c *echo.Context) error {
	ctx := c.Request().Context()
	ip := c.RealIP()
	if ok, _ := p.challengeLim.Allow(auth.IPKey(ip)); !ok {
		return writeError(c, &Error{http.StatusTooManyRequests, "slow_down", "请求过于频繁，请稍后再试", ""})
	}
	req, e := p.parseChallengeReq(c, "/oauth/authorize-challenge")
	if e != nil {
		return writeError(c, e)
	}
	c.Response().Header().Set("DPoP-Nonce", p.dpop.Nonce())

	// Step 2: second factor for an earlier credential step.
	if as := c.FormValue("auth_session"); as != "" {
		cs, ok := p.openChallenge(as)
		if !ok || cs.ClientID != req.cl.ID || cs.Challenge != req.challenge || cs.JKT != req.jkt {
			return writeError(c, errInvalidGrant("auth_session 无效或已过期"))
		}
		key := "otp:" + cs.UserID.String()
		if d := p.throttle.Delay(key); d > 0 {
			return writeError(c, &Error{http.StatusTooManyRequests, "slow_down", "尝试过于频繁", ""})
		}
		u, err := store.GetUser(ctx, p.DB, cs.UserID)
		if err != nil || !u.IsActive() {
			return writeError(c, errAccessDenied("账号不可用"))
		}
		if err := p.Accounts.VerifyTOTP(ctx, u, c.FormValue("otp")); err != nil {
			p.throttle.Fail(key)
			return writeJSON(c, http.StatusBadRequest, map[string]string{
				"error": "insufficient_authorization", "error_description": "验证码不正确", "auth_session": as, "required": "otp"})
		}
		p.throttle.Success(key)
		return p.challengeSuccess(c, req, u, []string{"pwd", "otp"})
	}

	// Step 1: username + password.
	username := account.NormalizeUsername(c.FormValue("username"))
	password := c.FormValue("password")
	if username == "" || password == "" {
		return writeError(c, errInvalidRequest("缺少用户名或密码"))
	}
	ukey := "u:" + username
	ipk := auth.IPKey(ip)
	if d := max(p.throttle.Delay(ukey+"|"+ipk), p.throttle.Delay(ukey)/4); d > 0 {
		return writeError(c, &Error{http.StatusTooManyRequests, "slow_down", "登录失败次数过多，请稍后再试", ""})
	}
	u, err := p.Accounts.Authenticate(ctx, username, password)
	if err != nil {
		switch {
		case errors.Is(err, crypto.ErrHasherBusy):
			return writeError(c, errTemporarilyUnavailable("服务器繁忙"))
		case errors.Is(err, account.ErrBadCredentials):
			p.throttle.Fail(ukey + "|" + ipk)
			p.throttle.Fail(ukey)
			return writeError(c, errAccessDenied("用户名或密码错误"))
		case errors.Is(err, account.ErrDisabled):
			return writeError(c, errAccessDenied(err.Error()))
		}
		return err
	}
	p.throttle.Success(ukey + "|" + ipk)
	p.throttle.Success(ukey)
	if u.MustChangePassword {
		return writeJSON(c, http.StatusBadRequest, map[string]string{"error": "password_change_required",
			"error_description": "管理员重置了密码，请先在浏览器中登录并设置新密码", "change_url": p.Issuer() + "/account/password/change"})
	}
	if u.HasTOTP() || req.cl.RequireAMR == "otp" {
		if !u.HasTOTP() {
			return writeError(c, errAccessDenied("该应用要求开启两步验证，请先在账号安全页面开启"))
		}
		as := p.sealChallenge(challengeSession{ClientID: req.cl.ID, UserID: u.ID, Scopes: req.scopes, Challenge: req.challenge, JKT: req.jkt})
		return writeJSON(c, http.StatusBadRequest, map[string]string{
			"error": "insufficient_authorization", "error_description": "需要两步验证码", "auth_session": as, "required": "otp"})
	}
	return p.challengeSuccess(c, req, u, []string{"pwd"})
}

// challengeSuccess creates a device session (visible and revocable in the
// account center) and returns a one-time authorization code.
func (p *Provider) challengeSuccess(c *echo.Context, req *challengeReq, u *store.User, amr []string) error {
	ctx := c.Request().Context()
	_, sess, err := p.Sessions.Create(ctx, u.ID, amr, c.RealIP(), c.Request().UserAgent())
	if err != nil {
		return err
	}
	code, err := p.issueDirectCode(ctx, req.cl, u, sess, req.scopes, req.challenge, req.jkt)
	if err != nil {
		return err
	}
	_ = store.InsertAudit(ctx, p.DB, &store.AuditEntry{At: p.now(), ActorUserID: &u.ID, ActorClientID: req.cl.ID,
		Action: "user.login", TargetType: "user", TargetID: u.PublicSub, IP: c.RealIP(), Meta: map[string]any{"via": "native", "amr": strings.Join(amr, " ")}})
	return writeJSON(c, http.StatusOK, map[string]string{"authorization_code": code})
}

func (p *Provider) issueDirectCode(ctx context.Context, cl *store.Client, u *store.User, sess *store.Session, scopes []string, challenge, jkt string) (string, error) {
	code := crypto.RandomToken(32)
	now := p.now()
	err := p.DB.Tx(ctx, sql.LevelReadCommitted, func(tx *sql.Tx) error {
		if err := store.InsertCode(ctx, tx, &store.AuthCode{
			CodeHash: crypto.SHA256(code), ClientID: cl.ID, UserID: u.ID, SID: sess.SID, RedirectURI: "",
			Scopes: scopes, CodeChallenge: challenge, CodeChallengeMethod: "S256", DPoPJKT: jkt,
			AuthTime: sess.AuthTime, AMR: sess.AMR, ExpiresAt: now.Add(p.Cfg.Tokens.CodeTTL.Duration),
		}); err != nil {
			return err
		}
		if err := store.AddSessionClient(ctx, tx, sess.SID, cl.ID, now); err != nil {
			return err
		}
		return p.recordGrant(ctx, tx, cl, u.ID, p.Subject(cl, u), scopes, true)
	})
	return code, err
}

// NativeRegister creates an account from inside a first-party app and
// returns an authorization code for the new user (registration must be open).
func (p *Provider) NativeRegister(c *echo.Context) error {
	ctx := c.Request().Context()
	if ok, _ := p.nativeRegLim.Allow(auth.IPKey(c.RealIP())); !ok {
		return writeError(c, &Error{http.StatusTooManyRequests, "slow_down", "注册过于频繁，请稍后再试", ""})
	}
	req, e := p.parseChallengeReq(c, "/api/v1/native/register")
	if e != nil {
		return writeError(c, e)
	}
	c.Response().Header().Set("DPoP-Nonce", p.dpop.Nonce())
	if !req.cl.AllowRegistration || !p.Settings.Get().RegistrationOpen {
		return writeError(c, &Error{http.StatusForbidden, "registration_closed", "暂未开放注册", ""})
	}
	u, err := p.Accounts.Register(ctx, account.RegisterInput{
		Username: c.FormValue("username"), Password: c.FormValue("password"), DisplayName: c.FormValue("display_name"),
		Via: "native:" + req.cl.ID, Actor: account.Actor{ClientID: req.cl.ID, IP: c.RealIP()},
	})
	if err != nil {
		return p.registrationError(c, err)
	}
	return p.challengeSuccess(c, req, u, []string{"pwd"})
}

// registrationError maps account errors to JSON.
func (p *Provider) registrationError(c *echo.Context, err error) error {
	var fe *account.FieldError
	switch {
	case errors.As(err, &fe):
		return writeJSON(c, http.StatusUnprocessableEntity, map[string]string{"error": "validation_failed", "error_description": fe.Msg, "field": fe.Field})
	case errors.Is(err, account.ErrRegistrationClosed):
		return writeError(c, &Error{http.StatusForbidden, "registration_closed", "暂未开放注册", ""})
	case errors.Is(err, crypto.ErrHasherBusy):
		return writeError(c, errTemporarilyUnavailable("服务器繁忙"))
	}
	return err
}

package oidc

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v5"

	"moon-sso/server/internal/crypto"
	"moon-sso/server/internal/httpx"
	"moon-sso/server/internal/store"
)

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// Token is the token endpoint (RFC 6749 §3.2).
func (p *Provider) Token(c *echo.Context) error {
	if !strings.HasPrefix(c.Request().Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		return writeError(c, errInvalidRequest("Content-Type 必须为 application/x-www-form-urlencoded"))
	}
	c.Response().Header().Set("DPoP-Nonce", p.dpop.Nonce())
	cl, e := p.AuthenticateClient(c)
	if e != nil {
		return writeError(c, e)
	}
	p.setCORS(c, cl)
	jkt, e := p.dpop.Verify(c.Request(), p.Issuer()+"/oauth/token")
	if e != nil {
		return writeError(c, e)
	}
	c.Response().Header().Set("DPoP-Nonce", p.dpop.Nonce())
	grant := c.FormValue("grant_type")
	if !cl.HasGrant(grant) {
		if grant == GrantAuthCode || grant == GrantRefresh || grant == GrantClientCredentials {
			return writeError(c, errUnauthorizedClient("该应用未启用 "+grant))
		}
		return writeError(c, errUnsupportedGrant("不支持的 grant_type"))
	}
	if cl.IsPublic() && cl.RequireDPoP && jkt == "" && grant != GrantClientCredentials {
		return writeError(c, errInvalidDPoP("该应用要求 DPoP 证明"))
	}
	var resp *tokenResponse
	switch grant {
	case GrantAuthCode:
		resp, e = p.exchangeCode(c, cl, jkt)
	case GrantRefresh:
		resp, e = p.refresh(c, cl, jkt)
	case GrantClientCredentials:
		resp, e = p.clientCredentials(c, cl)
	default:
		e = errUnsupportedGrant("不支持的 grant_type")
	}
	if e != nil {
		httpx.Metrics.Inc(`token_errors_total{error="` + e.Code + `"}`)
		return writeError(c, e)
	}
	httpx.Metrics.Inc(`tokens_issued_total{grant="` + grant + `"}`)
	return writeJSON(c, http.StatusOK, resp)
}

func verifyPKCE(verifier, challenge string) bool {
	if n := len(verifier); n < 43 || n > 128 {
		return false
	}
	for _, r := range verifier {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '.' || r == '_' || r == '~') {
			return false
		}
	}
	sum := sha256.Sum256([]byte(verifier))
	got := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(got), []byte(challenge)) == 1
}

func (p *Provider) exchangeCode(c *echo.Context, cl *store.Client, jkt string) (*tokenResponse, *Error) {
	ctx := c.Request().Context()
	code := c.FormValue("code")
	if code == "" || len(code) > 128 {
		return nil, errInvalidGrant("缺少或无效的 code")
	}
	verifier := c.FormValue("code_verifier")
	redirectURI := c.FormValue("redirect_uri")
	var resp *tokenResponse
	var oerr *Error
	err := p.DB.Tx(ctx, sql.LevelReadCommitted, func(tx *sql.Tx) error {
		resp, oerr = nil, nil
		ac, err := store.GetCodeForUpdate(ctx, tx, crypto.SHA256(code))
		if errors.Is(err, store.ErrNotFound) {
			oerr = errInvalidGrant("授权码无效")
			return nil
		}
		if err != nil {
			return err
		}
		now := p.now()
		if ac.UsedAt != nil {
			// RFC 6749 §4.1.2: revoke what the replayed code produced.
			if ac.FamilyID != nil {
				if err := store.RevokeFamily(ctx, tx, *ac.FamilyID, "code_replay", now); err != nil {
					return err
				}
			}
			p.Log.Warn("authorization code replay", "client", cl.ID)
			oerr = errInvalidGrant("授权码已被使用")
			return nil
		}
		switch {
		case ac.ClientID != cl.ID:
			oerr = errInvalidGrant("授权码不属于该应用")
		case now.After(ac.ExpiresAt):
			oerr = errInvalidGrant("授权码已过期")
		case ac.RedirectURI != redirectURI:
			oerr = errInvalidGrant("redirect_uri 与授权请求不一致")
		case !verifyPKCE(verifier, ac.CodeChallenge):
			oerr = errInvalidGrant("PKCE 校验失败")
		case ac.DPoPJKT != "" && ac.DPoPJKT != jkt:
			oerr = errInvalidDPoP("DPoP 密钥与授权请求不一致")
		}
		if oerr != nil {
			return nil
		}
		user, err := store.GetUser(ctx, tx, ac.UserID)
		if err != nil || !user.IsActive() {
			oerr = errInvalidGrant("用户不可用")
			return nil
		}
		if ac.SID != "" {
			sess, err := store.GetSessionBySID(ctx, tx, ac.SID)
			if err != nil || !sess.Valid(now) {
				oerr = errInvalidGrant("登录会话已结束")
				return nil
			}
		}
		in := tokenInput{client: cl, user: user, sub: p.Subject(cl, user), scopes: ac.Scopes, sid: ac.SID,
			authTime: ac.AuthTime, amr: strings.Fields(ac.AMR), nonce: ac.Nonce, resource: ac.Resource}
		var familyID *uuid.UUID
		var refreshToken string
		if cl.HasGrant(GrantRefresh) {
			bindJKT := ""
			if cl.IsPublic() {
				bindJKT = jkt
			}
			fam, tok, err := p.newFamily(ctx, tx, c, cl, user, ac, bindJKT)
			if err != nil {
				return err
			}
			familyID, refreshToken = &fam.ID, tok
		}
		if err := store.MarkCodeUsed(ctx, tx, ac.CodeHash, now, familyID); err != nil {
			return err
		}
		resp, oerr = p.buildResponse(in, refreshToken, slices.Contains(ac.Scopes, ScopeOpenID))
		return nil
	})
	if err != nil {
		p.Log.Error("code exchange failed", "err", err)
		return nil, errTemporarilyUnavailable("服务暂时不可用，请重试")
	}
	return resp, oerr
}

func (p *Provider) newFamily(ctx context.Context, tx *sql.Tx, c *echo.Context, cl *store.Client, u *store.User, ac *store.AuthCode, jkt string) (*store.Family, string, error) {
	now := p.now()
	set := p.Settings.Get()
	id, err := uuid.NewV7()
	if err != nil {
		return nil, "", err
	}
	tok := crypto.RandomToken(32)
	f := &store.Family{
		ID: id, ClientID: cl.ID, UserID: u.ID, Scopes: ac.Scopes, Resource: ac.Resource,
		CurrentHash: crypto.SHA256(tok), CurrentIssuedAt: now, Generation: 1, AuthTime: ac.AuthTime, AMR: ac.AMR,
		DPoPJKT: jkt, CreatedAt: now, LastUsedAt: now, LastIP: c.RealIP(), UserAgent: truncate(c.Request().UserAgent(), 255),
		IDPV: u.ProfileVersion,
	}
	f.SID = ac.SID
	if slices.Contains(ac.Scopes, ScopeOffline) {
		f.Offline = true
		f.AbsExpiresAt = now.Add(set.RefreshAbsTTL())
	} else {
		// Bound to the SSO session: dies with it and never outlives it.
		sess, err := store.GetSessionBySID(ctx, tx, ac.SID)
		if err != nil {
			return nil, "", err
		}
		f.AbsExpiresAt = sess.AbsExpiresAt
	}
	f.IdleExpiresAt = minTime(now.Add(set.RefreshIdleTTL()), f.AbsExpiresAt)
	f.CurrentEnc = p.refreshBox.Seal([]byte(tok), familyAAD(f.ID, f.Generation))
	if err := store.InsertFamily(ctx, tx, f); err != nil {
		return nil, "", err
	}
	return f, tok, nil
}

func familyAAD(id uuid.UUID, gen int) []byte {
	b := append([]byte("rt:"), id[:]...)
	return append(b, byte(gen>>24), byte(gen>>16), byte(gen>>8), byte(gen))
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func (p *Provider) buildResponse(in tokenInput, refreshToken string, withID bool) (*tokenResponse, *Error) {
	at, ttl, _, err := p.mintAccess(in)
	if err != nil {
		return nil, errServer("签发令牌失败")
	}
	resp := &tokenResponse{AccessToken: at, TokenType: "Bearer", ExpiresIn: int64(ttl.Seconds()),
		RefreshToken: refreshToken, Scope: strings.Join(in.scopes, " ")}
	if withID && in.user != nil {
		if resp.IDToken, err = p.mintID(in, at); err != nil {
			return nil, errServer("签发令牌失败")
		}
	}
	return resp, nil
}

// refresh implements rotation with an idempotent grace window:
//   - presenting the current token rotates it;
//   - presenting an ancestor rotated within the grace window (same client,
//     same DPoP key) returns the current token again, so concurrent tabs,
//     processes and network retries all converge on one result;
//   - presenting an older ancestor revokes this family only.
func (p *Provider) refresh(c *echo.Context, cl *store.Client, jkt string) (*tokenResponse, *Error) {
	ctx := c.Request().Context()
	presented := c.FormValue("refresh_token")
	if presented == "" || len(presented) > 128 {
		return nil, errInvalidGrant("缺少或无效的 refresh_token")
	}
	var narrowed []string
	if s := c.FormValue("scope"); s != "" {
		narrowed = parseScopes(s)
	}
	h := crypto.SHA256(presented)
	grace := p.Cfg.Tokens.RefreshGrace.Duration
	var resp *tokenResponse
	var oerr *Error
	err := p.DB.Tx(ctx, sql.LevelReadCommitted, func(tx *sql.Tx) error {
		resp, oerr = nil, nil
		now := p.now()
		ancestor := false
		var rotatedAt time.Time
		f, ss, err := store.LockFamilyByCurrentHash(ctx, tx, h)
		if errors.Is(err, store.ErrNotFound) {
			// Not current: maybe an ancestor (rotated, possibly just now by a
			// concurrent request that held the lock before us).
			fid, at, herr := store.HistoryLookup(ctx, tx, h)
			if errors.Is(herr, store.ErrNotFound) {
				oerr = errInvalidGrant("刷新令牌无效")
				return nil
			}
			if herr != nil {
				return herr
			}
			ancestor, rotatedAt = true, at
			f, ss, err = store.LockFamilyByID(ctx, tx, fid)
		}
		if errors.Is(err, store.ErrNotFound) {
			oerr = errInvalidGrant("刷新令牌无效")
			return nil
		}
		if err != nil {
			return err
		}
		switch {
		case f.RevokedAt != nil:
			oerr = errInvalidGrant("刷新令牌已被吊销")
		case f.ClientID != cl.ID:
			oerr = errInvalidGrant("刷新令牌不属于该应用")
		case now.After(f.IdleExpiresAt) || now.After(f.AbsExpiresAt):
			oerr = errInvalidGrant("刷新令牌已过期")
		case f.DPoPJKT != "" && f.DPoPJKT != jkt:
			oerr = errInvalidDPoP("刷新令牌绑定的 DPoP 密钥不匹配")
		}
		if oerr != nil {
			return nil
		}
		// Disabling or deleting a user, revoking a grant and ending a session
		// all revoke the affected families in the database, so the cached user
		// and computed subject are sufficient here.
		user, err := p.cachedUser(ctx, tx, f.UserID)
		if errors.Is(err, store.ErrNotFound) || (err == nil && !user.IsActive()) {
			_ = store.RevokeFamily(ctx, tx, f.ID, "user_unavailable", now)
			oerr = errInvalidGrant("用户不可用")
			return nil
		}
		if err != nil {
			return err
		}
		if !f.Offline && f.SID != "" && !ss.Valid(now) {
			_ = store.RevokeFamily(ctx, tx, f.ID, "session_ended", now)
			oerr = errInvalidGrant("登录会话已结束")
			return nil
		}
		if ss.Valid(now) && now.Sub(ss.LastSeenAt) > 5*time.Minute {
			// A refreshing device counts as activity on its session.
			_ = store.TouchSession(ctx, tx, ss.ID, now, now.Add(p.Settings.Get().SessionIdleTTL()), c.RealIP())
		}
		g := struct{ Sub string }{Sub: p.Subject(cl, user)}
		// Scopes: what the family holds, still allowed for the client, narrowed on request.
		scopes := slices.DeleteFunc(slices.Clone(f.Scopes), func(s string) bool { return !cl.AllowsScope(s) })
		if narrowed != nil {
			for _, s := range narrowed {
				if !slices.Contains(scopes, s) {
					oerr = errInvalidScope("不能扩大 scope: " + s)
					return nil
				}
			}
			scopes = narrowed
		}
		in := tokenInput{client: cl, user: user, sub: g.Sub, scopes: scopes, sid: f.SID,
			authTime: f.AuthTime, amr: strings.Fields(f.AMR), resource: f.Resource}

		var token string
		// A new ID token is only minted when the profile changed since the
		// last one this family received (OIDC Core 12.2 makes it optional).
		withID := false
		if ancestor {
			if now.Sub(rotatedAt) > grace || f.CurrentEnc == nil || now.Sub(f.CurrentIssuedAt) > grace {
				if err := store.RevokeFamily(ctx, tx, f.ID, "reuse_detected", now); err != nil {
					return err
				}
				p.Log.Warn("refresh token reuse detected; family revoked", "client", cl.ID, "family", f.ID.String())
				_ = store.InsertAudit(ctx, tx, &store.AuditEntry{At: now, ActorClientID: cl.ID, Action: "security.refresh_reuse",
					TargetType: "user", TargetID: user.PublicSub, IP: c.RealIP(), Meta: map[string]any{"family": f.ID.String()}})
				oerr = errInvalidGrant("刷新令牌已被使用")
				return nil
			}
			pt, err := p.refreshBox.Open(f.CurrentEnc, familyAAD(f.ID, f.Generation))
			if err != nil {
				return err
			}
			token = string(pt)
			httpx.Metrics.Inc("refresh_grace_hits_total")
		} else {
			token = crypto.RandomToken(32)
			f.CurrentHash = crypto.SHA256(token)
			f.Generation++
			f.CurrentEnc = p.refreshBox.Seal([]byte(token), familyAAD(f.ID, f.Generation))
			f.CurrentIssuedAt = now
			f.IdleExpiresAt = minTime(now.Add(p.Settings.Get().RefreshIdleTTL()), f.AbsExpiresAt)
			f.LastUsedAt = now
			f.LastIP = c.RealIP()
			f.UserAgent = truncate(c.Request().UserAgent(), 255)
			if slices.Contains(scopes, ScopeOpenID) && user.ProfileVersion != f.IDPV {
				withID, f.IDPV = true, user.ProfileVersion
			}
			if err := store.RotateFamily(ctx, tx, f, h, now); err != nil {
				return err
			}
		}
		resp, oerr = p.buildResponse(in, token, withID)
		return nil
	})
	if err != nil {
		p.Log.Error("refresh failed", "err", err)
		return nil, errTemporarilyUnavailable("服务暂时不可用，请重试")
	}
	return resp, oerr
}

func (p *Provider) clientCredentials(c *echo.Context, cl *store.Client) (*tokenResponse, *Error) {
	if cl.IsPublic() {
		return nil, errUnauthorizedClient("公共客户端不能使用 client_credentials")
	}
	scopes := parseScopes(c.FormValue("scope"))
	for _, s := range scopes {
		info, ok := scopeInfo(s)
		if !ok || info.UserScope || !cl.AllowsScope(s) {
			return nil, errInvalidScope("不允许的 scope: " + s)
		}
	}
	in := tokenInput{client: cl, sub: cl.ID, scopes: scopes}
	return p.buildResponse(in, "", false)
}

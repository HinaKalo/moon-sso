package oidc

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v5"

	"moon-sso/server/internal/auth"
	"moon-sso/server/internal/crypto"
	"moon-sso/server/internal/store"
	"moon-sso/server/internal/ui"
)

// AuthzRequest is a validated authorization request.
type AuthzRequest struct {
	ClientID            string   `json:"c"`
	RedirectURI         string   `json:"r"`
	ResponseMode        string   `json:"m,omitempty"`
	Scopes              []string `json:"s"`
	State               string   `json:"st,omitempty"`
	Nonce               string   `json:"n,omitempty"`
	CodeChallenge       string   `json:"cc"`
	CodeChallengeMethod string   `json:"ccm"`
	Prompt              []string `json:"p,omitempty"`
	MaxAge              *int     `json:"ma,omitempty"`
	IDTokenHint         string   `json:"-"`
	LoginHint           string   `json:"lh,omitempty"`
	Resource            string   `json:"res,omitempty"`
	DPoPJKT             string   `json:"jkt,omitempty"`
	LoginAfter          int64    `json:"la,omitempty"`
}

func (r *AuthzRequest) hasPrompt(p string) bool { return slices.Contains(r.Prompt, p) }

// rawParams returns the request parameters from the query (GET) or form (POST).
func rawParams(c *echo.Context) url.Values {
	if c.Request().Method == http.MethodPost {
		if v, err := c.FormValues(); err == nil {
			return v
		}
	}
	return c.QueryParams()
}

func (p *Provider) Authorize(c *echo.Context) error {
	q := rawParams(c)
	for k, v := range q {
		if len(v) > 1 && k != "resource" {
			return p.authzPageError(c, "参数 "+k+" 重复出现")
		}
	}
	if q.Get("request") != "" || q.Get("request_uri") != "" {
		return p.authzPageError(c, "不支持 request 对象")
	}
	cl, err := p.Client(c.Request().Context(), q.Get("client_id"))
	if err != nil || !cl.IsActive() {
		if err == nil && cl.Status == store.ClientPending {
			return p.authzPageError(c, "该应用尚未通过管理员审核，暂时无法登录")
		}
		return p.authzPageError(c, "应用不存在或已停用（client_id 无效）")
	}
	redirectURI := q.Get("redirect_uri")
	if !MatchRedirect(cl, redirectURI) {
		return p.authzPageError(c, "回调地址未在该应用中登记（redirect_uri 不匹配）")
	}
	req := &AuthzRequest{ClientID: cl.ID, RedirectURI: redirectURI, State: q.Get("state"), ResponseMode: q.Get("response_mode")}
	fail := func(code, desc string) error { return p.authzRedirectError(c, req, code, desc) }

	if len(req.State) > 2048 {
		req.State = ""
		return fail("invalid_request", "state 过长")
	}
	switch req.ResponseMode {
	case "", "query", "form_post":
	default:
		req.ResponseMode = ""
		return fail("invalid_request", "不支持的 response_mode")
	}
	if q.Get("response_type") != "code" {
		return fail("unsupported_response_type", "仅支持 response_type=code")
	}
	if !cl.HasGrant(GrantAuthCode) {
		return fail("unauthorized_client", "该应用未启用授权码模式")
	}
	req.Scopes = parseScopes(q.Get("scope"))
	if len(req.Scopes) == 0 {
		return fail("invalid_scope", "缺少 scope")
	}
	if e := checkUserScopes(cl, req.Scopes); e != nil {
		return fail(e.Code, e.Description)
	}
	req.CodeChallenge, req.CodeChallengeMethod = q.Get("code_challenge"), q.Get("code_challenge_method")
	if req.CodeChallenge == "" {
		return fail("invalid_request", "必须使用 PKCE（缺少 code_challenge）")
	}
	if req.CodeChallengeMethod != "S256" {
		return fail("invalid_request", "code_challenge_method 必须为 S256")
	}
	if n := len(req.CodeChallenge); n < 43 || n > 128 {
		return fail("invalid_request", "code_challenge 长度无效")
	}
	req.Nonce = q.Get("nonce")
	if len(req.Nonce) > 255 {
		return fail("invalid_request", "nonce 过长")
	}
	for _, pv := range strings.Fields(q.Get("prompt")) {
		switch pv {
		case "none", "login", "consent", "select_account":
			req.Prompt = append(req.Prompt, pv)
		default:
			return fail("invalid_request", "不支持的 prompt: "+pv)
		}
	}
	if req.hasPrompt("none") && len(req.Prompt) > 1 {
		return fail("invalid_request", "prompt=none 不能与其他值同时使用")
	}
	if ma := q.Get("max_age"); ma != "" {
		v, err := strconv.Atoi(ma)
		if err != nil || v < 0 {
			return fail("invalid_request", "max_age 无效")
		}
		req.MaxAge = &v
	}
	req.IDTokenHint = q.Get("id_token_hint")
	req.LoginHint = q.Get("login_hint")
	if len(req.LoginHint) > 64 {
		req.LoginHint = ""
	}
	if res := q["resource"]; len(res) > 0 {
		if len(res) > 1 {
			return fail("invalid_target", "只支持一个 resource")
		}
		u, err := url.Parse(res[0])
		if err != nil || !u.IsAbs() || u.Fragment != "" {
			return fail("invalid_target", "resource 必须是绝对 URI")
		}
		req.Resource = res[0]
	}
	req.DPoPJKT = q.Get("dpop_jkt")
	if !validJKT(req.DPoPJKT) {
		return fail("invalid_request", "dpop_jkt 无效")
	}
	if cl.RequireDPoP && req.DPoPJKT == "" {
		return fail("invalid_request", "该应用要求 DPoP 绑定（缺少 dpop_jkt）")
	}
	if la, err := strconv.ParseInt(q.Get("_la"), 10, 64); err == nil {
		req.LoginAfter = la
	}
	return p.continueAuthz(c, cl, req)
}

// authzURL rebuilds an authorization URL to resume after login or step-up.
func (p *Provider) authzURL(req *AuthzRequest, forceLoginAfter int64) string {
	v := url.Values{}
	v.Set("client_id", req.ClientID)
	v.Set("redirect_uri", req.RedirectURI)
	v.Set("response_type", "code")
	v.Set("scope", strings.Join(req.Scopes, " "))
	v.Set("code_challenge", req.CodeChallenge)
	v.Set("code_challenge_method", req.CodeChallengeMethod)
	for k, val := range map[string]string{"state": req.State, "nonce": req.Nonce, "response_mode": req.ResponseMode,
		"login_hint": req.LoginHint, "resource": req.Resource, "dpop_jkt": req.DPoPJKT, "id_token_hint": req.IDTokenHint} {
		if val != "" {
			v.Set(k, val)
		}
	}
	var prompts []string
	for _, pr := range req.Prompt {
		if pr == "consent" {
			prompts = append(prompts, pr)
		}
	}
	if len(prompts) > 0 {
		v.Set("prompt", strings.Join(prompts, " "))
	}
	if req.MaxAge != nil && forceLoginAfter == 0 {
		v.Set("max_age", strconv.Itoa(*req.MaxAge))
	}
	la := req.LoginAfter
	if forceLoginAfter > la {
		la = forceLoginAfter
	}
	if la > 0 {
		v.Set("_la", strconv.FormatInt(la, 10))
	}
	return "/oauth/authorize?" + v.Encode()
}

func (p *Provider) continueAuthz(c *echo.Context, cl *store.Client, req *AuthzRequest) error {
	ctx := c.Request().Context()
	fail := func(code, desc string) error { return p.authzRedirectError(c, req, code, desc) }
	sess, user := ui.SessionOf(c), ui.UserOf(c)
	now := p.now()
	none := req.hasPrompt("none")

	needLogin := sess == nil || user == nil
	forceAfter := int64(0)
	if !needLogin {
		if req.LoginAfter > 0 && sess.AuthTime.Unix() < req.LoginAfter {
			needLogin = true
		}
		if req.hasPrompt("login") {
			needLogin, forceAfter = true, now.Unix()
		}
		if req.MaxAge != nil && now.Sub(sess.AuthTime) > time.Duration(*req.MaxAge)*time.Second {
			needLogin, forceAfter = true, now.Unix()
		}
		if req.IDTokenHint != "" {
			hint, ok := p.parseIDTokenHint(req.IDTokenHint)
			if !ok || !hint.hasAud(cl.ID) {
				return fail("invalid_request", "id_token_hint 无效")
			}
			if hint.Sub != p.Subject(cl, user) {
				if none {
					return fail("login_required", "当前登录的账号与 id_token_hint 不一致")
				}
				needLogin, forceAfter = true, now.Unix()
			}
		}
	}
	if needLogin {
		if none {
			return fail("login_required", "需要登录")
		}
		next := p.authzURL(req, forceAfter)
		to := "/login?next=" + url.QueryEscape(next)
		if forceAfter > 0 || req.LoginAfter > 0 {
			to += "&prompt=login"
		}
		if req.LoginHint != "" {
			to += "&username=" + url.QueryEscape(req.LoginHint)
		}
		return c.Redirect(http.StatusFound, to)
	}
	if !user.IsActive() {
		return fail("access_denied", "账号已停用")
	}
	if user.MustChangePassword {
		if none {
			return fail("interaction_required", "需要先修改密码")
		}
		return c.Redirect(http.StatusFound, "/account/password/change?next="+url.QueryEscape(p.authzURL(req, 0)))
	}
	if req.hasPrompt("select_account") {
		return p.selectAccountPage(c, cl, req)
	}
	if cl.RequireAMR == "otp" && !slices.Contains(strings.Fields(sess.AMR), "otp") {
		if none {
			return fail("interaction_required", "该应用要求两步验证")
		}
		if user.HasTOTP() {
			return p.UI.BeginStepUp(c, user, p.authzURL(req, 0))
		}
		pg := p.UI.NewPage(c, "需要两步验证")
		pg.Data["Heading"] = "需要先开启两步验证"
		pg.Data["Message"] = "「" + cl.Name + "」要求账号开启两步验证。请先在账号安全页面完成绑定，然后重新进入该应用。"
		pg.Data["Action"] = "/account/security"
		pg.Data["ActionText"] = "去开启两步验证"
		return ui.Render(c, http.StatusForbidden, "notice", "", pg)
	}

	grant, err := store.GetGrant(ctx, p.DB, user.ID, cl.ID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	if p.needsConsent(cl, grant, req) {
		if none {
			return fail("consent_required", "需要用户授权")
		}
		return p.consentPage(c, cl, req, user, grant)
	}
	return p.issueCodeAndRedirect(c, cl, req, user, sess, false)
}

func (p *Provider) needsConsent(cl *store.Client, g *store.Grant, req *AuthzRequest) bool {
	if req.hasPrompt("consent") {
		return true
	}
	if cl.SkipConsent {
		return false
	}
	if g == nil || g.RevokedAt != nil {
		return true
	}
	for _, s := range req.Scopes {
		if s != ScopeOpenID && !slices.Contains(g.ConsentedScopes, s) {
			return true
		}
	}
	return false
}

func mergeScopes(a, b []string) []string {
	out := slices.Clone(a)
	for _, s := range b {
		if s != ScopeOpenID && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

func (p *Provider) issueCodeAndRedirect(c *echo.Context, cl *store.Client, req *AuthzRequest, user *store.User, sess *store.Session, consented bool) error {
	ctx := c.Request().Context()
	code := crypto.RandomToken(32)
	now := p.now()
	sub := p.Subject(cl, user)
	err := p.DB.Tx(ctx, sql.LevelReadCommitted, func(tx *sql.Tx) error {
		if err := store.InsertCode(ctx, tx, &store.AuthCode{
			CodeHash: crypto.SHA256(code), ClientID: cl.ID, UserID: user.ID, SID: sess.SID, RedirectURI: req.RedirectURI,
			Scopes: req.Scopes, Resource: req.Resource, Nonce: req.Nonce, CodeChallenge: req.CodeChallenge,
			CodeChallengeMethod: req.CodeChallengeMethod, DPoPJKT: req.DPoPJKT, AuthTime: sess.AuthTime, AMR: sess.AMR,
			ExpiresAt: now.Add(p.Cfg.Tokens.CodeTTL.Duration),
		}); err != nil {
			return err
		}
		if err := store.AddSessionClient(ctx, tx, sess.SID, cl.ID, now); err != nil {
			return err
		}
		return p.recordGrant(ctx, tx, cl, user.ID, sub, req.Scopes, consented)
	})
	if err != nil {
		return err
	}
	return p.authzRespond(c, req, url.Values{"code": {code}})
}

// recordGrant upserts the user↔client grant. Consented scopes are merged when
// the user approved them now or the client skips consent.
func (p *Provider) recordGrant(ctx context.Context, tx *sql.Tx, cl *store.Client, userID uuid.UUID, sub string, scopes []string, consented bool) error {
	g, err := store.GetGrant(ctx, tx, userID, cl.ID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	var current []string
	if g != nil && g.RevokedAt == nil {
		current = g.ConsentedScopes
	}
	if consented || cl.SkipConsent {
		current = mergeScopes(current, scopes)
	}
	return store.UpsertGrant(ctx, tx, userID, cl.ID, sub, current, p.now())
}

// authzRespond delivers parameters to the client's redirect URI.
func (p *Provider) authzRespond(c *echo.Context, req *AuthzRequest, params url.Values) error {
	params.Set("iss", p.Issuer())
	if req.State != "" {
		params.Set("state", req.State)
	}
	c.Response().Header().Set("Cache-Control", "no-store")
	if req.ResponseMode == "form_post" {
		pg := p.UI.NewPage(c, "正在返回应用")
		pg.Data["Action"] = req.RedirectURI
		fields := map[string]string{}
		for k := range params {
			fields[k] = params.Get(k)
		}
		pg.Data["Fields"] = fields
		return ui.Render(c, http.StatusOK, "form_post", "", pg)
	}
	u, err := url.Parse(req.RedirectURI)
	if err != nil {
		return err
	}
	qv := u.Query()
	for k := range params {
		qv.Set(k, params.Get(k))
	}
	u.RawQuery = qv.Encode()
	return c.Redirect(http.StatusFound, u.String())
}

func (p *Provider) authzRedirectError(c *echo.Context, req *AuthzRequest, code, desc string) error {
	return p.authzRespond(c, req, url.Values{"error": {code}, "error_description": {desc}})
}

func (p *Provider) authzPageError(c *echo.Context, msg string) error {
	pg := p.UI.NewPage(c, "授权请求无效")
	pg.Data["Heading"] = "无法继续登录"
	pg.Data["Message"] = msg
	return ui.Render(c, http.StatusBadRequest, "error", "", pg)
}

// ---- consent ----

type sealedRequest struct {
	Req  AuthzRequest `json:"q"`
	User string       `json:"u"`
	SID  string       `json:"sid"`
	Exp  int64        `json:"e"`
}

func (p *Provider) sealRequest(req *AuthzRequest, userID, sid string) string {
	b, _ := json.Marshal(sealedRequest{Req: *req, User: userID, SID: sid, Exp: p.now().Add(15 * time.Minute).Unix()})
	return crypto.B64(p.requestBox.Seal(b, []byte("authz-request")))
}

func (p *Provider) openRequest(s string) (*sealedRequest, bool) {
	raw, err := crypto.UnB64(s)
	if err != nil || len(raw) > 8192 {
		return nil, false
	}
	pt, err := p.requestBox.Open(raw, []byte("authz-request"))
	if err != nil {
		return nil, false
	}
	var sr sealedRequest
	if json.Unmarshal(pt, &sr) != nil || p.now().Unix() > sr.Exp {
		return nil, false
	}
	return &sr, true
}

type consentScope struct {
	Name        string
	Description string
	Sensitive   bool
	New         bool
}

func (p *Provider) consentPage(c *echo.Context, cl *store.Client, req *AuthzRequest, user *store.User, g *store.Grant) error {
	pg := p.UI.NewPage(c, "授权 "+cl.Name)
	var scopes []consentScope
	for _, s := range req.Scopes {
		info, _ := scopeInfo(s)
		isNew := g == nil || g.RevokedAt != nil || !slices.Contains(g.ConsentedScopes, s)
		scopes = append(scopes, consentScope{Name: s, Description: info.Description, Sensitive: info.Sensitive, New: isNew && s != ScopeOpenID})
	}
	pg.Data["Client"] = cl
	pg.Data["Scopes"] = scopes
	pg.Data["Request"] = p.sealRequest(req, user.ID.String(), ui.SessionOf(c).SID)
	pg.Data["RedirectHost"] = redirectHost(req.RedirectURI)
	return ui.Render(c, http.StatusOK, "consent", "", pg)
}

func redirectHost(r string) string {
	u, err := url.Parse(r)
	if err != nil {
		return r
	}
	if u.Host == "" {
		return r // custom scheme: show it in full so users can spot impostors
	}
	return u.Host
}

// ConsentSubmit handles approve/deny from the consent page (CSRF-protected).
func (p *Provider) ConsentSubmit(c *echo.Context) error {
	sr, ok := p.openRequest(c.FormValue("request"))
	if !ok {
		return p.authzPageError(c, "授权页面已过期，请回到应用重新登录")
	}
	user, sess := ui.UserOf(c), ui.SessionOf(c)
	if user == nil || sess == nil || user.ID.String() != sr.User || sess.SID != sr.SID {
		return p.authzPageError(c, "登录状态已变化，请回到应用重新登录")
	}
	cl, err := p.Client(c.Request().Context(), sr.Req.ClientID)
	if err != nil || !cl.IsActive() || !MatchRedirect(cl, sr.Req.RedirectURI) {
		return p.authzPageError(c, "应用不存在或已停用")
	}
	req := &sr.Req
	if c.FormValue("decision") != "approve" {
		p.UI.Audit(c, user, "oauth.consent_denied", map[string]any{"client": cl.ID})
		return p.authzRedirectError(c, req, "access_denied", "用户拒绝了授权")
	}
	p.UI.Audit(c, user, "oauth.consent_granted", map[string]any{"client": cl.ID, "scope": strings.Join(req.Scopes, " ")})
	return p.issueCodeAndRedirect(c, cl, req, user, sess, true)
}

// ---- account selection ----

func (p *Provider) selectAccountPage(c *echo.Context, cl *store.Client, req *AuthzRequest) error {
	pg := p.UI.NewPage(c, "选择账号")
	req2 := *req
	req2.Prompt = slices.DeleteFunc(slices.Clone(req.Prompt), func(s string) bool { return s == "select_account" })
	pg.Data["Client"] = cl
	pg.Data["Continue"] = p.authzURL(&req2, 0)
	return ui.Render(c, http.StatusOK, "select_account", "", pg)
}

// SwitchAccount ends the current session and returns to login with next.
func (p *Provider) SwitchAccount(c *echo.Context) error {
	next := ui.SafeNext(c.FormValue("next"))
	if sess := ui.SessionOf(c); sess != nil {
		if err := p.EndSession(c.Request().Context(), sess, "switch_account"); err != nil {
			return err
		}
	}
	c.SetCookie(p.UI.Cookies.Clear(auth.SessionCookie))
	return ui.Redirect(c, "/login?next="+url.QueryEscape(next))
}

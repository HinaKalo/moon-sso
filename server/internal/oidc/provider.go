// Package oidc implements the OAuth 2.x / OpenID Connect endpoints:
// discovery, JWKS, authorization (with consent and step-up), token
// (authorization_code + PKCE, rotating refresh tokens with a grace window,
// client_credentials), DPoP, first-party challenge, userinfo, revocation,
// introspection, RP-initiated and back-channel logout.
package oidc

import (
	"context"
	"crypto/hmac"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v5"

	"moon-sso/server/internal/account"
	"moon-sso/server/internal/auth"
	"moon-sso/server/internal/cache"
	"moon-sso/server/internal/config"
	"moon-sso/server/internal/crypto"
	"moon-sso/server/internal/db"
	"moon-sso/server/internal/keys"
	"moon-sso/server/internal/settings"
	"moon-sso/server/internal/store"
	"moon-sso/server/internal/ui"
)

// Scopes understood by the server.
const (
	ScopeOpenID        = "openid"
	ScopeProfile       = "profile"
	ScopeOffline       = "offline_access"
	ScopeProfileWrite  = "profile:write"
	ScopePasswordWrite = "password:write"
	ScopeUsersSync     = "users:sync" // client_credentials only
)

type ScopeInfo struct {
	Name        string
	Description string
	Sensitive   bool
	UserScope   bool // requestable through the authorization endpoint
}

var Scopes = []ScopeInfo{
	{ScopeOpenID, "确认你的身份", false, true},
	{ScopeProfile, "读取你的用户名、昵称和头像", false, true},
	{ScopeOffline, "保持长期登录（你离开后也能自动续期）", false, true},
	{ScopeProfileWrite, "修改你的用户名、昵称和头像", true, true},
	{ScopePasswordWrite, "修改你的登录密码（需要验证当前密码）", true, true},
	{ScopeUsersSync, "同步已授权用户的资料变更", false, false},
}

func scopeInfo(name string) (ScopeInfo, bool) {
	for _, s := range Scopes {
		if s.Name == name {
			return s, true
		}
	}
	return ScopeInfo{}, false
}

// APIScopes grant access to the /api/v1 audience.
var APIScopes = []string{ScopeProfileWrite, ScopePasswordWrite, ScopeUsersSync}

// GrantTypes supported by the token endpoint.
const (
	GrantAuthCode          = "authorization_code"
	GrantRefresh           = "refresh_token"
	GrantClientCredentials = "client_credentials"
)

type Provider struct {
	Cfg      *config.Config
	DB       *db.DB
	Keys     *keys.Manager
	Keyring  *crypto.Keyring
	Settings *settings.Service
	Sessions *auth.Sessions
	Accounts *account.Service
	UI       *ui.Handler
	Log      *slog.Logger
	Now      func() time.Time

	// WakeEvents nudges the outbox sequencer and back-channel worker.
	WakeEvents func()

	clients      *cache.Cache[string, *store.Client]
	subjects     *cache.Cache[string, uuid.UUID]
	revokedJTI   *cache.Cache[string, struct{}]
	refreshBox   *crypto.Sealer
	requestBox   *crypto.Sealer
	secretKey    []byte
	pairwiseKey  []byte
	dpop         *DPoP
	challengeLim *auth.Limiter
	throttle     *auth.Throttle
	nativeRegLim *auth.Limiter
}

func New(p *Provider) *Provider {
	p.clients = cache.New[string, *store.Client](5000, time.Minute)
	p.subjects = cache.New[string, uuid.UUID](100_000, 10*time.Minute)
	p.revokedJTI = cache.New[string, struct{}](100_000, time.Hour)
	p.refreshBox = p.Keyring.Sealer(crypto.PurposeRefreshAEAD)
	p.requestBox = p.Keyring.Sealer(crypto.PurposeCookieAEAD)
	p.secretKey = p.Keyring.Key(crypto.PurposeTokenHMAC)
	p.pairwiseKey = p.Keyring.Key(crypto.PurposePairwise)
	p.dpop = NewDPoP(p.Keyring.Key(crypto.PurposeDPoPNonce))
	p.challengeLim = auth.NewLimiter(30, 15)
	p.nativeRegLim = auth.NewLimiter(0.5, 5)
	p.throttle = auth.NewThrottle()
	if p.Now == nil {
		p.Now = time.Now
	}
	return p
}

func (p *Provider) now() time.Time { return p.Now().UTC() }

func (p *Provider) Issuer() string      { return p.Cfg.Issuer() }
func (p *Provider) APIAudience() string { return p.Cfg.Issuer() + "/api" }

// RelaxLimits removes rate limits (testbed only).
func (p *Provider) RelaxLimits() {
	p.challengeLim = auth.NewLimiter(1e6, 1_000_000)
	p.nativeRegLim = auth.NewLimiter(1e6, 1_000_000)
}

// GC trims in-memory limiters.
func (p *Provider) GC() {
	p.challengeLim.GC()
	p.nativeRegLim.GC()
	p.throttle.GC()
}

// ---- clients ----

// Client returns an active-or-not client by id with a short cache.
func (p *Provider) Client(ctx context.Context, id string) (*store.Client, error) {
	if id == "" || len(id) > 64 {
		return nil, store.ErrNotFound
	}
	if c, ok := p.clients.Get(id); ok {
		return c, nil
	}
	c, err := store.GetClient(ctx, p.DB, id)
	if err != nil {
		return nil, err
	}
	p.clients.Set(id, c)
	return c, nil
}

// InvalidateClient drops a cached client after an admin change.
func (p *Provider) InvalidateClient(id string) { p.clients.Delete(id) }

// HashSecret returns the stored form of a client secret or registration token.
func (p *Provider) HashSecret(secret string) []byte {
	m := hmacSHA256(p.secretKey, []byte(secret))
	return m
}

func hmacSHA256(key, data []byte) []byte {
	m := hmac.New(sha256New, key)
	m.Write(data)
	return m.Sum(nil)
}

// AuthenticateClient implements client_secret_basic, client_secret_post and
// "none" for public clients.
func (p *Provider) AuthenticateClient(c *echo.Context) (*store.Client, *Error) {
	r := c.Request()
	id, secret, basic := r.BasicAuth()
	if basic {
		var err1, err2 error
		id, err1 = url.QueryUnescape(id)
		secret, err2 = url.QueryUnescape(secret)
		if err1 != nil || err2 != nil {
			return nil, errInvalidClient("Basic 认证格式错误")
		}
		if fid := c.FormValue("client_id"); fid != "" && fid != id {
			return nil, errInvalidRequest("client_id 不一致")
		}
	} else {
		id = c.FormValue("client_id")
		secret = c.FormValue("client_secret")
	}
	if id == "" {
		return nil, errInvalidClient("缺少客户端认证")
	}
	cl, err := p.Client(r.Context(), id)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, errTemporarilyUnavailable("服务暂时不可用，请稍后重试")
	}
	if err != nil {
		return nil, errInvalidClient("客户端认证失败")
	}
	switch cl.Status {
	case store.ClientActive:
	case store.ClientPending:
		return nil, errInvalidClient("应用尚未通过管理员审核")
	default:
		return nil, errInvalidClient("应用已停用")
	}
	if cl.IsPublic() {
		if secret != "" {
			return nil, errInvalidClient("公共客户端不能使用密钥")
		}
		return cl, nil
	}
	if secret == "" || len(cl.SecretHash) == 0 || !hmac.Equal(p.HashSecret(secret), cl.SecretHash) {
		return nil, errInvalidClient("客户端认证失败")
	}
	return cl, nil
}

// MatchRedirect checks redirect_uri by exact string comparison, except that
// native clients may use any port on a loopback redirect (RFC 8252 §7.3).
func MatchRedirect(c *store.Client, uri string) bool {
	if uri == "" || len(uri) > 2000 {
		return false
	}
	for _, r := range c.RedirectURIs {
		if r == uri {
			return true
		}
		if c.ApplicationType == "native" && loopbackEqual(r, uri) {
			return true
		}
	}
	return false
}

func isLoopbackHost(h string) bool { return h == "127.0.0.1" || h == "::1" || h == "localhost" }

func loopbackEqual(registered, got string) bool {
	a, err1 := url.Parse(registered)
	b, err2 := url.Parse(got)
	if err1 != nil || err2 != nil || a.Scheme != "http" || b.Scheme != "http" {
		return false
	}
	if !isLoopbackHost(a.Hostname()) || a.Hostname() != b.Hostname() {
		return false
	}
	return a.Path == b.Path && a.RawQuery == b.RawQuery && b.Fragment == "" && b.User == nil
}

// Subject returns the identifier a client sees for a user: the public sub for
// clients configured as "public", otherwise a pairwise value per sector.
func (p *Provider) Subject(c *store.Client, u *store.User) string {
	if c.SubjectType == "public" {
		return u.PublicSub
	}
	return p.pairwise(c, u.ID)
}

func (p *Provider) pairwise(c *store.Client, uid uuid.UUID) string {
	sector := c.SectorID
	if sector == "" {
		sector = c.ID
	}
	mac := hmacSHA256(p.pairwiseKey, append([]byte(sector+"\x00"), uid[:]...))
	return base64.RawURLEncoding.EncodeToString(mac[:16])
}

// SubjectForUserID is used when rendering events for a recipient.
func (p *Provider) SubjectForUserID(c *store.Client, uid uuid.UUID, publicSub string) string {
	if c.SubjectType == "public" {
		return publicSub
	}
	return p.pairwise(c, uid)
}

// UserIDForSubject maps (client, sub) back to the internal user id.
func (p *Provider) UserIDForSubject(ctx context.Context, clientID, sub string) (uuid.UUID, error) {
	key := clientID + "\x00" + sub
	if id, ok := p.subjects.Get(key); ok {
		return id, nil
	}
	id, err := store.UserBySubject(ctx, p.DB, clientID, sub)
	if err != nil {
		return id, err
	}
	p.subjects.Set(key, id)
	return id, nil
}

// ForgetSubjects drops cached subject mappings for a client (after revocation).
func (p *Provider) ForgetSubjects(clientID string, uid uuid.UUID) {
	p.subjects.DeleteFunc(func(k string, v uuid.UUID) bool {
		return v == uid && (clientID == "" || strings.HasPrefix(k, clientID+"\x00"))
	})
}

// ---- scopes ----

func parseScopes(s string) []string {
	var out []string
	for _, f := range strings.Fields(s) {
		if !slices.Contains(out, f) {
			out = append(out, f)
		}
	}
	return out
}

// checkUserScopes validates scopes requested through authorize/challenge.
func checkUserScopes(c *store.Client, scopes []string) *Error {
	for _, s := range scopes {
		info, ok := scopeInfo(s)
		if !ok || !info.UserScope {
			return errInvalidScope("不支持的 scope: " + s)
		}
		if !c.AllowsScope(s) {
			return errInvalidScope("该应用未被允许申请 scope: " + s)
		}
	}
	return nil
}

func hasAny(scopes []string, set []string) bool {
	for _, s := range scopes {
		if slices.Contains(set, s) {
			return true
		}
	}
	return false
}

// ---- CORS for browser-based public clients ----

// originAllowed reports whether origin belongs to one of the client's web redirect URIs.
func originAllowed(c *store.Client, origin string) bool {
	if c == nil || origin == "" {
		return false
	}
	for _, r := range c.RedirectURIs {
		u, err := url.Parse(r)
		if err != nil || u.Host == "" {
			continue
		}
		if u.Scheme+"://"+u.Host == origin {
			return true
		}
	}
	return false
}

func (p *Provider) setCORS(c *echo.Context, cl *store.Client) {
	origin := c.Request().Header.Get("Origin")
	if originAllowed(cl, origin) {
		h := c.Response().Header()
		h.Set("Access-Control-Allow-Origin", origin)
		h.Set("Access-Control-Expose-Headers", "DPoP-Nonce, WWW-Authenticate, ETag, Retry-After")
		h.Add("Vary", "Origin")
	}
}

// CORS sets CORS headers for a response to the given client's origin.
func (p *Provider) CORS(c *echo.Context, cl *store.Client) { p.setCORS(c, cl) }

// Preflight answers CORS preflight requests. The real response only carries
// Access-Control-Allow-Origin when the origin belongs to the calling client.
func Preflight(c *echo.Context) error {
	h := c.Response().Header()
	if o := c.Request().Header.Get("Origin"); o != "" {
		h.Set("Access-Control-Allow-Origin", o)
		h.Add("Vary", "Origin")
	}
	h.Set("Access-Control-Allow-Methods", "GET, POST, PATCH, PUT, DELETE, OPTIONS")
	h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, DPoP, Last-Event-ID, Idempotency-Key, If-Match, If-None-Match")
	h.Set("Access-Control-Max-Age", "600")
	return c.NoContent(http.StatusNoContent)
}

// originSet caches the origins of all active clients' web redirect URIs, so
// error responses (sent before the calling client is known) can carry CORS
// headers and browsers see the real 401 instead of a network error.
type originSet struct {
	mu      sync.RWMutex
	origins map[string]bool
	loaded  time.Time
}

var allowedOrigins = &originSet{}

func (p *Provider) originKnown(ctx context.Context, origin string) bool {
	allowedOrigins.mu.RLock()
	fresh := time.Since(allowedOrigins.loaded) < time.Minute
	ok := allowedOrigins.origins[origin]
	allowedOrigins.mu.RUnlock()
	if fresh {
		return ok
	}
	rows, err := p.DB.QueryContext(ctx, "SELECT redirect_uris FROM clients WHERE status=1")
	if err != nil {
		return ok
	}
	defer rows.Close()
	set := map[string]bool{}
	for rows.Next() {
		var raw []byte
		if rows.Scan(&raw) != nil {
			continue
		}
		var uris []string
		_ = json.Unmarshal(raw, &uris)
		for _, r := range uris {
			if u, err := url.Parse(r); err == nil && u.Host != "" && (u.Scheme == "https" || u.Scheme == "http") {
				set[u.Scheme+"://"+u.Host] = true
			}
		}
	}
	allowedOrigins.mu.Lock()
	allowedOrigins.origins, allowedOrigins.loaded = set, time.Now()
	allowedOrigins.mu.Unlock()
	return set[origin]
}

// APICORS adds CORS headers to every response of a browser-callable API when
// the Origin belongs to a registered client, including error responses.
func (p *Provider) APICORS() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			if o := c.Request().Header.Get("Origin"); o != "" && p.originKnown(c.Request().Context(), o) {
				h := c.Response().Header()
				h.Set("Access-Control-Allow-Origin", o)
				h.Set("Access-Control-Expose-Headers", "DPoP-Nonce, WWW-Authenticate, ETag, Retry-After")
				h.Add("Vary", "Origin")
			}
			return next(c)
		}
	}
}

// PublicCORS allows any origin for public, credential-less resources.
func PublicCORS() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			c.Response().Header().Set("Access-Control-Allow-Origin", "*")
			return next(c)
		}
	}
}

// ---- token revocation helpers used by account and logout flows ----

// RevokeUserTokens revokes sessions and refresh families of a user (except
// keepSID) inside tx and queues back-channel logouts.
func (p *Provider) RevokeUserTokens(ctx context.Context, tx *sql.Tx, userID uuid.UUID, keepSID, reason string) error {
	now := p.now()
	sids, err := auth.RevokeAllForUser(ctx, tx, userID, keepSID, now)
	if err != nil {
		return err
	}
	if err := store.RevokeFamilies(ctx, tx, userID, "", "", keepSID, reason, now); err != nil {
		return err
	}
	for _, sid := range sids {
		if err := p.queueBackchannel(ctx, tx, userID, sid); err != nil {
			return err
		}
	}
	return nil
}

func (p *Provider) queueBackchannel(ctx context.Context, q db.Querier, userID uuid.UUID, sid string) error {
	clients, err := store.SessionClients(ctx, q, sid)
	if err != nil {
		return err
	}
	now := p.now()
	for _, cid := range clients {
		cl, ok := p.clients.Get(cid)
		if !ok {
			// Read through the caller's transaction (see cachedUser).
			c, err := store.GetClient(ctx, q, cid)
			if err != nil {
				continue
			}
			cl = c
		}
		if cl.BackchannelLogoutURI == "" {
			continue
		}
		if err := store.InsertBackchannelJob(ctx, q, cid, userID, sid, now); err != nil {
			return err
		}
	}
	return nil
}

// EndSession revokes one browser/device session, its refresh families and
// notifies participating clients. Safe to call more than once. Removing a
// device (reason "device_removed") also kills its offline_access tokens;
// an ordinary logout leaves them, as OIDC intends for offline access.
func (p *Provider) EndSession(ctx context.Context, sess *store.Session, reason string) error {
	err := p.DB.Tx(ctx, sql.LevelReadCommitted, func(tx *sql.Tx) error {
		now := p.now()
		if _, err := store.RevokeSession(ctx, tx, sess.SID, now); err != nil {
			return err
		}
		if err := store.RevokeSessionFamilies(ctx, tx, sess.SID, reason, reason == "device_removed", now); err != nil {
			return err
		}
		return p.queueBackchannel(ctx, tx, sess.UserID, sess.SID)
	})
	if err != nil {
		return err
	}
	_ = p.Sessions.Revoke(ctx, p.DB, sess.SID)
	if p.WakeEvents != nil {
		p.WakeEvents()
	}
	return nil
}

// LogoutTokenFor implements events.LogoutSigner.
func (p *Provider) LogoutTokenFor(ctx context.Context, clientID string, userID uuid.UUID, sid string) (string, string, error) {
	cl, err := p.Client(ctx, clientID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return "", "", nil
		}
		return "", "", err
	}
	if cl.BackchannelLogoutURI == "" {
		return "", "", nil
	}
	publicSub := ""
	if u, err := store.GetUser(ctx, p.DB, userID); err == nil {
		publicSub = u.PublicSub
	} else if err := p.DB.QueryRowContext(ctx, "SELECT public_sub FROM user_tombstones WHERE id=?", userID[:]).Scan(&publicSub); err != nil {
		return "", "", err
	}
	tok, err := p.mintLogoutToken(cl, p.SubjectForUserID(cl, userID, publicSub), sid)
	return tok, cl.BackchannelLogoutURI, err
}

// RevokeGrant withdraws a user's authorization of a client: the grant is
// revoked, the client's refresh families die and the client is told through
// a consent.revoked event.
func (p *Provider) RevokeGrant(ctx context.Context, userID uuid.UUID, clientID string, actor account.Actor) error {
	err := p.DB.Tx(ctx, sql.LevelReadCommitted, func(tx *sql.Tx) error {
		now := p.now()
		ok, err := store.RevokeGrant(ctx, tx, userID, clientID, now)
		if err != nil || !ok {
			return err
		}
		if err := store.RevokeFamilies(ctx, tx, userID, clientID, "", "", "consent_revoked", now); err != nil {
			return err
		}
		u, err := store.GetUser(ctx, tx, userID)
		if err != nil {
			return err
		}
		if err := store.InsertEvent(ctx, tx, account.EventConsentRevoked, &u.ID, account.SnapshotOf(u, nil), []string{clientID}, now); err != nil {
			return err
		}
		return store.InsertAudit(ctx, tx, &store.AuditEntry{At: now, ActorUserID: actor.UserID, ActorClientID: actor.ClientID,
			Action: "user.consent_revoked", TargetType: "client", TargetID: clientID, IP: actor.IP})
	})
	if err != nil {
		return err
	}
	p.ForgetSubjects(clientID, userID)
	if p.WakeEvents != nil {
		p.WakeEvents()
	}
	return nil
}

// cachedUser returns a user from the shared 30-second cache (invalidated on
// every change made through the account service). q must be the caller's
// transaction when one is open: taking a second pooled connection while
// holding one can exhaust the pool under load and deadlock.
func (p *Provider) cachedUser(ctx context.Context, q db.Querier, id uuid.UUID) (*store.User, error) {
	if u, ok := p.UI.Users.Get(id); ok {
		return u, nil
	}
	u, err := store.GetUser(ctx, q, id)
	if err != nil {
		return nil, err
	}
	p.UI.Users.Set(id, u)
	return u, nil
}

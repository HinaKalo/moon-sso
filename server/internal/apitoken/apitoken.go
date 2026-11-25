// Package apitoken issues and verifies long-lived API tokens for terminals,
// scripts and CI.
//
// Two kinds exist and never mix:
//   - developer tokens (msso_dev_…), owned by an SSO user and accepted only on
//     the public host under /api/v1/developer;
//   - console tokens (msso_adm_…), owned by a console administrator and
//     accepted only on the admin host under /api/v1.
//
// Tokens are 256-bit random values; only an HMAC is stored. Every token has
// scopes, a mandatory expiry and an optional IP allowlist, and can be rotated
// with a grace period during which the old token keeps working.
package apitoken

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v5"

	"moon-sso/server/internal/auth"
	"moon-sso/server/internal/crypto"
	"moon-sso/server/internal/db"
	"moon-sso/server/internal/httpx"
	"moon-sso/server/internal/store"
)

const (
	PrefixDeveloper = "msso_dev_"
	PrefixConsole   = "msso_adm_"

	MaxActivePerOwner = 20
	MaxGrace          = 7 * 24 * time.Hour
	touchEvery        = time.Minute
	hashPurpose       = "moon-sso/api-token/v1"
)

// Scope describes one permission a token may carry.
type Scope struct {
	Name  string
	Label string
}

// Developer token scopes (public host).
var DeveloperScopes = []Scope{
	{"apps:read", "查看我的应用"},
	{"apps:write", "创建、修改、删除我的应用，轮换密钥，测试 Webhook"},
}

// Console token scopes (admin host).
var ConsoleScopes = []Scope{
	{"stats:read", "查看总览统计"},
	{"users:read", "查看 SSO 用户"},
	{"users:write", "创建、停用、启用、重置、删除 SSO 用户，结束会话"},
	{"clients:read", "查看应用和 Webhook 投递"},
	{"clients:write", "创建、修改、审核、停用、删除应用，轮换密钥，重投死信"},
	{"settings:read", "查看系统设置"},
	{"settings:write", "修改系统设置（含自助注册开关）"},
	{"audit:read", "查看审计日志"},
}

// Lifetimes offered in the UI and accepted by the API (days).
var (
	DeveloperLifetimes = []int{7, 30, 90, 180, 365}
	ConsoleLifetimes   = []int{1, 7, 30, 90}
)

func ScopesFor(kind int) []Scope {
	if kind == store.TokenConsole {
		return ConsoleScopes
	}
	return DeveloperScopes
}

func LifetimesFor(kind int) []int {
	if kind == store.TokenConsole {
		return ConsoleLifetimes
	}
	return DeveloperLifetimes
}

func maxLifetime(kind int) time.Duration {
	l := LifetimesFor(kind)
	return time.Duration(l[len(l)-1]) * 24 * time.Hour
}

func prefixFor(kind int) string {
	if kind == store.TokenConsole {
		return PrefixConsole
	}
	return PrefixDeveloper
}

// HasScope reports whether granted covers need; a ":write" scope implies ":read".
func HasScope(granted []string, need string) bool {
	if need == "" || slices.Contains(granted, need) {
		return true
	}
	if res, ok := strings.CutSuffix(need, ":read"); ok {
		return slices.Contains(granted, res+":write")
	}
	return false
}

var (
	ErrInvalid   = errors.New("api token invalid")
	ErrLimit     = fmt.Errorf("每个账号最多同时持有 %d 个有效令牌，请先吊销不用的令牌", MaxActivePerOwner)
	ErrNotActive = errors.New("令牌已吊销或已过期")
)

// FieldError is a validation failure on one input field.
type FieldError struct{ Field, Msg string }

func (e *FieldError) Error() string { return e.Msg }

// Service issues and verifies tokens.
type Service struct {
	DB      *db.DB
	Keyring *crypto.Keyring
	Log     *slog.Logger
	Now     func() time.Time

	limiters map[int]*auth.Limiter
	failures *auth.Limiter
}

func New(s *Service) *Service {
	if s.Now == nil {
		s.Now = time.Now
	}
	s.limiters = map[int]*auth.Limiter{
		store.TokenDeveloper: auth.NewLimiter(600, 120),  // per token: 10 req/s sustained
		store.TokenConsole:   auth.NewLimiter(1200, 240), // per token: 20 req/s sustained
	}
	s.failures = auth.NewLimiter(60, 30) // per IP: rejected tokens
	return s
}

// GC trims in-memory limiters.
func (s *Service) GC() {
	for _, l := range s.limiters {
		l.GC()
	}
	s.failures.GC()
}

// RelaxLimits removes rate limits (tests and testbed only).
func (s *Service) RelaxLimits() {
	for k := range s.limiters {
		s.limiters[k] = auth.NewLimiter(1e6, 1_000_000)
	}
	s.failures = auth.NewLimiter(1e6, 1_000_000)
}

func (s *Service) hash(tok string) []byte { return s.Keyring.MAC(hashPurpose, []byte(tok)) }

// Request is what an owner asks for when issuing a token.
type Request struct {
	Kind         int
	OwnerID      uuid.UUID
	Name         string
	Scopes       []string
	Lifetime     time.Duration
	AllowedCIDRs []string
	IP           string
	OwnerName    string // for the audit log
}

// Normalize validates and canonicalizes a request.
func (r *Request) Normalize() error {
	r.Name = strings.TrimSpace(r.Name)
	if r.Name == "" || len([]rune(r.Name)) > 64 {
		return &FieldError{"name", "名称长度需在 1–64 个字符之间"}
	}
	allowed := ScopesFor(r.Kind)
	var scopes []string
	for _, sc := range r.Scopes {
		sc = strings.TrimSpace(sc)
		if sc == "" || slices.Contains(scopes, sc) {
			continue
		}
		if !slices.ContainsFunc(allowed, func(a Scope) bool { return a.Name == sc }) {
			return &FieldError{"scopes", "不支持的权限：" + sc}
		}
		scopes = append(scopes, sc)
	}
	if len(scopes) == 0 {
		return &FieldError{"scopes", "至少选择一个权限"}
	}
	slices.Sort(scopes)
	r.Scopes = scopes
	if r.Lifetime < time.Hour || r.Lifetime > maxLifetime(r.Kind) {
		return &FieldError{"expires_in_days", fmt.Sprintf("有效期需在 1 小时到 %d 天之间", int(maxLifetime(r.Kind).Hours()/24))}
	}
	cidrs, err := ParseCIDRs(r.AllowedCIDRs)
	if err != nil {
		return err
	}
	r.AllowedCIDRs = cidrs
	return nil
}

// ParseCIDRs accepts IPs and CIDR prefixes (IPv4 and IPv6), at most 16.
func ParseCIDRs(in []string) ([]string, error) {
	var out []string
	for _, raw := range in {
		for _, f := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\r' || r == '\t' }) {
			var p netip.Prefix
			if strings.Contains(f, "/") {
				pp, err := netip.ParsePrefix(f)
				if err != nil {
					return nil, &FieldError{"allowed_ips", "无效的 IP 或网段：" + f}
				}
				p = pp.Masked()
			} else {
				a, err := netip.ParseAddr(f)
				if err != nil {
					return nil, &FieldError{"allowed_ips", "无效的 IP 或网段：" + f}
				}
				p = netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen())
			}
			if s := p.String(); !slices.Contains(out, s) {
				out = append(out, s)
			}
		}
	}
	if len(out) > 16 {
		return nil, &FieldError{"allowed_ips", "最多 16 个 IP 或网段"}
	}
	return out, nil
}

func ipAllowed(cidrs []string, ip string) bool {
	if len(cidrs) == 0 {
		return true
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap()
	for _, c := range cidrs {
		if p, err := netip.ParsePrefix(c); err == nil && p.Contains(a) {
			return true
		}
	}
	return false
}

func newSecret(kind int) (tok, hint string) {
	body := crypto.RandomToken(32)
	return prefixFor(kind) + body, prefixFor(kind) + body[:4] + "…" + body[len(body)-4:]
}

// Issue creates a token and returns its plaintext (shown once).
func (s *Service) Issue(ctx context.Context, r Request, a Actor) (string, *store.APIToken, error) {
	if err := r.Normalize(); err != nil {
		return "", nil, err
	}
	now := s.Now().UTC()
	tok, hint := newSecret(r.Kind)
	t := &store.APIToken{ID: uuid.Must(uuid.NewV7()), Kind: r.Kind, OwnerID: r.OwnerID, Name: r.Name, Scopes: r.Scopes,
		TokenHash: s.hash(tok), Hint: hint, AllowedCIDRs: r.AllowedCIDRs, CreatedAt: now, CreatedIP: r.IP, ExpiresAt: now.Add(r.Lifetime),
		OwnerName: r.OwnerName, OwnerStatus: store.UserActive}
	err := s.DB.Tx(ctx, sql.LevelReadCommitted, func(tx *sql.Tx) error {
		n, err := store.CountActiveAPITokens(ctx, tx, r.Kind, r.OwnerID, now)
		if err != nil {
			return err
		}
		if n >= MaxActivePerOwner {
			return ErrLimit
		}
		if err := store.InsertAPIToken(ctx, tx, t); err != nil {
			return err
		}
		return a.audit(ctx, tx, "api_token.created", t, map[string]any{"name": t.Name, "scopes": t.Scopes, "expires_at": t.ExpiresAt,
			"allowed_ips": t.AllowedCIDRs, "kind": kindName(t.Kind), "owner": r.OwnerName})
	})
	if err != nil {
		return "", nil, err
	}
	return tok, t, nil
}

// Rotate issues a successor with the same name, scopes and allowlist and a
// fresh lifetime equal to the original one. The old token keeps working for
// grace (0 = revoked immediately), never beyond its own expiry.
func (s *Service) Rotate(ctx context.Context, id uuid.UUID, grace time.Duration, a Actor) (string, *store.APIToken, error) {
	if grace < 0 || grace > MaxGrace {
		return "", nil, &FieldError{"grace_seconds", "宽限期需在 0 到 7 天之间"}
	}
	now := s.Now().UTC()
	var out *store.APIToken
	var plain string
	err := s.DB.Tx(ctx, sql.LevelReadCommitted, func(tx *sql.Tx) error {
		old, err := store.GetAPITokenForUpdate(ctx, tx, id)
		if err != nil {
			return err
		}
		if !old.Active(now) || old.ReplacedBy != nil {
			return ErrNotActive
		}
		// The successor gets the lifetime the owner originally picked.
		life := min(max(old.ExpiresAt.Sub(old.CreatedAt), time.Hour), maxLifetime(old.Kind))
		tok, hint := newSecret(old.Kind)
		oldID := old.ID
		t := &store.APIToken{ID: uuid.Must(uuid.NewV7()), Kind: old.Kind, OwnerID: old.OwnerID, Name: old.Name, Scopes: old.Scopes,
			TokenHash: s.hash(tok), Hint: hint, AllowedCIDRs: old.AllowedCIDRs, CreatedAt: now, CreatedIP: a.IP,
			ExpiresAt: now.Add(life), RotatedFrom: &oldID}
		if err := store.InsertAPIToken(ctx, tx, t); err != nil {
			return err
		}
		if grace == 0 {
			if _, err := store.RevokeAPIToken(ctx, tx, old.ID, "rotated", now); err != nil {
				return err
			}
		}
		if err := store.MarkAPITokenReplaced(ctx, tx, old.ID, t.ID, now.Add(grace)); err != nil {
			return err
		}
		t.OwnerName, t.OwnerStatus = old.OwnerName, old.OwnerStatus
		if err := a.audit(ctx, tx, "api_token.rotated", old, map[string]any{"name": old.Name, "successor": t.ID.String(),
			"grace_seconds": int(grace.Seconds()), "kind": kindName(old.Kind), "owner": old.OwnerName}); err != nil {
			return err
		}
		out, plain = t, tok
		return nil
	})
	if err != nil {
		return "", nil, err
	}
	return plain, out, nil
}

// Revoke ends a token immediately.
func (s *Service) Revoke(ctx context.Context, id uuid.UUID, reason string, a Actor) error {
	now := s.Now().UTC()
	return s.DB.Tx(ctx, sql.LevelReadCommitted, func(tx *sql.Tx) error {
		t, err := store.GetAPITokenForUpdate(ctx, tx, id)
		if err != nil {
			return err
		}
		ok, err := store.RevokeAPIToken(ctx, tx, id, reason, now)
		if err != nil {
			return err
		}
		if !ok {
			return ErrNotActive
		}
		return a.audit(ctx, tx, "api_token.revoked", t, map[string]any{"name": t.Name, "reason": reason, "kind": kindName(t.Kind), "owner": t.OwnerName})
	})
}

// Actor is who performed a token lifecycle action, for the audit log.
type Actor struct {
	UserID *uuid.UUID // SSO user (developer)
	Admin  string     // console administrator username
	Via    string     // "token:…" when done through the API with a token
	IP     string
}

func (a Actor) audit(ctx context.Context, q db.Querier, action string, t *store.APIToken, meta map[string]any) error {
	return store.InsertAudit(ctx, q, &store.AuditEntry{At: time.Now().UTC(), ActorUserID: a.UserID, ActorAdmin: a.Admin, ActorClientID: a.Via,
		Action: action, TargetType: "api_token", TargetID: t.ID.String(), IP: a.IP, Meta: meta})
}

func kindName(kind int) string {
	if kind == store.TokenConsole {
		return "console"
	}
	return "developer"
}

// Principal is an authenticated API token.
type Principal struct {
	Token *store.APIToken
}

// Actor tag used in audit entries for actions made with a token.
func (p *Principal) Tag() string { return "token:" + p.Token.ID.String()[:13] }

func (p *Principal) Has(scope string) bool { return HasScope(p.Token.Scopes, scope) }

// Error is a JSON API error.
type Error struct {
	Status int
	Code   string
	Desc   string
}

func (e *Error) Error() string { return e.Desc }

// WriteError renders an API error in the shared {"error","error_description"} shape.
func WriteError(c *echo.Context, status int, code, desc string) error {
	switch status {
	case http.StatusUnauthorized:
		c.Response().Header().Set("WWW-Authenticate", `Bearer realm="moon-sso", error="`+code+`"`)
	}
	if err := c.JSON(status, map[string]string{"error": code, "error_description": desc}); err != nil {
		return err
	}
	return httpx.ErrResponded
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

// Middleware authenticates requests with a token of the given kind and
// enforces expiry, revocation, owner status, IP allowlist and rate limits.
func (s *Service) Middleware(kind int) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			p, err := s.authenticate(c, kind)
			if err != nil {
				var ae *Error
				if errors.As(err, &ae) {
					return WriteError(c, ae.Status, ae.Code, ae.Desc)
				}
				return err
			}
			c.Set("api_token", p)
			return next(c)
		}
	}
}

// PrincipalOf returns the token set by Middleware.
func PrincipalOf(c *echo.Context) *Principal { p, _ := c.Get("api_token").(*Principal); return p }

// Require rejects requests whose token lacks scope.
func Require(scope string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			if p := PrincipalOf(c); p == nil || !p.Has(scope) {
				c.Response().Header().Set("WWW-Authenticate", `Bearer realm="moon-sso", error="insufficient_scope", scope="`+scope+`"`)
				return WriteError(c, http.StatusForbidden, "insufficient_scope", "令牌缺少权限："+scope)
			}
			return next(c)
		}
	}
}

func (s *Service) authenticate(c *echo.Context, kind int) (*Principal, error) {
	ip := c.RealIP()
	tok := bearer(c.Request())
	if tok == "" {
		return nil, &Error{http.StatusUnauthorized, "invalid_token", "缺少 Authorization: Bearer <API 令牌>"}
	}
	if !s.failures.Peek(ip) {
		c.Response().Header().Set("Retry-After", "60")
		return nil, &Error{http.StatusTooManyRequests, "rate_limited", "无效令牌尝试过多，请稍后再试"}
	}
	fail := func(desc string) error {
		s.failures.Allow(ip)
		return &Error{http.StatusUnauthorized, "invalid_token", desc}
	}
	want := prefixFor(kind)
	if !strings.HasPrefix(tok, want) {
		if strings.HasPrefix(tok, PrefixDeveloper) || strings.HasPrefix(tok, PrefixConsole) {
			return nil, fail("该令牌不能用于此站点：开发者令牌请调用 sso 域名，控制台令牌请调用 sso-admin 域名")
		}
		return nil, fail("令牌格式无效")
	}
	if len(tok) > 128 {
		return nil, fail("令牌格式无效")
	}
	ctx := c.Request().Context()
	t, err := store.GetAPITokenByHash(ctx, s.DB, s.hash(tok))
	if errors.Is(err, store.ErrNotFound) {
		return nil, fail("令牌无效")
	}
	if err != nil {
		c.Response().Header().Set("Retry-After", "3")
		return nil, &Error{http.StatusServiceUnavailable, "temporarily_unavailable", "服务暂时不可用，请稍后重试"}
	}
	now := s.Now().UTC()
	switch {
	case t.Kind != kind:
		return nil, fail("令牌无效")
	case t.RevokedAt != nil:
		return nil, fail("令牌已被吊销")
	case !now.Before(t.ExpiresAt):
		return nil, fail("令牌已过期")
	case t.OwnerStatus != store.UserActive:
		return nil, fail("令牌所属账号已停用或不存在")
	case !ipAllowed(t.AllowedCIDRs, ip):
		return nil, &Error{http.StatusForbidden, "ip_not_allowed", "当前 IP（" + ip + "）不在该令牌的 IP 白名单内"}
	}
	if ok, wait := s.limiters[kind].Allow(t.ID.String()); !ok {
		c.Response().Header().Set("Retry-After", strconv.Itoa(max(1, int(wait.Seconds()+0.5))))
		return nil, &Error{http.StatusTooManyRequests, "rate_limited", "请求过于频繁，请稍后再试"}
	}
	if t.LastUsedAt == nil || now.Sub(*t.LastUsedAt) >= touchEvery || t.LastUsedIP != ip {
		if err := store.TouchAPIToken(ctx, s.DB, t.ID, truncIP(ip), now); err != nil {
			s.Log.Warn("api token touch failed", "err", err)
		}
	}
	h := c.Response().Header()
	h.Set("Moon-Token-Expires-At", t.ExpiresAt.UTC().Format(time.RFC3339))
	h.Set("Moon-Token-Expires-Soon", strconv.FormatBool(t.ExpiresSoon(now))) // clients warn and suggest rotation when true
	if t.ReplacedBy != nil {
		h.Set("Moon-Token-Rotated", "true") // superseded: switch to the new token before the grace period ends
	}
	return &Principal{Token: t}, nil
}

func truncIP(ip string) string {
	if net.ParseIP(ip) == nil || len(ip) > 45 {
		return ""
	}
	return ip
}

// View is the JSON representation of a token (never the secret).
type View struct {
	ID          string     `json:"id"`
	Kind        string     `json:"kind"`
	Name        string     `json:"name"`
	Owner       string     `json:"owner"`
	Hint        string     `json:"hint"`
	Scopes      []string   `json:"scopes"`
	AllowedIPs  []string   `json:"allowed_ips"`
	Status      string     `json:"status"`
	ExpiresSoon bool       `json:"expires_soon"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   time.Time  `json:"expires_at"`
	LastUsedAt  *time.Time `json:"last_used_at"`
	LastUsedIP  string     `json:"last_used_ip,omitempty"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
	RotatedFrom string     `json:"rotated_from,omitempty"`
	ReplacedBy  string     `json:"replaced_by,omitempty"`
}

func ViewOf(t *store.APIToken, now time.Time) View {
	v := View{ID: t.ID.String(), Kind: kindName(t.Kind),
		Name: t.Name, Owner: t.OwnerName, Hint: t.Hint, Scopes: t.Scopes, AllowedIPs: t.AllowedCIDRs, Status: t.State(now), ExpiresSoon: t.ExpiresSoon(now),
		CreatedAt: t.CreatedAt, ExpiresAt: t.ExpiresAt, LastUsedAt: t.LastUsedAt, LastUsedIP: t.LastUsedIP, RevokedAt: t.RevokedAt}
	if v.Scopes == nil {
		v.Scopes = []string{}
	}
	if v.AllowedIPs == nil {
		v.AllowedIPs = []string{}
	}
	if t.RotatedFrom != nil {
		v.RotatedFrom = t.RotatedFrom.String()
	}
	if t.ReplacedBy != nil {
		v.ReplacedBy = t.ReplacedBy.String()
	}
	return v
}

// Views converts a list for templates and JSON.
func Views(list []*store.APIToken, now time.Time) []View {
	out := make([]View, 0, len(list))
	for _, t := range list {
		out = append(out, ViewOf(t, now))
	}
	return out
}

// RequestFromForm reads the shared token form fields (name, scopes, days, allowed_ips).
func RequestFromForm(kind int, owner uuid.UUID, ownerName string, form map[string][]string, ip string) Request {
	first := func(k string) string {
		if v := form[k]; len(v) > 0 {
			return v[0]
		}
		return ""
	}
	days, _ := strconv.Atoi(first("days"))
	return Request{Kind: kind, OwnerID: owner, OwnerName: ownerName, Name: first("name"), Scopes: form["scopes"],
		Lifetime: time.Duration(days) * 24 * time.Hour, AllowedCIDRs: []string{first("allowed_ips")}, IP: ip}
}

// GraceChoices are the rotation grace periods offered in the UI.
var GraceChoices = []struct {
	Seconds int
	Label   string
}{{0, "立即失效"}, {3600, "1 小时"}, {86400, "24 小时"}, {604800, "7 天"}}

// IssuedView adds the plaintext token, returned exactly once.
type IssuedView struct {
	View
	Token string `json:"token"`
}

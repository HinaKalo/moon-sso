// Package clients manages OAuth client registrations: validation of
// metadata, credentials, lifecycle (pending → active → disabled) and the
// RFC 7591/7592 dynamic registration endpoints.
package clients

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"moon-sso/server/internal/account"
	"moon-sso/server/internal/crypto"
	"moon-sso/server/internal/db"
	"moon-sso/server/internal/feed"
	"moon-sso/server/internal/oidc"
	"moon-sso/server/internal/safehttp"
	"moon-sso/server/internal/settings"
	"moon-sso/server/internal/store"
)

type Service struct {
	DB       *db.DB
	OIDC     *oidc.Provider
	Feed     *feed.Feed
	Settings *settings.Service
	Log      *slog.Logger
}

// Metadata is what a developer (or DCR request) may set.
type Metadata struct {
	Name                   string
	Description            string
	LogoURI                string
	ClientURI              string
	PolicyURI              string
	TOSURI                 string
	ApplicationType        string // web | native
	AuthMethod             string // client_secret_basic | client_secret_post | none
	RedirectURIs           []string
	PostLogoutRedirectURIs []string
	GrantTypes             []string
	Scopes                 []string
	IDTokenAlg             string
	BackchannelLogoutURI   string
	WebhookURL             string
	WebhookEvents          []string
	RequireDPoP            bool
}

// AdminFlags may only be set by administrators.
type AdminFlags struct {
	FirstParty           bool
	NativeLogin          bool
	SkipConsent          bool
	AllowRegistration    bool
	Verified             bool
	RequireAMR           string
	SubjectType          string
	WebhookAllowInsecure bool
	AccessTokenTTL       *int
}

type Credentials struct {
	ClientSecret      string
	RegistrationToken string
	WebhookSecret     string
}

var EventTypes = []string{account.EventUserUpdated, account.EventUserPasswordChanged, account.EventUserDisabled,
	account.EventUserEnabled, account.EventUserDeleted, account.EventConsentRevoked}

func ferr(field, msg string) error { return &account.FieldError{Field: field, Msg: msg} }

func validURI(raw string, allowHTTPLoopback, allowPrivateScheme bool) bool {
	if raw == "" || len(raw) > 500 {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Fragment != "" || u.User != nil {
		return false
	}
	switch u.Scheme {
	case "https":
		return u.Host != ""
	case "http":
		h := u.Hostname()
		return allowHTTPLoopback && (h == "127.0.0.1" || h == "::1" || h == "localhost")
	case "javascript", "data", "file", "vbscript", "about", "blob":
		return false
	default:
		// Private-use URI schemes must be reverse-domain (RFC 8252 §7.1).
		return allowPrivateScheme && strings.Contains(u.Scheme, ".") && u.Host == ""
	}
}

// Normalize applies defaults and validates metadata. admin relaxes nothing
// security-relevant except allowing insecure webhook URLs via flags.
func (s *Service) Normalize(m *Metadata, flags *AdminFlags) error {
	m.Name = strings.TrimSpace(m.Name)
	if m.Name == "" || len([]rune(m.Name)) > 60 {
		return ferr("name", "应用名称长度需在 1–60 个字符之间")
	}
	if len([]rune(m.Description)) > 300 {
		return ferr("description", "简介最多 300 个字符")
	}
	if m.ApplicationType == "" {
		m.ApplicationType = "web"
	}
	if m.ApplicationType != "web" && m.ApplicationType != "native" {
		return ferr("application_type", "应用类型只能是 web 或 native")
	}
	switch m.AuthMethod {
	case "":
		m.AuthMethod = "client_secret_basic"
	case "client_secret_basic", "client_secret_post", "none":
	default:
		return ferr("token_endpoint_auth_method", "不支持的客户端认证方式")
	}
	public := m.AuthMethod == "none"
	if len(m.GrantTypes) == 0 {
		m.GrantTypes = []string{oidc.GrantAuthCode, oidc.GrantRefresh}
	}
	for _, g := range m.GrantTypes {
		switch g {
		case oidc.GrantAuthCode, oidc.GrantRefresh:
		case oidc.GrantClientCredentials:
			if public {
				return ferr("grant_types", "公共客户端不能使用 client_credentials")
			}
		default:
			return ferr("grant_types", "不支持的授权类型: "+g)
		}
	}
	m.GrantTypes = slices.Compact(m.GrantTypes)
	needsRedirect := slices.Contains(m.GrantTypes, oidc.GrantAuthCode)
	if needsRedirect && len(m.RedirectURIs) == 0 {
		return ferr("redirect_uris", "至少需要一个回调地址")
	}
	if len(m.RedirectURIs) > 20 || len(m.PostLogoutRedirectURIs) > 20 {
		return ferr("redirect_uris", "回调地址最多 20 个")
	}
	native := m.ApplicationType == "native"
	for _, r := range m.RedirectURIs {
		if !validURI(r, true, native) {
			return ferr("redirect_uris", "回调地址无效："+r+"（web 应用需使用 https，原生应用可用回环地址或反向域名的自定义 scheme）")
		}
	}
	for _, r := range m.PostLogoutRedirectURIs {
		if !validURI(r, true, native) {
			return ferr("post_logout_redirect_uris", "退出回调地址无效："+r)
		}
	}
	if len(m.Scopes) == 0 {
		m.Scopes = []string{oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeOffline}
	}
	for _, sc := range m.Scopes {
		known := false
		for _, info := range oidc.Scopes {
			if info.Name == sc {
				known = true
			}
		}
		if !known {
			return ferr("scope", "不支持的 scope: "+sc)
		}
		if sc == oidc.ScopeUsersSync && (public || !slices.Contains(m.GrantTypes, oidc.GrantClientCredentials)) {
			return ferr("scope", "users:sync 需要机密客户端并启用 client_credentials")
		}
	}
	m.Scopes = slices.Compact(m.Scopes)
	if m.IDTokenAlg == "" {
		m.IDTokenAlg = "RS256"
	}
	if m.IDTokenAlg != "RS256" && m.IDTokenAlg != "ES256" {
		return ferr("id_token_signed_response_alg", "仅支持 RS256 或 ES256")
	}
	for _, u := range []struct{ field, v string }{{"logo_uri", m.LogoURI}, {"client_uri", m.ClientURI}, {"policy_uri", m.PolicyURI}, {"tos_uri", m.TOSURI}} {
		if u.v != "" && !validURI(u.v, false, false) {
			return ferr(u.field, "地址必须是 https URL")
		}
	}
	insecure := flags != nil && flags.WebhookAllowInsecure
	if m.WebhookURL != "" && !insecure {
		if err := safehttp.ValidateURL(m.WebhookURL, false); err != nil {
			return ferr("webhook_url", "Webhook 地址："+err.Error())
		}
	}
	if m.BackchannelLogoutURI != "" && !insecure {
		if err := safehttp.ValidateURL(m.BackchannelLogoutURI, false); err != nil {
			return ferr("backchannel_logout_uri", "登出通知地址："+err.Error())
		}
	}
	if len(m.WebhookEvents) == 0 {
		m.WebhookEvents = []string{"*"}
	}
	for _, ev := range m.WebhookEvents {
		if ev != "*" && !slices.Contains(EventTypes, ev) {
			return ferr("webhook_events", "未知的事件类型: "+ev)
		}
	}
	return nil
}

func applyMetadata(c *store.Client, m *Metadata) {
	c.Name, c.Description, c.LogoURI, c.ClientURI, c.PolicyURI, c.TOSURI = m.Name, m.Description, m.LogoURI, m.ClientURI, m.PolicyURI, m.TOSURI
	c.ApplicationType, c.TokenEndpointAuthMethod = m.ApplicationType, m.AuthMethod
	c.Type = store.ClientConfidential
	if m.AuthMethod == "none" {
		c.Type = store.ClientPublic
	}
	c.RedirectURIs, c.PostLogoutRedirectURIs, c.GrantTypes, c.Scopes = m.RedirectURIs, m.PostLogoutRedirectURIs, m.GrantTypes, m.Scopes
	c.IDTokenAlg, c.BackchannelLogoutURI, c.WebhookURL, c.WebhookEvents, c.RequireDPoP = m.IDTokenAlg, m.BackchannelLogoutURI, m.WebhookURL, m.WebhookEvents, m.RequireDPoP
}

func applyFlags(c *store.Client, f *AdminFlags) {
	c.FirstParty, c.NativeLogin, c.SkipConsent, c.AllowRegistration, c.Verified = f.FirstParty, f.NativeLogin, f.SkipConsent, f.AllowRegistration, f.Verified
	c.RequireAMR, c.WebhookAllowInsecure, c.AccessTokenTTLSeconds = f.RequireAMR, f.WebhookAllowInsecure, f.AccessTokenTTL
	if f.SubjectType == "public" || f.SubjectType == "pairwise" {
		c.SubjectType = f.SubjectType
	}
}

// MetadataOf extracts the editable metadata of an existing client.
func MetadataOf(c *store.Client) Metadata {
	return Metadata{Name: c.Name, Description: c.Description, LogoURI: c.LogoURI, ClientURI: c.ClientURI, PolicyURI: c.PolicyURI,
		TOSURI: c.TOSURI, ApplicationType: c.ApplicationType, AuthMethod: c.TokenEndpointAuthMethod, RedirectURIs: c.RedirectURIs,
		PostLogoutRedirectURIs: c.PostLogoutRedirectURIs, GrantTypes: c.GrantTypes, Scopes: c.Scopes, IDTokenAlg: c.IDTokenAlg,
		BackchannelLogoutURI: c.BackchannelLogoutURI, WebhookURL: c.WebhookURL, WebhookEvents: c.WebhookEvents, RequireDPoP: c.RequireDPoP}
}

func FlagsOf(c *store.Client) AdminFlags {
	return AdminFlags{FirstParty: c.FirstParty, NativeLogin: c.NativeLogin, SkipConsent: c.SkipConsent, AllowRegistration: c.AllowRegistration,
		Verified: c.Verified, RequireAMR: c.RequireAMR, SubjectType: c.SubjectType, WebhookAllowInsecure: c.WebhookAllowInsecure,
		AccessTokenTTL: c.AccessTokenTTLSeconds}
}

var ErrQuota = errors.New("已达到可创建应用的数量上限")

// Create registers a client. owner is the developer (nil for admin-created).
// Self-registered clients are pending when the registration mode requires approval.
func (s *Service) Create(ctx context.Context, m Metadata, flags *AdminFlags, owner *uuid.UUID, byAdmin bool, actor account.Actor) (*store.Client, *Credentials, error) {
	if err := s.Normalize(&m, flags); err != nil {
		return nil, nil, err
	}
	set := s.Settings.Get()
	if !byAdmin {
		if set.ClientRegistration == settings.ClientRegClosed {
			return nil, nil, ferr("", "管理员已关闭应用自助注册")
		}
		if owner != nil && set.MaxClientsPerDeveloper > 0 {
			_, n, err := store.ListClients(ctx, s.DB, store.ClientFilter{Owner: owner, Limit: 1})
			if err != nil {
				return nil, nil, err
			}
			if n >= set.MaxClientsPerDeveloper {
				return nil, nil, ErrQuota
			}
		}
	}
	now := time.Now().UTC()
	c := &store.Client{ID: "ms_" + crypto.RandomToken(15), SubjectType: "pairwise", AllowRegistration: byAdmin,
		Status: store.ClientActive, OwnerUserID: owner, CreatedAt: now, UpdatedAt: now}
	applyMetadata(c, &m)
	if flags != nil && byAdmin {
		applyFlags(c, flags)
	}
	if !byAdmin && set.ClientRegistration == settings.ClientRegApproval {
		c.Status = store.ClientPending
	}
	creds := &Credentials{RegistrationToken: "rat_" + crypto.RandomToken(32)}
	c.RATHash = s.OIDC.HashSecret(creds.RegistrationToken)
	if !c.IsPublic() {
		creds.ClientSecret = "mss_" + crypto.RandomToken(32)
		c.SecretHash = s.OIDC.HashSecret(creds.ClientSecret)
		c.SecretRotatedAt = &now
	}
	if c.WebhookURL != "" {
		creds.WebhookSecret, c.WebhookSecretEnc = s.Feed.NewWebhookSecret(c.ID)
	}
	err := s.DB.Tx(ctx, sql.LevelReadCommitted, func(tx *sql.Tx) error {
		if err := store.InsertClient(ctx, tx, c); err != nil {
			return err
		}
		// New endpoints start at the current head of the event stream.
		if _, err := tx.ExecContext(ctx, "UPDATE clients SET webhook_cursor_seq=(SELECT COALESCE(MAX(seq),0) FROM outbox_events) WHERE id=?", c.ID); err != nil {
			return err
		}
		return audit(ctx, tx, actor, "client.created", c.ID, map[string]any{"name": c.Name, "status": c.Status, "by_admin": byAdmin})
	})
	if err != nil {
		return nil, nil, err
	}
	return c, creds, nil
}

func audit(ctx context.Context, q db.Querier, a account.Actor, action, clientID string, meta map[string]any) error {
	return store.InsertAudit(ctx, q, &store.AuditEntry{At: time.Now().UTC(), ActorUserID: a.UserID, ActorClientID: a.ClientID, ActorAdmin: a.AdminName,
		Action: action, TargetType: "client", TargetID: clientID, IP: a.IP, Meta: meta})
}

// Update rewrites metadata (and admin flags when flags != nil). A newly set
// webhook URL generates a secret which is returned once.
func (s *Service) Update(ctx context.Context, id string, m Metadata, flags *AdminFlags, actor account.Actor) (*store.Client, string, error) {
	if err := s.Normalize(&m, flags); err != nil {
		return nil, "", err
	}
	var out *store.Client
	var newSecret string
	err := s.DB.Tx(ctx, sql.LevelReadCommitted, func(tx *sql.Tx) error {
		c, err := store.GetClient(ctx, tx, id)
		if err != nil {
			return err
		}
		wasPublic := c.IsPublic()
		hadWebhook := c.WebhookURL != ""
		applyMetadata(c, &m)
		if flags != nil {
			applyFlags(c, flags)
		}
		if wasPublic != c.IsPublic() {
			return ferr("token_endpoint_auth_method", "创建后不能在公共客户端和机密客户端之间切换")
		}
		if c.WebhookURL != "" && (!hadWebhook || len(c.WebhookSecretEnc) == 0) {
			newSecret, c.WebhookSecretEnc = s.Feed.NewWebhookSecret(c.ID)
		}
		c.UpdatedAt = time.Now().UTC()
		if err := store.UpdateClient(ctx, tx, c); err != nil {
			return err
		}
		if c.WebhookURL != "" && !hadWebhook {
			if _, err := tx.ExecContext(ctx, "UPDATE clients SET webhook_cursor_seq=(SELECT COALESCE(MAX(seq),0) FROM outbox_events), webhook_disabled_at=NULL WHERE id=?", c.ID); err != nil {
				return err
			}
		}
		out = c
		return audit(ctx, tx, actor, "client.updated", c.ID, nil)
	})
	if err != nil {
		return nil, "", err
	}
	s.OIDC.InvalidateClient(id)
	return out, newSecret, nil
}

func (s *Service) RotateSecret(ctx context.Context, id string, actor account.Actor) (string, error) {
	secret := "mss_" + crypto.RandomToken(32)
	now := time.Now().UTC()
	err := s.DB.Tx(ctx, sql.LevelReadCommitted, func(tx *sql.Tx) error {
		c, err := store.GetClient(ctx, tx, id)
		if err != nil {
			return err
		}
		if c.IsPublic() {
			return ferr("", "公共客户端没有密钥")
		}
		if _, err := tx.ExecContext(ctx, "UPDATE clients SET secret_hash=?, secret_rotated_at=?, updated_at=? WHERE id=?", s.OIDC.HashSecret(secret), now, now, id); err != nil {
			return err
		}
		return audit(ctx, tx, actor, "client.secret_rotated", id, nil)
	})
	if err != nil {
		return "", err
	}
	s.OIDC.InvalidateClient(id)
	return secret, nil
}

func (s *Service) RotateWebhookSecret(ctx context.Context, id string, actor account.Actor) (string, error) {
	secret, enc := s.Feed.NewWebhookSecret(id)
	err := s.DB.Tx(ctx, sql.LevelReadCommitted, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, "UPDATE clients SET webhook_secret_enc=?, updated_at=? WHERE id=?", enc, time.Now().UTC(), id); err != nil {
			return err
		}
		return audit(ctx, tx, actor, "client.webhook_secret_rotated", id, nil)
	})
	if err != nil {
		return "", err
	}
	s.OIDC.InvalidateClient(id)
	return secret, nil
}

func (s *Service) SetStatus(ctx context.Context, id string, status int, actor account.Actor) error {
	err := s.DB.Tx(ctx, sql.LevelReadCommitted, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, "UPDATE clients SET status=?, updated_at=? WHERE id=?", status, time.Now().UTC(), id); err != nil {
			return err
		}
		if status == store.ClientDisabled {
			if _, err := tx.ExecContext(ctx, "UPDATE refresh_families SET revoked_at=UTC_TIMESTAMP(3), revoke_reason='client_disabled' WHERE client_id=? AND revoked_at IS NULL", id); err != nil {
				return err
			}
		}
		return audit(ctx, tx, actor, "client.status_changed", id, map[string]any{"status": status})
	})
	if err == nil {
		s.OIDC.InvalidateClient(id)
	}
	return err
}

func (s *Service) Delete(ctx context.Context, id string, actor account.Actor) error {
	err := s.DB.Tx(ctx, sql.LevelReadCommitted, func(tx *sql.Tx) error {
		if err := store.DeleteClient(ctx, tx, id); err != nil {
			return err
		}
		return audit(ctx, tx, actor, "client.deleted", id, nil)
	})
	if err == nil {
		s.OIDC.InvalidateClient(id)
	}
	return err
}

// ---- initial access tokens ----

// NewInitialAccessToken lets a developer (or admin) authorize one dynamic registration.
func (s *Service) NewInitialAccessToken(ctx context.Context, creator uuid.UUID, uses int, ttl time.Duration, note string) (string, error) {
	tok := "iat_" + crypto.RandomToken(32)
	now := time.Now().UTC()
	_, err := s.DB.ExecContext(ctx, "INSERT INTO initial_access_tokens (token_hash, note, created_by, uses_left, expires_at, created_at) VALUES (?,?,?,?,?,?)",
		s.OIDC.HashSecret(tok), note, creator[:], uses, now.Add(ttl), now)
	return tok, err
}

// consumeIAT spends one use of an initial access token and returns its creator.
func (s *Service) consumeIAT(ctx context.Context, tok string) (*store.User, error) {
	var creator []byte
	h := s.OIDC.HashSecret(tok)
	err := s.DB.Tx(ctx, sql.LevelReadCommitted, func(tx *sql.Tx) error {
		var uses int
		var exp time.Time
		if err := tx.QueryRowContext(ctx, "SELECT created_by, uses_left, expires_at FROM initial_access_tokens WHERE token_hash=? FOR UPDATE", h).Scan(&creator, &uses, &exp); err != nil {
			return err
		}
		if uses <= 0 || time.Now().After(exp) {
			return sql.ErrNoRows
		}
		_, err := tx.ExecContext(ctx, "UPDATE initial_access_tokens SET uses_left=uses_left-1 WHERE token_hash=?", h)
		return err
	})
	if err != nil {
		return nil, err
	}
	if len(creator) != 16 {
		return nil, sql.ErrNoRows
	}
	id, _ := uuid.FromBytes(creator)
	return store.GetUser(ctx, s.DB, id)
}

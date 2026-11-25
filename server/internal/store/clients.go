package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"

	"moon-sso/server/internal/db"
)

const (
	ClientConfidential = 1
	ClientPublic       = 2

	ClientActive   = 1
	ClientPending  = 2
	ClientDisabled = 3
)

type Client struct {
	ID                      string
	Name                    string
	Description             string
	LogoURI                 string
	ClientURI               string
	PolicyURI               string
	TOSURI                  string
	Type                    int
	ApplicationType         string // web | native
	TokenEndpointAuthMethod string // client_secret_basic | client_secret_post | none
	SecretHash              []byte
	SecretRotatedAt         *time.Time
	RedirectURIs            []string
	PostLogoutRedirectURIs  []string
	GrantTypes              []string
	Scopes                  []string
	IDTokenAlg              string
	SubjectType             string // public | pairwise
	SectorID                string
	FirstParty              bool
	NativeLogin             bool
	SkipConsent             bool
	AllowRegistration       bool
	RequireAMR              string
	RequireDPoP             bool
	Verified                bool
	AccessTokenTTLSeconds   *int
	WebhookURL              string
	WebhookSecretEnc        []byte
	WebhookEvents           []string
	WebhookAllowInsecure    bool
	WebhookCursorSeq        uint64
	WebhookAttempts         int
	WebhookNextAttemptAt    *time.Time
	WebhookLastError        string
	WebhookFailSince        *time.Time
	WebhookDisabledAt       *time.Time
	BackchannelLogoutURI    string
	Status                  int
	OwnerUserID             *uuid.UUID
	RATHash                 []byte
	CreatedAt               time.Time
	UpdatedAt               time.Time
}

func (c *Client) IsPublic() bool { return c.Type == ClientPublic }
func (c *Client) IsActive() bool { return c.Status == ClientActive }

func (c *Client) HasGrant(g string) bool {
	for _, x := range c.GrantTypes {
		if x == g {
			return true
		}
	}
	return false
}

func (c *Client) AllowsScope(s string) bool {
	for _, x := range c.Scopes {
		if x == s {
			return true
		}
	}
	return false
}

func (c *Client) WantsEvent(e string) bool {
	for _, x := range c.WebhookEvents {
		if x == e || x == "*" {
			return true
		}
	}
	return false
}

const clientCols = `id, name, description, logo_uri, client_uri, policy_uri, tos_uri, client_type, application_type,
	token_endpoint_auth_method, secret_hash, secret_rotated_at, redirect_uris, post_logout_redirect_uris, grant_types,
	scopes, id_token_alg, subject_type, sector_id, first_party, native_login, skip_consent, allow_registration,
	require_amr, require_dpop, verified, access_token_ttl_s, webhook_url, webhook_secret_enc, webhook_events,
	webhook_allow_insecure, webhook_cursor_seq, webhook_attempts, webhook_next_attempt_at, webhook_last_error,
	webhook_fail_since, webhook_disabled_at, backchannel_logout_uri, status, owner_user_id, rat_hash, created_at, updated_at`

func scanClient(row interface{ Scan(...any) error }) (*Client, error) {
	var c Client
	var rot, nextAt, failSince, disabledAt sql.NullTime
	var ttl sql.NullInt64
	var redirects, postLogout, grants, events []byte
	var scopes string
	var owner []byte
	err := row.Scan(&c.ID, &c.Name, &c.Description, &c.LogoURI, &c.ClientURI, &c.PolicyURI, &c.TOSURI, &c.Type,
		&c.ApplicationType, &c.TokenEndpointAuthMethod, &c.SecretHash, &rot, &redirects, &postLogout, &grants,
		&scopes, &c.IDTokenAlg, &c.SubjectType, &c.SectorID, &c.FirstParty, &c.NativeLogin, &c.SkipConsent,
		&c.AllowRegistration, &c.RequireAMR, &c.RequireDPoP, &c.Verified, &ttl, &c.WebhookURL, &c.WebhookSecretEnc,
		&events, &c.WebhookAllowInsecure, &c.WebhookCursorSeq, &c.WebhookAttempts, &nextAt, &c.WebhookLastError,
		&failSince, &disabledAt, &c.BackchannelLogoutURI, &c.Status, &owner, &c.RATHash, &c.CreatedAt, &c.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	c.SecretRotatedAt = scanNullTime(rot)
	c.WebhookNextAttemptAt = scanNullTime(nextAt)
	c.WebhookFailSince = scanNullTime(failSince)
	c.WebhookDisabledAt = scanNullTime(disabledAt)
	if ttl.Valid {
		v := int(ttl.Int64)
		c.AccessTokenTTLSeconds = &v
	}
	_ = json.Unmarshal(redirects, &c.RedirectURIs)
	_ = json.Unmarshal(postLogout, &c.PostLogoutRedirectURIs)
	_ = json.Unmarshal(grants, &c.GrantTypes)
	_ = json.Unmarshal(events, &c.WebhookEvents)
	c.Scopes = strings.Fields(scopes)
	if len(owner) == 16 {
		id, _ := uuid.FromBytes(owner)
		c.OwnerUserID = &id
	}
	return &c, nil
}

func jsonList(v []string) []byte {
	if v == nil {
		v = []string{}
	}
	b, _ := json.Marshal(v)
	return b
}

func clientArgs(c *Client) []any {
	var owner []byte
	if c.OwnerUserID != nil {
		owner = c.OwnerUserID[:]
	}
	var ttl sql.NullInt64
	if c.AccessTokenTTLSeconds != nil {
		ttl = sql.NullInt64{Int64: int64(*c.AccessTokenTTLSeconds), Valid: true}
	}
	return []any{c.ID, c.Name, c.Description, c.LogoURI, c.ClientURI, c.PolicyURI, c.TOSURI, c.Type, c.ApplicationType,
		c.TokenEndpointAuthMethod, c.SecretHash, db.NullTime(c.SecretRotatedAt), jsonList(c.RedirectURIs),
		jsonList(c.PostLogoutRedirectURIs), jsonList(c.GrantTypes), strings.Join(c.Scopes, " "), c.IDTokenAlg,
		c.SubjectType, c.SectorID, c.FirstParty, c.NativeLogin, c.SkipConsent, c.AllowRegistration, c.RequireAMR,
		c.RequireDPoP, c.Verified, ttl, c.WebhookURL, c.WebhookSecretEnc, jsonList(c.WebhookEvents),
		c.WebhookAllowInsecure, c.WebhookCursorSeq, c.WebhookAttempts, db.NullTime(c.WebhookNextAttemptAt),
		c.WebhookLastError, db.NullTime(c.WebhookFailSince), db.NullTime(c.WebhookDisabledAt), c.BackchannelLogoutURI,
		c.Status, owner, c.RATHash, c.CreatedAt, c.UpdatedAt}
}

func InsertClient(ctx context.Context, q db.Querier, c *Client) error {
	_, err := q.ExecContext(ctx, "INSERT INTO clients ("+clientCols+") VALUES ("+placeholders(43)+")", clientArgs(c)...)
	return err
}

// UpdateClient rewrites the configuration columns. Webhook delivery state is
// owned by the dispatcher and updated separately.
func UpdateClient(ctx context.Context, q db.Querier, c *Client) error {
	var owner []byte
	if c.OwnerUserID != nil {
		owner = c.OwnerUserID[:]
	}
	var ttl sql.NullInt64
	if c.AccessTokenTTLSeconds != nil {
		ttl = sql.NullInt64{Int64: int64(*c.AccessTokenTTLSeconds), Valid: true}
	}
	_, err := q.ExecContext(ctx, `UPDATE clients SET name=?, description=?, logo_uri=?, client_uri=?, policy_uri=?, tos_uri=?,
		client_type=?, application_type=?, token_endpoint_auth_method=?, secret_hash=?, secret_rotated_at=?, redirect_uris=?,
		post_logout_redirect_uris=?, grant_types=?, scopes=?, id_token_alg=?, subject_type=?, sector_id=?, first_party=?,
		native_login=?, skip_consent=?, allow_registration=?, require_amr=?, require_dpop=?, verified=?, access_token_ttl_s=?,
		webhook_url=?, webhook_secret_enc=?, webhook_events=?, webhook_allow_insecure=?, backchannel_logout_uri=?, status=?,
		owner_user_id=?, rat_hash=?, updated_at=? WHERE id=?`,
		c.Name, c.Description, c.LogoURI, c.ClientURI, c.PolicyURI, c.TOSURI, c.Type, c.ApplicationType,
		c.TokenEndpointAuthMethod, c.SecretHash, db.NullTime(c.SecretRotatedAt), jsonList(c.RedirectURIs),
		jsonList(c.PostLogoutRedirectURIs), jsonList(c.GrantTypes), strings.Join(c.Scopes, " "), c.IDTokenAlg,
		c.SubjectType, c.SectorID, c.FirstParty, c.NativeLogin, c.SkipConsent, c.AllowRegistration, c.RequireAMR,
		c.RequireDPoP, c.Verified, ttl, c.WebhookURL, c.WebhookSecretEnc, jsonList(c.WebhookEvents),
		c.WebhookAllowInsecure, c.BackchannelLogoutURI, c.Status, owner, c.RATHash, c.UpdatedAt, c.ID)
	return err
}

func GetClient(ctx context.Context, q db.Querier, id string) (*Client, error) {
	return scanClient(q.QueryRowContext(ctx, "SELECT "+clientCols+" FROM clients WHERE id=?", id))
}

func DeleteClient(ctx context.Context, q db.Querier, id string) error {
	for _, stmt := range []string{
		"DELETE FROM grants WHERE client_id=?",
		"DELETE FROM client_events WHERE client_id=?",
		"DELETE FROM webhook_dead_letters WHERE client_id=?",
		"DELETE FROM backchannel_jobs WHERE client_id=?",
		"UPDATE refresh_families SET revoked_at=UTC_TIMESTAMP(3), revoke_reason='client_deleted' WHERE client_id=? AND revoked_at IS NULL",
		"DELETE FROM clients WHERE id=?",
	} {
		if _, err := q.ExecContext(ctx, stmt, id); err != nil {
			return err
		}
	}
	return nil
}

type ClientFilter struct {
	Query  string
	Status int
	Owner  *uuid.UUID
	Limit  int
	Offset int
}

func ListClients(ctx context.Context, q db.Querier, f ClientFilter) ([]*Client, int, error) {
	where := " WHERE 1=1"
	var args []any
	if f.Query != "" {
		where += " AND (id LIKE ? OR name LIKE ?)"
		like := "%" + escapeLike(f.Query) + "%"
		args = append(args, like, like)
	}
	if f.Status != 0 {
		where += " AND status=?"
		args = append(args, f.Status)
	}
	if f.Owner != nil {
		where += " AND owner_user_id=?"
		args = append(args, f.Owner[:])
	}
	var total int
	if err := q.QueryRowContext(ctx, "SELECT COUNT(*) FROM clients"+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	if f.Limit <= 0 || f.Limit > 200 {
		f.Limit = 50
	}
	rows, err := q.QueryContext(ctx, "SELECT "+clientCols+" FROM clients"+where+" ORDER BY created_at DESC LIMIT ? OFFSET ?", append(args, f.Limit, f.Offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []*Client
	for rows.Next() {
		c, err := scanClient(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, c)
	}
	return out, total, rows.Err()
}

func placeholders(n int) string {
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

// ---- grants ----

type Grant struct {
	UserID          uuid.UUID
	ClientID        string
	Sub             string
	ConsentedScopes []string
	CreatedAt       time.Time
	UpdatedAt       time.Time
	RevokedAt       *time.Time
}

func GetGrant(ctx context.Context, q db.Querier, userID uuid.UUID, clientID string) (*Grant, error) {
	var g Grant
	var scopes string
	var rev sql.NullTime
	err := q.QueryRowContext(ctx, "SELECT user_id, client_id, sub, consented_scopes, created_at, updated_at, revoked_at FROM grants WHERE user_id=? AND client_id=?",
		userID[:], clientID).Scan(&g.UserID, &g.ClientID, &g.Sub, &scopes, &g.CreatedAt, &g.UpdatedAt, &rev)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	g.ConsentedScopes = strings.Fields(scopes)
	g.RevokedAt = scanNullTime(rev)
	return &g, nil
}

// UpsertGrant records that a client received tokens for a user, setting the
// full consented scope list (callers merge) and reactivating a revoked grant.
func UpsertGrant(ctx context.Context, q db.Querier, userID uuid.UUID, clientID, sub string, consented []string, now time.Time) error {
	_, err := q.ExecContext(ctx, `INSERT INTO grants (user_id, client_id, sub, consented_scopes, created_at, updated_at)
		VALUES (?,?,?,?,?,?) AS n
		ON DUPLICATE KEY UPDATE sub=n.sub, consented_scopes=n.consented_scopes, updated_at=n.updated_at, revoked_at=NULL`,
		userID[:], clientID, sub, strings.Join(consented, " "), now, now)
	return err
}

// TouchGrant marks a grant as used without changing consent.
func TouchGrant(ctx context.Context, q db.Querier, userID uuid.UUID, clientID string, now time.Time) error {
	_, err := q.ExecContext(ctx, "UPDATE grants SET updated_at=? WHERE user_id=? AND client_id=?", now, userID[:], clientID)
	return err
}

func RevokeGrant(ctx context.Context, q db.Querier, userID uuid.UUID, clientID string, now time.Time) (bool, error) {
	res, err := q.ExecContext(ctx, "UPDATE grants SET revoked_at=?, consented_scopes='' WHERE user_id=? AND client_id=? AND revoked_at IS NULL", now, userID[:], clientID)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// UserBySubject maps a client-specific subject back to the internal user id.
func UserBySubject(ctx context.Context, q db.Querier, clientID, sub string) (uuid.UUID, error) {
	var id uuid.UUID
	err := q.QueryRowContext(ctx, "SELECT user_id FROM grants WHERE client_id=? AND sub=? AND revoked_at IS NULL", clientID, sub).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return id, ErrNotFound
	}
	return id, err
}

type GrantView struct {
	Grant
	ClientName string
	ClientLogo string
	ClientURI  string
	FirstParty bool
	Verified   bool
	LastUsedAt *time.Time
}

// ListUserGrants returns active grants with client display data.
func ListUserGrants(ctx context.Context, q db.Querier, userID uuid.UUID) ([]*GrantView, error) {
	rows, err := q.QueryContext(ctx, `SELECT g.user_id, g.client_id, g.sub, g.consented_scopes, g.created_at, g.updated_at,
		c.name, c.logo_uri, c.client_uri, c.first_party, c.verified,
		(SELECT MAX(f.last_used_at) FROM refresh_families f WHERE f.user_id=g.user_id AND f.client_id=g.client_id)
		FROM grants g JOIN clients c ON c.id=g.client_id
		WHERE g.user_id=? AND g.revoked_at IS NULL ORDER BY g.updated_at DESC`, userID[:])
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*GrantView
	for rows.Next() {
		var g GrantView
		var scopes string
		var last sql.NullTime
		if err := rows.Scan(&g.UserID, &g.ClientID, &g.Sub, &scopes, &g.CreatedAt, &g.UpdatedAt, &g.ClientName,
			&g.ClientLogo, &g.ClientURI, &g.FirstParty, &g.Verified, &last); err != nil {
			return nil, err
		}
		g.ConsentedScopes = strings.Fields(scopes)
		g.LastUsedAt = scanNullTime(last)
		out = append(out, &g)
	}
	return out, rows.Err()
}

func CountClientGrants(ctx context.Context, q db.Querier, clientID string) (int, error) {
	var n int
	err := q.QueryRowContext(ctx, "SELECT COUNT(*) FROM grants WHERE client_id=? AND revoked_at IS NULL", clientID).Scan(&n)
	return n, err
}

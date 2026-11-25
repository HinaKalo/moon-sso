package store

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"moon-sso/server/internal/db"
)

// API token kinds. A token is only accepted on the host of its kind.
const (
	TokenDeveloper = 1 // owned by an SSO user, public host
	TokenConsole   = 2 // owned by a console administrator, admin host
)

// APIToken is a long-lived bearer token for terminals, scripts and CI.
type APIToken struct {
	ID           uuid.UUID
	Kind         int
	OwnerID      uuid.UUID
	Name         string
	Scopes       []string
	TokenHash    []byte
	Hint         string
	AllowedCIDRs []string
	CreatedAt    time.Time
	CreatedIP    string
	ExpiresAt    time.Time
	LastUsedAt   *time.Time
	LastUsedIP   string
	RevokedAt    *time.Time
	RevokeReason string
	RotatedFrom  *uuid.UUID
	ReplacedBy   *uuid.UUID

	// Filled by queries that join the owner.
	OwnerName   string
	OwnerStatus int
}

// Active reports whether the token can still authenticate at now.
func (t *APIToken) Active(now time.Time) bool { return t.RevokedAt == nil && now.Before(t.ExpiresAt) }

// State is a short machine-readable status.
func (t *APIToken) State(now time.Time) string {
	switch {
	case t.RevokedAt != nil:
		return "revoked"
	case !now.Before(t.ExpiresAt):
		return "expired"
	case t.ReplacedBy != nil:
		return "rotating" // superseded, still valid during the rotation grace period
	}
	return "active"
}

// ExpiresSoon is true once less than 7 days and less than a quarter of the
// token's lifetime remain, so short-lived tokens are not flagged from birth.
func (t *APIToken) ExpiresSoon(now time.Time) bool {
	left := t.ExpiresAt.Sub(now)
	return t.Active(now) && left < 7*24*time.Hour && left < t.ExpiresAt.Sub(t.CreatedAt)/4
}

const apiTokenCols = `t.id, t.kind, t.owner_id, t.name, t.scopes, t.token_hash, t.hint, t.allowed_cidrs, t.created_at, t.created_ip,
	t.expires_at, t.last_used_at, t.last_used_ip, t.revoked_at, t.revoke_reason, t.rotated_from, t.replaced_by,
	COALESCE(u.username, a.username, ''), COALESCE(u.status, a.status, 0)`

const apiTokenFrom = ` FROM api_tokens t
	LEFT JOIN users u ON t.kind = 1 AND u.id = t.owner_id
	LEFT JOIN admin_accounts a ON t.kind = 2 AND a.id = t.owner_id`

func splitList(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Fields(s)
}

func scanAPIToken(row interface{ Scan(...any) error }) (*APIToken, error) {
	var t APIToken
	var scopes, cidrs string
	var lastUsed, revoked sql.NullTime
	var from, repl []byte
	err := row.Scan(&t.ID, &t.Kind, &t.OwnerID, &t.Name, &scopes, &t.TokenHash, &t.Hint, &cidrs, &t.CreatedAt, &t.CreatedIP,
		&t.ExpiresAt, &lastUsed, &t.LastUsedIP, &revoked, &t.RevokeReason, &from, &repl, &t.OwnerName, &t.OwnerStatus)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	t.Scopes, t.AllowedCIDRs = splitList(scopes), splitList(cidrs)
	t.LastUsedAt, t.RevokedAt = scanNullTime(lastUsed), scanNullTime(revoked)
	if id, err := uuid.FromBytes(from); err == nil {
		t.RotatedFrom = &id
	}
	if id, err := uuid.FromBytes(repl); err == nil {
		t.ReplacedBy = &id
	}
	return &t, nil
}

func uuidArg(id *uuid.UUID) any {
	if id == nil {
		return nil
	}
	return id[:]
}

func InsertAPIToken(ctx context.Context, q db.Querier, t *APIToken) error {
	_, err := q.ExecContext(ctx, `INSERT INTO api_tokens (id, kind, owner_id, name, scopes, token_hash, hint, allowed_cidrs,
		created_at, created_ip, expires_at, rotated_from) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
		t.ID[:], t.Kind, t.OwnerID[:], t.Name, strings.Join(t.Scopes, " "), t.TokenHash, t.Hint, strings.Join(t.AllowedCIDRs, " "),
		t.CreatedAt, t.CreatedIP, t.ExpiresAt, uuidArg(t.RotatedFrom))
	return err
}

func GetAPITokenByHash(ctx context.Context, q db.Querier, hash []byte) (*APIToken, error) {
	return scanAPIToken(q.QueryRowContext(ctx, "SELECT "+apiTokenCols+apiTokenFrom+" WHERE t.token_hash=?", hash))
}

func GetAPIToken(ctx context.Context, q db.Querier, id uuid.UUID) (*APIToken, error) {
	return scanAPIToken(q.QueryRowContext(ctx, "SELECT "+apiTokenCols+apiTokenFrom+" WHERE t.id=?", id[:]))
}

func GetAPITokenForUpdate(ctx context.Context, tx *sql.Tx, id uuid.UUID) (*APIToken, error) {
	return scanAPIToken(tx.QueryRowContext(ctx, "SELECT "+apiTokenCols+apiTokenFrom+" WHERE t.id=? FOR UPDATE", id[:]))
}

// APITokenFilter selects tokens for listings. Zero values match everything.
type APITokenFilter struct {
	Kind          int
	Owner         *uuid.UUID
	OwnerName     string // exact (normalized) owner username
	IncludeClosed bool   // also list revoked and expired tokens (kept 30 days)
	Limit         int
}

func ListAPITokens(ctx context.Context, q db.Querier, f APITokenFilter, now time.Time) ([]*APIToken, error) {
	where := []string{"t.kind = ?"}
	args := []any{f.Kind}
	if f.Owner != nil {
		where = append(where, "t.owner_id = ?")
		args = append(args, f.Owner[:])
	}
	if f.OwnerName != "" {
		where = append(where, "COALESCE(u.username_norm, a.username_norm) = ?")
		args = append(args, f.OwnerName)
	}
	if !f.IncludeClosed {
		where = append(where, "t.revoked_at IS NULL AND t.expires_at > ?")
		args = append(args, now)
	}
	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := q.QueryContext(ctx, "SELECT "+apiTokenCols+apiTokenFrom+" WHERE "+strings.Join(where, " AND ")+
		" ORDER BY t.created_at DESC LIMIT "+strconv.Itoa(limit), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*APIToken
	for rows.Next() {
		t, err := scanAPIToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func CountActiveAPITokens(ctx context.Context, q db.Querier, kind int, owner uuid.UUID, now time.Time) (int, error) {
	var n int
	err := q.QueryRowContext(ctx, "SELECT COUNT(*) FROM api_tokens WHERE kind=? AND owner_id=? AND revoked_at IS NULL AND expires_at > ?",
		kind, owner[:], now).Scan(&n)
	return n, err
}

// RevokeAPIToken revokes one token; it reports false when it was already revoked.
func RevokeAPIToken(ctx context.Context, q db.Querier, id uuid.UUID, reason string, now time.Time) (bool, error) {
	res, err := q.ExecContext(ctx, "UPDATE api_tokens SET revoked_at=?, revoke_reason=? WHERE id=? AND revoked_at IS NULL", now, reason, id[:])
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// RevokeOwnerAPITokens revokes every live token of an owner.
func RevokeOwnerAPITokens(ctx context.Context, q db.Querier, kind int, owner uuid.UUID, reason string, now time.Time) (int64, error) {
	res, err := q.ExecContext(ctx, "UPDATE api_tokens SET revoked_at=?, revoke_reason=? WHERE kind=? AND owner_id=? AND revoked_at IS NULL",
		now, reason, kind, owner[:])
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// MarkAPITokenReplaced shortens a rotated token to its grace period.
func MarkAPITokenReplaced(ctx context.Context, q db.Querier, id, by uuid.UUID, graceEnd time.Time) error {
	_, err := q.ExecContext(ctx, "UPDATE api_tokens SET replaced_by=?, expires_at=LEAST(expires_at, ?) WHERE id=?", by[:], graceEnd, id[:])
	return err
}

// TouchAPIToken records use; callers throttle how often it runs.
func TouchAPIToken(ctx context.Context, q db.Querier, id uuid.UUID, ip string, now time.Time) error {
	_, err := q.ExecContext(ctx, "UPDATE api_tokens SET last_used_at=?, last_used_ip=? WHERE id=?", now, ip, id[:])
	return err
}

package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"

	"moon-sso/server/internal/db"
)

// Admin is a console administrator. Admins live in their own table and are
// unrelated to SSO users.
type Admin struct {
	ID                 uuid.UUID
	Username           string
	UsernameNorm       string
	DisplayName        string
	PasswordHash       string
	PasswordChangedAt  time.Time
	MustChangePassword bool
	TOTPSecretEnc      []byte
	TOTPLastStep       int64
	Status             int
	CreatedAt          time.Time
	UpdatedAt          time.Time
	LastLoginAt        *time.Time
	LastLoginIP        string
}

func (a *Admin) HasTOTP() bool  { return len(a.TOTPSecretEnc) > 0 }
func (a *Admin) IsActive() bool { return a.Status == UserActive }
func (a *Admin) Name() string {
	if a.DisplayName != "" {
		return a.DisplayName
	}
	return a.Username
}

const adminCols = `id, username, username_norm, display_name, password_hash, password_changed_at, must_change_password,
	totp_secret_enc, totp_last_step, status, created_at, updated_at, last_login_at, last_login_ip`

func scanAdmin(row interface{ Scan(...any) error }) (*Admin, error) {
	var a Admin
	var last sql.NullTime
	err := row.Scan(&a.ID, &a.Username, &a.UsernameNorm, &a.DisplayName, &a.PasswordHash, &a.PasswordChangedAt,
		&a.MustChangePassword, &a.TOTPSecretEnc, &a.TOTPLastStep, &a.Status, &a.CreatedAt, &a.UpdatedAt, &last, &a.LastLoginIP)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	a.LastLoginAt = scanNullTime(last)
	return &a, nil
}

func GetAdmin(ctx context.Context, q db.Querier, id uuid.UUID) (*Admin, error) {
	return scanAdmin(q.QueryRowContext(ctx, "SELECT "+adminCols+" FROM admin_accounts WHERE id=?", id[:]))
}

func GetAdminByUsername(ctx context.Context, q db.Querier, norm string) (*Admin, error) {
	return scanAdmin(q.QueryRowContext(ctx, "SELECT "+adminCols+" FROM admin_accounts WHERE username_norm=?", norm))
}

func ListAdmins(ctx context.Context, q db.Querier) ([]*Admin, error) {
	rows, err := q.QueryContext(ctx, "SELECT "+adminCols+" FROM admin_accounts ORDER BY created_at")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Admin
	for rows.Next() {
		a, err := scanAdmin(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func InsertAdmin(ctx context.Context, q db.Querier, a *Admin) error {
	_, err := q.ExecContext(ctx, "INSERT INTO admin_accounts ("+adminCols+") VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
		a.ID[:], a.Username, a.UsernameNorm, a.DisplayName, a.PasswordHash, a.PasswordChangedAt, a.MustChangePassword,
		a.TOTPSecretEnc, a.TOTPLastStep, a.Status, a.CreatedAt, a.UpdatedAt, db.NullTime(a.LastLoginAt), a.LastLoginIP)
	return err
}

func UpdateAdmin(ctx context.Context, q db.Querier, a *Admin) error {
	_, err := q.ExecContext(ctx, `UPDATE admin_accounts SET display_name=?, password_hash=?, password_changed_at=?, must_change_password=?,
		totp_secret_enc=?, totp_last_step=?, status=?, updated_at=?, last_login_at=?, last_login_ip=? WHERE id=?`,
		a.DisplayName, a.PasswordHash, a.PasswordChangedAt, a.MustChangePassword, a.TOTPSecretEnc, a.TOTPLastStep, a.Status,
		a.UpdatedAt, db.NullTime(a.LastLoginAt), a.LastLoginIP, a.ID[:])
	return err
}

// AdvanceAdminTOTP burns a TOTP step (replay protection); false if already used.
func AdvanceAdminTOTP(ctx context.Context, q db.Querier, id uuid.UUID, step int64) (bool, error) {
	res, err := q.ExecContext(ctx, "UPDATE admin_accounts SET totp_last_step=? WHERE id=? AND totp_last_step < ?", step, id[:], step)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

func CountActiveAdmins(ctx context.Context, q db.Querier) (int, error) {
	var n int
	err := q.QueryRowContext(ctx, "SELECT COUNT(*) FROM admin_accounts WHERE status=1").Scan(&n)
	return n, err
}

// ---- admin sessions ----

type AdminSession struct {
	ID            []byte
	AdminID       uuid.UUID
	CreatedAt     time.Time
	LastSeenAt    time.Time
	IdleExpiresAt time.Time
	AbsExpiresAt  time.Time
	IP            string
	UserAgent     string
	RevokedAt     *time.Time
}

func (s *AdminSession) Valid(now time.Time) bool {
	return s.RevokedAt == nil && now.Before(s.IdleExpiresAt) && now.Before(s.AbsExpiresAt)
}

const adminSessCols = "id, admin_id, created_at, last_seen_at, idle_expires_at, abs_expires_at, ip, user_agent, revoked_at"

func scanAdminSession(row interface{ Scan(...any) error }) (*AdminSession, error) {
	var s AdminSession
	var rev sql.NullTime
	err := row.Scan(&s.ID, &s.AdminID, &s.CreatedAt, &s.LastSeenAt, &s.IdleExpiresAt, &s.AbsExpiresAt, &s.IP, &s.UserAgent, &rev)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	s.RevokedAt = scanNullTime(rev)
	return &s, nil
}

func InsertAdminSession(ctx context.Context, q db.Querier, s *AdminSession) error {
	_, err := q.ExecContext(ctx, "INSERT INTO admin_sessions ("+adminSessCols+") VALUES (?,?,?,?,?,?,?,?,?)",
		s.ID, s.AdminID[:], s.CreatedAt, s.LastSeenAt, s.IdleExpiresAt, s.AbsExpiresAt, s.IP, s.UserAgent, db.NullTime(s.RevokedAt))
	return err
}

func GetAdminSession(ctx context.Context, q db.Querier, id []byte) (*AdminSession, error) {
	return scanAdminSession(q.QueryRowContext(ctx, "SELECT "+adminSessCols+" FROM admin_sessions WHERE id=?", id))
}

func TouchAdminSession(ctx context.Context, q db.Querier, id []byte, now, idle time.Time, ip string) error {
	_, err := q.ExecContext(ctx, "UPDATE admin_sessions SET last_seen_at=?, idle_expires_at=LEAST(?, abs_expires_at), ip=? WHERE id=? AND revoked_at IS NULL",
		now, idle, ip, id)
	return err
}

func RevokeAdminSession(ctx context.Context, q db.Querier, id []byte, now time.Time) error {
	_, err := q.ExecContext(ctx, "UPDATE admin_sessions SET revoked_at=? WHERE id=? AND revoked_at IS NULL", now, id)
	return err
}

// RevokeAdminSessions ends every session of an admin except keep (may be nil).
func RevokeAdminSessions(ctx context.Context, q db.Querier, adminID uuid.UUID, keep []byte, now time.Time) error {
	if keep == nil {
		keep = []byte{}
	}
	_, err := q.ExecContext(ctx, "UPDATE admin_sessions SET revoked_at=? WHERE admin_id=? AND revoked_at IS NULL AND id<>?", now, adminID[:], keep)
	return err
}

func ListAdminSessions(ctx context.Context, q db.Querier, adminID uuid.UUID, now time.Time) ([]*AdminSession, error) {
	rows, err := q.QueryContext(ctx, "SELECT "+adminSessCols+` FROM admin_sessions
		WHERE admin_id=? AND revoked_at IS NULL AND idle_expires_at > ? AND abs_expires_at > ? ORDER BY last_seen_at DESC`, adminID[:], now, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*AdminSession
	for rows.Next() {
		s, err := scanAdminSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

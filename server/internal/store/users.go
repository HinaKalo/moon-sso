// Package store contains the SQL for every table. Functions take a
// db.Querier so they compose inside transactions.
package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"

	"moon-sso/server/internal/db"
)

var ErrNotFound = errors.New("not found")

const (
	UserActive   = 1
	UserDisabled = 2
)

type User struct {
	ID                 uuid.UUID
	PublicSub          string
	Username           string
	UsernameNorm       string
	DisplayName        string
	PasswordHash       string
	PasswordChangedAt  time.Time
	MustChangePassword bool
	AvatarKey          string
	Status             int
	Roles              uint32
	TOTPSecretEnc      []byte
	TOTPLastStep       int64
	ProfileVersion     uint64
	UsernameChangedAt  *time.Time
	RegisteredVia      string
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

func (u *User) HasTOTP() bool  { return len(u.TOTPSecretEnc) > 0 }
func (u *User) IsActive() bool { return u.Status == UserActive }
func (u *User) Name() string {
	if u.DisplayName != "" {
		return u.DisplayName
	}
	return u.Username
}

const userCols = `id, public_sub, username, username_norm, display_name, password_hash, password_changed_at,
	must_change_password, avatar_key, status, roles, totp_secret_enc, totp_last_step, profile_version,
	username_changed_at, registered_via, created_at, updated_at`

func scanUser(row interface{ Scan(...any) error }) (*User, error) {
	var u User
	var avatar sql.NullString
	var uchg sql.NullTime
	err := row.Scan(&u.ID, &u.PublicSub, &u.Username, &u.UsernameNorm, &u.DisplayName, &u.PasswordHash,
		&u.PasswordChangedAt, &u.MustChangePassword, &avatar, &u.Status, &u.Roles, &u.TOTPSecretEnc,
		&u.TOTPLastStep, &u.ProfileVersion, &uchg, &u.RegisteredVia, &u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	u.AvatarKey = avatar.String
	if uchg.Valid {
		t := uchg.Time
		u.UsernameChangedAt = &t
	}
	return &u, nil
}

func GetUser(ctx context.Context, q db.Querier, id uuid.UUID) (*User, error) {
	return scanUser(q.QueryRowContext(ctx, "SELECT "+userCols+" FROM users WHERE id = ?", id[:]))
}

// GetUserForUpdate locks the row; q must be a transaction.
func GetUserForUpdate(ctx context.Context, q db.Querier, id uuid.UUID) (*User, error) {
	return scanUser(q.QueryRowContext(ctx, "SELECT "+userCols+" FROM users WHERE id = ? FOR UPDATE", id[:]))
}

func GetUserByUsername(ctx context.Context, q db.Querier, norm string) (*User, error) {
	return scanUser(q.QueryRowContext(ctx, "SELECT "+userCols+" FROM users WHERE username_norm = ?", norm))
}

func GetUserByPublicSub(ctx context.Context, q db.Querier, sub string) (*User, error) {
	return scanUser(q.QueryRowContext(ctx, "SELECT "+userCols+" FROM users WHERE public_sub = ?", sub))
}

func InsertUser(ctx context.Context, q db.Querier, u *User) error {
	_, err := q.ExecContext(ctx, `INSERT INTO users (`+userCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		u.ID[:], u.PublicSub, u.Username, u.UsernameNorm, u.DisplayName, u.PasswordHash, u.PasswordChangedAt,
		u.MustChangePassword, nullString(u.AvatarKey), u.Status, u.Roles, u.TOTPSecretEnc, u.TOTPLastStep,
		u.ProfileVersion, db.NullTime(u.UsernameChangedAt), u.RegisteredVia, u.CreatedAt, u.UpdatedAt)
	return err
}

// UpdateUser writes every mutable column. Callers hold the row lock.
func UpdateUser(ctx context.Context, q db.Querier, u *User) error {
	_, err := q.ExecContext(ctx, `UPDATE users SET username=?, username_norm=?, display_name=?, password_hash=?,
		password_changed_at=?, must_change_password=?, avatar_key=?, status=?, roles=?, totp_secret_enc=?,
		totp_last_step=?, profile_version=?, username_changed_at=?, updated_at=? WHERE id=?`,
		u.Username, u.UsernameNorm, u.DisplayName, u.PasswordHash, u.PasswordChangedAt, u.MustChangePassword,
		nullString(u.AvatarKey), u.Status, u.Roles, u.TOTPSecretEnc, u.TOTPLastStep, u.ProfileVersion,
		db.NullTime(u.UsernameChangedAt), u.UpdatedAt, u.ID[:])
	return err
}

// SetTOTPLastStep advances the replay counter only forward.
func SetTOTPLastStep(ctx context.Context, q db.Querier, id uuid.UUID, step int64) (bool, error) {
	res, err := q.ExecContext(ctx, "UPDATE users SET totp_last_step=? WHERE id=? AND totp_last_step < ?", step, id[:], step)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// SetPasswordHash is used for transparent rehashing after a successful login.
func SetPasswordHash(ctx context.Context, q db.Querier, id uuid.UUID, hash string) error {
	_, err := q.ExecContext(ctx, "UPDATE users SET password_hash=? WHERE id=?", hash, id[:])
	return err
}

func DeleteUser(ctx context.Context, q db.Querier, id uuid.UUID) error {
	_, err := q.ExecContext(ctx, "DELETE FROM users WHERE id=?", id[:])
	return err
}

func InsertTombstone(ctx context.Context, q db.Querier, id uuid.UUID, publicSub string, at time.Time) error {
	_, err := q.ExecContext(ctx, "INSERT INTO user_tombstones (id, public_sub, deleted_at) VALUES (?,?,?)", id[:], publicSub, at)
	return err
}

// UsernameReserved reports whether norm is held for a different user.
func UsernameReserved(ctx context.Context, q db.Querier, norm string, for_ uuid.UUID, now time.Time) (bool, error) {
	var owner []byte
	err := q.QueryRowContext(ctx, "SELECT user_id FROM username_reservations WHERE username_norm=? AND expires_at > ?", norm, now).Scan(&owner)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return string(owner) != string(for_[:]), nil
}

func ReserveUsername(ctx context.Context, q db.Querier, norm string, owner uuid.UUID, until time.Time) error {
	_, err := q.ExecContext(ctx, `INSERT INTO username_reservations (username_norm, user_id, expires_at) VALUES (?,?,?)
		ON DUPLICATE KEY UPDATE user_id=VALUES(user_id), expires_at=VALUES(expires_at)`, norm, owner[:], until)
	return err
}

func ReleaseUsernameReservation(ctx context.Context, q db.Querier, norm string) error {
	_, err := q.ExecContext(ctx, "DELETE FROM username_reservations WHERE username_norm=?", norm)
	return err
}

type UserListFilter struct {
	Query  string
	Status int
	Limit  int
	Offset int
}

func ListUsers(ctx context.Context, q db.Querier, f UserListFilter) ([]*User, int, error) {
	where := " WHERE 1=1"
	var args []any
	if f.Query != "" {
		where += " AND (username_norm LIKE ? OR display_name LIKE ? OR public_sub = ?)"
		like := escapeLike(f.Query) + "%"
		args = append(args, like, "%"+escapeLike(f.Query)+"%", f.Query)
	}
	if f.Status != 0 {
		where += " AND status = ?"
		args = append(args, f.Status)
	}
	var total int
	if err := q.QueryRowContext(ctx, "SELECT COUNT(*) FROM users"+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	if f.Limit <= 0 || f.Limit > 200 {
		f.Limit = 50
	}
	rows, err := q.QueryContext(ctx, "SELECT "+userCols+" FROM users"+where+" ORDER BY created_at DESC LIMIT ? OFFSET ?",
		append(args, f.Limit, f.Offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []*User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, u)
	}
	return out, total, rows.Err()
}

func CountUsers(ctx context.Context, q db.Querier) (total, disabled int, err error) {
	err = q.QueryRowContext(ctx, "SELECT COUNT(*), COALESCE(SUM(status=2),0) FROM users").Scan(&total, &disabled)
	return
}

func nullString(s string) sql.NullString { return sql.NullString{String: s, Valid: s != ""} }

func escapeLike(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r == '%' || r == '_' || r == '\\' {
			out = append(out, '\\')
		}
		out = append(out, r)
	}
	return string(out)
}

package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"

	"moon-sso/server/internal/db"
)

// ---- authorization codes ----

type AuthCode struct {
	CodeHash            []byte
	ClientID            string
	UserID              uuid.UUID
	SID                 string
	RedirectURI         string
	Scopes              []string
	Resource            string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	DPoPJKT             string
	AuthTime            time.Time
	AMR                 string
	ExpiresAt           time.Time
	UsedAt              *time.Time
	FamilyID            *uuid.UUID
}

func InsertCode(ctx context.Context, q db.Querier, c *AuthCode) error {
	_, err := q.ExecContext(ctx, `INSERT INTO auth_codes (code_hash, client_id, user_id, sid, redirect_uri, scopes, resource,
		nonce, code_challenge, code_challenge_method, dpop_jkt, auth_time, amr, expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		c.CodeHash, c.ClientID, c.UserID[:], c.SID, c.RedirectURI, strings.Join(c.Scopes, " "), c.Resource, c.Nonce,
		c.CodeChallenge, c.CodeChallengeMethod, c.DPoPJKT, c.AuthTime, c.AMR, c.ExpiresAt)
	return err
}

// GetCodeForUpdate locks the code row; q must be a transaction.
func GetCodeForUpdate(ctx context.Context, q db.Querier, hash []byte) (*AuthCode, error) {
	var c AuthCode
	var scopes string
	var used sql.NullTime
	var fam []byte
	err := q.QueryRowContext(ctx, `SELECT code_hash, client_id, user_id, sid, redirect_uri, scopes, resource, nonce, code_challenge,
		code_challenge_method, dpop_jkt, auth_time, amr, expires_at, used_at, family_id FROM auth_codes WHERE code_hash=? FOR UPDATE`, hash).
		Scan(&c.CodeHash, &c.ClientID, &c.UserID, &c.SID, &c.RedirectURI, &scopes, &c.Resource, &c.Nonce, &c.CodeChallenge,
			&c.CodeChallengeMethod, &c.DPoPJKT, &c.AuthTime, &c.AMR, &c.ExpiresAt, &used, &fam)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	c.Scopes = strings.Fields(scopes)
	c.UsedAt = scanNullTime(used)
	if len(fam) == 16 {
		id, _ := uuid.FromBytes(fam)
		c.FamilyID = &id
	}
	return &c, nil
}

func MarkCodeUsed(ctx context.Context, q db.Querier, hash []byte, at time.Time, family *uuid.UUID) error {
	var fam []byte
	if family != nil {
		fam = family[:]
	}
	_, err := q.ExecContext(ctx, "UPDATE auth_codes SET used_at=?, family_id=? WHERE code_hash=?", at, fam, hash)
	return err
}

// ---- refresh token families ----

type Family struct {
	ID              uuid.UUID
	ClientID        string
	UserID          uuid.UUID
	SID             string // originating browser or device session
	Offline         bool   // offline_access: survives the end of SID
	Scopes          []string
	Resource        string
	CurrentHash     []byte
	CurrentEnc      []byte
	CurrentIssuedAt time.Time
	Generation      int
	IDPV            uint64 // profile version of the last ID token issued
	AuthTime        time.Time
	AMR             string
	DPoPJKT         string
	CreatedAt       time.Time
	IdleExpiresAt   time.Time
	AbsExpiresAt    time.Time
	LastUsedAt      time.Time
	LastIP          string
	UserAgent       string
	RevokedAt       *time.Time
	RevokeReason    string
}

const familyCols = `id, client_id, user_id, sid, offline, scopes, resource, current_hash, current_enc, current_issued_at, generation, id_pv,
	auth_time, amr, dpop_jkt, created_at, idle_expires_at, abs_expires_at, last_used_at, last_ip, user_agent, revoked_at, revoke_reason`

func scanFamily(row interface{ Scan(...any) error }) (*Family, error) {
	var f Family
	var sid sql.NullString
	var scopes string
	var rev sql.NullTime
	err := row.Scan(&f.ID, &f.ClientID, &f.UserID, &sid, &f.Offline, &scopes, &f.Resource, &f.CurrentHash, &f.CurrentEnc,
		&f.CurrentIssuedAt, &f.Generation, &f.IDPV, &f.AuthTime, &f.AMR, &f.DPoPJKT, &f.CreatedAt, &f.IdleExpiresAt,
		&f.AbsExpiresAt, &f.LastUsedAt, &f.LastIP, &f.UserAgent, &rev, &f.RevokeReason)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	f.SID = sid.String
	f.Scopes = strings.Fields(scopes)
	f.RevokedAt = scanNullTime(rev)
	return &f, nil
}

func InsertFamily(ctx context.Context, q db.Querier, f *Family) error {
	_, err := q.ExecContext(ctx, "INSERT INTO refresh_families ("+familyCols+") VALUES ("+placeholders(23)+")",
		f.ID[:], f.ClientID, f.UserID[:], nullString(f.SID), f.Offline, strings.Join(f.Scopes, " "), f.Resource, f.CurrentHash,
		f.CurrentEnc, f.CurrentIssuedAt, f.Generation, f.IDPV, f.AuthTime, f.AMR, f.DPoPJKT, f.CreatedAt, f.IdleExpiresAt,
		f.AbsExpiresAt, f.LastUsedAt, f.LastIP, f.UserAgent, db.NullTime(f.RevokedAt), f.RevokeReason)
	return err
}

// SessionState is the originating session of a family, read with it.
type SessionState struct {
	Exists        bool
	ID            []byte
	IdleExpiresAt time.Time
	AbsExpiresAt  time.Time
	LastSeenAt    time.Time
	Revoked       bool
}

// Valid reports whether the session is alive at now.
func (s *SessionState) Valid(now time.Time) bool {
	return s.Exists && !s.Revoked && now.Before(s.IdleExpiresAt) && now.Before(s.AbsExpiresAt)
}

var familyColsF = func() string {
	parts := strings.Split(familyCols, ",")
	for i, p := range parts {
		parts[i] = "f." + strings.TrimSpace(p)
	}
	return strings.Join(parts, ", ")
}()

func lockFamily(ctx context.Context, q db.Querier, where string, arg any) (*Family, *SessionState, error) {
	row := q.QueryRowContext(ctx, "SELECT "+familyColsF+`, s.id, s.idle_expires_at, s.abs_expires_at, s.last_seen_at, s.revoked_at
		FROM refresh_families f LEFT JOIN sso_sessions s ON s.sid = f.sid WHERE `+where+" FOR UPDATE OF f", arg)
	var f Family
	var sid sql.NullString
	var scopes string
	var rev sql.NullTime
	var sID []byte
	var sIdle, sAbs, sSeen, sRev sql.NullTime
	err := row.Scan(&f.ID, &f.ClientID, &f.UserID, &sid, &f.Offline, &scopes, &f.Resource, &f.CurrentHash, &f.CurrentEnc,
		&f.CurrentIssuedAt, &f.Generation, &f.IDPV, &f.AuthTime, &f.AMR, &f.DPoPJKT, &f.CreatedAt, &f.IdleExpiresAt,
		&f.AbsExpiresAt, &f.LastUsedAt, &f.LastIP, &f.UserAgent, &rev, &f.RevokeReason, &sID, &sIdle, &sAbs, &sSeen, &sRev)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, ErrNotFound
	}
	if err != nil {
		return nil, nil, err
	}
	f.SID = sid.String
	f.Scopes = strings.Fields(scopes)
	f.RevokedAt = scanNullTime(rev)
	ss := &SessionState{Exists: len(sID) > 0, ID: sID, IdleExpiresAt: sIdle.Time, AbsExpiresAt: sAbs.Time, LastSeenAt: sSeen.Time, Revoked: sRev.Valid}
	return &f, ss, nil
}

// LockFamilyByCurrentHash locks the family whose current token hashes to h,
// together with its session state, in one round trip.
func LockFamilyByCurrentHash(ctx context.Context, q db.Querier, h []byte) (*Family, *SessionState, error) {
	return lockFamily(ctx, q, "f.current_hash = ?", h)
}

// LockFamilyByID locks a family by primary key.
func LockFamilyByID(ctx context.Context, q db.Querier, id uuid.UUID) (*Family, *SessionState, error) {
	return lockFamily(ctx, q, "f.id = ?", id[:])
}

// FamilyIDByCurrentHash finds the family whose current token hashes to h (no lock).
func FamilyIDByCurrentHash(ctx context.Context, q db.Querier, h []byte) (uuid.UUID, error) {
	var id uuid.UUID
	err := q.QueryRowContext(ctx, "SELECT id FROM refresh_families WHERE current_hash=?", h).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return id, ErrNotFound
	}
	return id, err
}

// HistoryLookup finds a rotated-out token.
func HistoryLookup(ctx context.Context, q db.Querier, h []byte) (uuid.UUID, time.Time, error) {
	var id uuid.UUID
	var at time.Time
	err := q.QueryRowContext(ctx, "SELECT family_id, rotated_at FROM refresh_token_history WHERE token_hash=?", h).Scan(&id, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return id, at, ErrNotFound
	}
	return id, at, err
}

func GetFamilyForUpdate(ctx context.Context, q db.Querier, id uuid.UUID) (*Family, error) {
	return scanFamily(q.QueryRowContext(ctx, "SELECT "+familyCols+" FROM refresh_families WHERE id=? FOR UPDATE", id[:]))
}

func GetFamily(ctx context.Context, q db.Querier, id uuid.UUID) (*Family, error) {
	return scanFamily(q.QueryRowContext(ctx, "SELECT "+familyCols+" FROM refresh_families WHERE id=?", id[:]))
}

// RotateFamily installs a new current token and records the old one in history.
func RotateFamily(ctx context.Context, q db.Querier, f *Family, oldHash []byte, now time.Time) error {
	if _, err := q.ExecContext(ctx, "INSERT INTO refresh_token_history (token_hash, family_id, rotated_at) VALUES (?,?,?)", oldHash, f.ID[:], now); err != nil {
		return err
	}
	_, err := q.ExecContext(ctx, `UPDATE refresh_families SET current_hash=?, current_enc=?, current_issued_at=?, generation=?, id_pv=?,
		idle_expires_at=?, last_used_at=?, last_ip=?, user_agent=? WHERE id=?`,
		f.CurrentHash, f.CurrentEnc, f.CurrentIssuedAt, f.Generation, f.IDPV, f.IdleExpiresAt, f.LastUsedAt, f.LastIP, f.UserAgent, f.ID[:])
	return err
}

func RevokeFamily(ctx context.Context, q db.Querier, id uuid.UUID, reason string, now time.Time) error {
	_, err := q.ExecContext(ctx, "UPDATE refresh_families SET revoked_at=?, revoke_reason=?, current_enc=NULL WHERE id=? AND revoked_at IS NULL", now, reason, id[:])
	return err
}

// RevokeFamiliesWhere revokes families by user, optionally limited to one
// client or one session, and optionally keeping one session's families.
func RevokeFamilies(ctx context.Context, q db.Querier, userID uuid.UUID, clientID, onlySID, keepSID, reason string, now time.Time) error {
	where := "user_id=? AND revoked_at IS NULL"
	args := []any{now, reason, userID[:]}
	if clientID != "" {
		where += " AND client_id=?"
		args = append(args, clientID)
	}
	if onlySID != "" {
		where += " AND sid=?"
		args = append(args, onlySID)
	}
	if keepSID != "" {
		where += " AND (sid IS NULL OR sid<>?)"
		args = append(args, keepSID)
	}
	_, err := q.ExecContext(ctx, "UPDATE refresh_families SET revoked_at=?, revoke_reason=?, current_enc=NULL WHERE "+where, args...)
	return err
}

// RevokeSessionFamilies revokes families that came from sid. Offline
// families are included only when includeOffline is set (device removal).
func RevokeSessionFamilies(ctx context.Context, q db.Querier, sid, reason string, includeOffline bool, now time.Time) error {
	where := "sid=? AND revoked_at IS NULL"
	if !includeOffline {
		where += " AND offline=0"
	}
	_, err := q.ExecContext(ctx, "UPDATE refresh_families SET revoked_at=?, revoke_reason=?, current_enc=NULL WHERE "+where, now, reason, sid)
	return err
}

// ClearGraceCopies drops encrypted current-token copies older than the grace window.
func ClearGraceCopies(ctx context.Context, q db.Querier, before time.Time) (int64, error) {
	res, err := q.ExecContext(ctx, "UPDATE refresh_families SET current_enc=NULL WHERE current_enc IS NOT NULL AND current_issued_at < ? LIMIT 5000", before)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func CountActiveFamilies(ctx context.Context, q db.Querier, now time.Time) (int, error) {
	var n int
	err := q.QueryRowContext(ctx, "SELECT COUNT(*) FROM refresh_families WHERE revoked_at IS NULL AND idle_expires_at > ?", now).Scan(&n)
	return n, err
}

// ---- back-channel logout jobs ----

func InsertBackchannelJob(ctx context.Context, q db.Querier, clientID string, userID uuid.UUID, sid string, now time.Time) error {
	_, err := q.ExecContext(ctx, "INSERT INTO backchannel_jobs (client_id, user_id, sid, next_attempt_at, created_at) VALUES (?,?,?,?,?)",
		clientID, userID[:], sid, now, now)
	return err
}

type BackchannelJob struct {
	ID       uint64
	ClientID string
	UserID   uuid.UUID
	SID      string
	Attempts int
}

func DueBackchannelJobs(ctx context.Context, q db.Querier, now time.Time, limit int) ([]*BackchannelJob, error) {
	rows, err := q.QueryContext(ctx, "SELECT id, client_id, user_id, sid, attempts FROM backchannel_jobs WHERE status=0 AND next_attempt_at <= ? ORDER BY next_attempt_at LIMIT ?", now, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*BackchannelJob
	for rows.Next() {
		var j BackchannelJob
		if err := rows.Scan(&j.ID, &j.ClientID, &j.UserID, &j.SID, &j.Attempts); err != nil {
			return nil, err
		}
		out = append(out, &j)
	}
	return out, rows.Err()
}

// FinishBackchannelJob sets status 1 (done) or 2 (gave up), or reschedules (status 0).
func FinishBackchannelJob(ctx context.Context, q db.Querier, id uint64, status int, attempts int, next time.Time, lastErr string) error {
	if len(lastErr) > 500 {
		lastErr = lastErr[:500]
	}
	_, err := q.ExecContext(ctx, "UPDATE backchannel_jobs SET status=?, attempts=?, next_attempt_at=?, last_error=? WHERE id=?", status, attempts, next, lastErr, id)
	return err
}

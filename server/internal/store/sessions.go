package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"

	"moon-sso/server/internal/db"
)

type Session struct {
	ID            []byte // SHA-256 of the cookie value
	SID           string // public session id (OIDC "sid")
	UserID        uuid.UUID
	AuthTime      time.Time
	AMR           string // space separated, e.g. "pwd otp"
	CreatedAt     time.Time
	LastSeenAt    time.Time
	IdleExpiresAt time.Time
	AbsExpiresAt  time.Time
	IP            string
	UserAgent     string
	RevokedAt     *time.Time
}

func (s *Session) Valid(now time.Time) bool {
	return s.RevokedAt == nil && now.Before(s.IdleExpiresAt) && now.Before(s.AbsExpiresAt)
}

const sessionCols = "id, sid, user_id, auth_time, amr, created_at, last_seen_at, idle_expires_at, abs_expires_at, ip, user_agent, revoked_at"

func scanSession(row interface{ Scan(...any) error }) (*Session, error) {
	var s Session
	var rev sql.NullTime
	err := row.Scan(&s.ID, &s.SID, &s.UserID, &s.AuthTime, &s.AMR, &s.CreatedAt, &s.LastSeenAt,
		&s.IdleExpiresAt, &s.AbsExpiresAt, &s.IP, &s.UserAgent, &rev)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if rev.Valid {
		t := rev.Time
		s.RevokedAt = &t
	}
	return &s, nil
}

func InsertSession(ctx context.Context, q db.Querier, s *Session) error {
	_, err := q.ExecContext(ctx, "INSERT INTO sso_sessions ("+sessionCols+") VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
		s.ID, s.SID, s.UserID[:], s.AuthTime, s.AMR, s.CreatedAt, s.LastSeenAt, s.IdleExpiresAt,
		s.AbsExpiresAt, s.IP, s.UserAgent, db.NullTime(s.RevokedAt))
	return err
}

func GetSession(ctx context.Context, q db.Querier, id []byte) (*Session, error) {
	return scanSession(q.QueryRowContext(ctx, "SELECT "+sessionCols+" FROM sso_sessions WHERE id=?", id))
}

func GetSessionBySID(ctx context.Context, q db.Querier, sid string) (*Session, error) {
	return scanSession(q.QueryRowContext(ctx, "SELECT "+sessionCols+" FROM sso_sessions WHERE sid=?", sid))
}

func TouchSession(ctx context.Context, q db.Querier, id []byte, now, idleExp time.Time, ip string) error {
	_, err := q.ExecContext(ctx, "UPDATE sso_sessions SET last_seen_at=?, idle_expires_at=LEAST(?, abs_expires_at), ip=? WHERE id=? AND revoked_at IS NULL",
		now, idleExp, ip, id)
	return err
}

// UpdateSessionAuth records a step-up or re-authentication in an existing session.
func UpdateSessionAuth(ctx context.Context, q db.Querier, id []byte, authTime time.Time, amr string) error {
	_, err := q.ExecContext(ctx, "UPDATE sso_sessions SET auth_time=?, amr=? WHERE id=?", authTime, amr, id)
	return err
}

func RevokeSession(ctx context.Context, q db.Querier, sid string, at time.Time) (bool, error) {
	res, err := q.ExecContext(ctx, "UPDATE sso_sessions SET revoked_at=? WHERE sid=? AND revoked_at IS NULL", at, sid)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// ListActiveSessions returns live sessions for a user, newest first.
func ListActiveSessions(ctx context.Context, q db.Querier, userID uuid.UUID, now time.Time) ([]*Session, error) {
	rows, err := q.QueryContext(ctx, "SELECT "+sessionCols+` FROM sso_sessions
		WHERE user_id=? AND revoked_at IS NULL AND idle_expires_at > ? AND abs_expires_at > ?
		ORDER BY last_seen_at DESC LIMIT 100`, userID[:], now, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Session
	for rows.Next() {
		s, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func CountActiveSessions(ctx context.Context, q db.Querier, now time.Time) (int, error) {
	var n int
	err := q.QueryRowContext(ctx, "SELECT COUNT(*) FROM sso_sessions WHERE revoked_at IS NULL AND idle_expires_at > ? AND abs_expires_at > ?", now, now).Scan(&n)
	return n, err
}

func AddSessionClient(ctx context.Context, q db.Querier, sid, clientID string, now time.Time) error {
	_, err := q.ExecContext(ctx, "INSERT IGNORE INTO session_clients (sid, client_id, created_at) VALUES (?,?,?)", sid, clientID, now)
	return err
}

func SessionClients(ctx context.Context, q db.Querier, sid string) ([]string, error) {
	rows, err := q.QueryContext(ctx, "SELECT client_id FROM session_clients WHERE sid=?", sid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Package auth manages browser SSO sessions, CSRF protection and login throttling.
package auth

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"moon-sso/server/internal/cache"
	"moon-sso/server/internal/crypto"
	"moon-sso/server/internal/db"
	"moon-sso/server/internal/store"
)

// Cookies builds cookie names and attributes. In production every cookie uses
// the __Host- prefix (Secure, Path=/, no Domain), so it can be neither read nor
// planted by any other subdomain of moonl.cloud.
type Cookies struct{ Insecure bool }

func (c Cookies) Name(base string) string {
	if c.Insecure {
		return base
	}
	return "__Host-" + base
}

func (c Cookies) New(base, value string, expires time.Time) *http.Cookie {
	ck := &http.Cookie{Name: c.Name(base), Value: value, Path: "/", HttpOnly: true, Secure: !c.Insecure, SameSite: http.SameSiteLaxMode}
	if !expires.IsZero() {
		ck.Expires = expires
		ck.MaxAge = int(time.Until(expires).Seconds())
		if ck.MaxAge <= 0 {
			ck.MaxAge = -1
		}
	}
	return ck
}

func (c Cookies) Clear(base string) *http.Cookie {
	return &http.Cookie{Name: c.Name(base), Value: "", Path: "/", HttpOnly: true, Secure: !c.Insecure, SameSite: http.SameSiteLaxMode, MaxAge: -1}
}

const SessionCookie = "sso_sid"

// Sessions stores browser sessions in MySQL with a short in-process cache.
type Sessions struct {
	DB      *db.DB
	Cookies Cookies
	IdleTTL func() time.Duration
	AbsTTL  time.Duration
	Now     func() time.Time
	cache   *cache.Cache[string, *store.Session]
}

func NewSessions(d *db.DB, ck Cookies, idle func() time.Duration, abs time.Duration) *Sessions {
	return &Sessions{DB: d, Cookies: ck, IdleTTL: idle, AbsTTL: abs, Now: time.Now,
		cache: cache.New[string, *store.Session](50_000, 30*time.Second)}
}

var ErrNoSession = errors.New("no session")

func hashToken(tok string) []byte { return crypto.SHA256(tok) }

// Create starts a new session and returns the cookie value.
func (s *Sessions) Create(ctx context.Context, userID uuid.UUID, amr []string, ip, ua string) (string, *store.Session, error) {
	tok := crypto.RandomToken(32)
	now := s.Now().UTC()
	idle := now.Add(s.IdleTTL())
	abs := now.Add(s.AbsTTL)
	if idle.After(abs) {
		idle = abs
	}
	sess := &store.Session{
		ID: hashToken(tok), SID: crypto.RandomToken(16), UserID: userID, AuthTime: now, AMR: strings.Join(amr, " "),
		CreatedAt: now, LastSeenAt: now, IdleExpiresAt: idle, AbsExpiresAt: abs, IP: ip, UserAgent: truncate(ua, 255),
	}
	if err := store.InsertSession(ctx, s.DB, sess); err != nil {
		return "", nil, err
	}
	s.cache.Set(hex.EncodeToString(sess.ID), sess)
	return tok, sess, nil
}

// Lookup returns the live session for a cookie value, sliding its idle
// expiry at most every five minutes to keep writes cheap.
func (s *Sessions) Lookup(ctx context.Context, tok, ip string) (*store.Session, error) {
	if tok == "" || len(tok) > 100 {
		return nil, ErrNoSession
	}
	id := hashToken(tok)
	key := hex.EncodeToString(id)
	now := s.Now().UTC()
	sess, ok := s.cache.Get(key)
	if !ok {
		var err error
		sess, err = store.GetSession(ctx, s.DB, id)
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrNoSession
		}
		if err != nil {
			return nil, err
		}
		s.cache.Set(key, sess)
	}
	if !sess.Valid(now) {
		return nil, ErrNoSession
	}
	if now.Sub(sess.LastSeenAt) > 5*time.Minute {
		idle := now.Add(s.IdleTTL())
		if err := store.TouchSession(ctx, s.DB, id, now, idle, ip); err == nil {
			cp := *sess
			cp.LastSeenAt = now
			if idle.Before(cp.AbsExpiresAt) {
				cp.IdleExpiresAt = idle
			} else {
				cp.IdleExpiresAt = cp.AbsExpiresAt
			}
			cp.IP = ip
			s.cache.Set(key, &cp)
			sess = &cp
		}
	}
	return sess, nil
}

// StepUp records an additional authentication method (e.g. TOTP) in the session.
func (s *Sessions) StepUp(ctx context.Context, sess *store.Session, method string) (*store.Session, error) {
	amr := strings.Fields(sess.AMR)
	if !contains(amr, method) {
		amr = append(amr, method)
	}
	now := s.Now().UTC()
	if err := store.UpdateSessionAuth(ctx, s.DB, sess.ID, now, strings.Join(amr, " ")); err != nil {
		return nil, err
	}
	cp := *sess
	cp.AMR = strings.Join(amr, " ")
	cp.AuthTime = now
	s.cache.Set(hex.EncodeToString(sess.ID), &cp)
	return &cp, nil
}

// Revoke ends a session by its public sid.
func (s *Sessions) Revoke(ctx context.Context, q db.Querier, sid string) error {
	_, err := store.RevokeSession(ctx, q, sid, s.Now().UTC())
	s.cache.DeleteFunc(func(_ string, v *store.Session) bool { return v.SID == sid })
	return err
}

// ForgetUser drops cached sessions of a user (after mass revocation).
func (s *Sessions) ForgetUser(userID uuid.UUID) {
	s.cache.DeleteFunc(func(_ string, v *store.Session) bool { return v.UserID == userID })
}

// RevokeAllForUser revokes every session of the user except keepSID, inside tx.
// It returns the revoked sids so callers can emit back-channel logouts.
func RevokeAllForUser(ctx context.Context, tx *sql.Tx, userID uuid.UUID, keepSID string, now time.Time) ([]string, error) {
	rows, err := tx.QueryContext(ctx, "SELECT sid FROM sso_sessions WHERE user_id=? AND revoked_at IS NULL AND sid <> ? FOR UPDATE", userID[:], keepSID)
	if err != nil {
		return nil, err
	}
	var sids []string
	for rows.Next() {
		var sid string
		if err := rows.Scan(&sid); err != nil {
			rows.Close()
			return nil, err
		}
		sids = append(sids, sid)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(sids) == 0 {
		return nil, nil
	}
	_, err = tx.ExecContext(ctx, "UPDATE sso_sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL AND sid <> ?", now, userID[:], keepSID)
	return sids, err
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

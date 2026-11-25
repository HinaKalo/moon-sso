package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/google/uuid"

	"moon-sso/server/internal/db"
)

// ---- settings ----

func LoadSettingsRaw(ctx context.Context, q db.Querier) (map[string]json.RawMessage, error) {
	rows, err := q.QueryContext(ctx, "SELECT k, v FROM settings")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]json.RawMessage{}
	for rows.Next() {
		var k string
		var v []byte
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}

func PutSetting(ctx context.Context, q db.Querier, k string, v any, now time.Time) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = q.ExecContext(ctx, "INSERT INTO settings (k, v, updated_at) VALUES (?,?,?) ON DUPLICATE KEY UPDATE v=VALUES(v), updated_at=VALUES(updated_at)", k, b, now)
	return err
}

// ---- audit ----

type AuditEntry struct {
	ID            uint64
	At            time.Time
	ActorUserID   *uuid.UUID
	ActorClientID string
	ActorAdmin    string // console administrator username
	Action        string
	TargetType    string
	TargetID      string
	IP            string
	Meta          map[string]any
}

func InsertAudit(ctx context.Context, q db.Querier, e *AuditEntry) error {
	var actor []byte
	if e.ActorUserID != nil {
		actor = e.ActorUserID[:]
	}
	var meta []byte
	if len(e.Meta) > 0 {
		meta, _ = json.Marshal(e.Meta)
	}
	_, err := q.ExecContext(ctx, `INSERT INTO audit_log (at, actor_user_id, actor_client_id, actor_admin, action, target_type, target_id, ip, meta)
		VALUES (?,?,?,?,?,?,?,?,?)`, e.At, actor, e.ActorClientID, e.ActorAdmin, e.Action, e.TargetType, e.TargetID, e.IP, nullJSON(meta))
	return err
}

type AuditFilter struct {
	Action     string
	TargetID   string
	ActorID    *uuid.UUID
	ActorAdmin string
	BeforeID   uint64
	Limit      int
}

func ListAudit(ctx context.Context, q db.Querier, f AuditFilter) ([]*AuditEntry, error) {
	where := " WHERE 1=1"
	var args []any
	if f.Action != "" {
		where += " AND action LIKE ?"
		args = append(args, escapeLike(f.Action)+"%")
	}
	if f.TargetID != "" {
		where += " AND target_id = ?"
		args = append(args, f.TargetID)
	}
	if f.ActorID != nil {
		where += " AND actor_user_id = ?"
		args = append(args, f.ActorID[:])
	}
	if f.ActorAdmin != "" {
		where += " AND actor_admin = ?"
		args = append(args, f.ActorAdmin)
	}
	if f.BeforeID > 0 {
		where += " AND id < ?"
		args = append(args, f.BeforeID)
	}
	if f.Limit <= 0 || f.Limit > 200 {
		f.Limit = 50
	}
	rows, err := q.QueryContext(ctx, "SELECT id, at, actor_user_id, actor_client_id, actor_admin, action, target_type, target_id, ip, meta FROM audit_log"+
		where+" ORDER BY id DESC LIMIT ?", append(args, f.Limit)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*AuditEntry
	for rows.Next() {
		var e AuditEntry
		var actor []byte
		var meta []byte
		if err := rows.Scan(&e.ID, &e.At, &actor, &e.ActorClientID, &e.ActorAdmin, &e.Action, &e.TargetType, &e.TargetID, &e.IP, &meta); err != nil {
			return nil, err
		}
		if len(actor) == 16 {
			id, _ := uuid.FromBytes(actor)
			e.ActorUserID = &id
		}
		if len(meta) > 0 {
			_ = json.Unmarshal(meta, &e.Meta)
		}
		out = append(out, &e)
	}
	return out, rows.Err()
}

func nullJSON(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
}

// ---- outbox ----

// InsertEvent records a domain event inside the caller's transaction.
// recipients is the snapshot of client ids that must be told about it.
func InsertEvent(ctx context.Context, q db.Querier, typ string, userID *uuid.UUID, payload any, recipients []string, now time.Time) error {
	p, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if recipients == nil {
		recipients = []string{}
	}
	r, _ := json.Marshal(recipients)
	var uid []byte
	if userID != nil {
		uid = userID[:]
	}
	_, err = q.ExecContext(ctx, "INSERT INTO outbox_events (event_type, user_id, payload, recipients, created_at) VALUES (?,?,?,?,?)",
		typ, uid, p, r, now)
	return err
}

// ActiveGrantClients lists clients that hold a live grant for the user.
func ActiveGrantClients(ctx context.Context, q db.Querier, userID uuid.UUID) ([]string, error) {
	rows, err := q.QueryContext(ctx, "SELECT client_id FROM grants WHERE user_id=? AND revoked_at IS NULL", userID[:])
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

func scanNullTime(t sql.NullTime) *time.Time {
	if !t.Valid {
		return nil
	}
	v := t.Time
	return &v
}

// Package feed renders domain events for each integrated application and
// delivers them through three channels that share one ordered sequence:
// signed webhooks (push), the changes feed (pull / reconciliation) and
// Server-Sent Events (live updates for desktop, Android and browser SDKs).
package feed

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"moon-sso/server/internal/account"
	"moon-sso/server/internal/crypto"
	"moon-sso/server/internal/db"
	"moon-sso/server/internal/events"
	"moon-sso/server/internal/oidc"
	"moon-sso/server/internal/store"
)

type Feed struct {
	DB        *db.DB
	OIDC      *oidc.Provider
	Bus       *events.Bus
	AtRest    *crypto.Sealer
	Log       *slog.Logger
	PublicURL string

	hub  *hub
	wake chan struct{}
}

func New(f *Feed) *Feed {
	f.hub = newHub()
	f.wake = make(chan struct{}, 1)
	f.Bus.Subscribe(func(ns []events.Notice) {
		f.hub.dispatch(ns)
		select {
		case f.wake <- struct{}{}:
		default:
		}
	})
	return f
}

// Event is the wire format shared by webhooks, the changes feed and SSE.
type Event struct {
	ID         string         `json:"id"`
	Seq        uint64         `json:"seq"`
	Type       string         `json:"type"`
	OccurredAt time.Time      `json:"occurred_at"`
	Data       map[string]any `json:"data"`
}

type rawEvent struct {
	seq     uint64
	typ     string
	payload []byte
	created time.Time
}

func statusName(snap *account.Snapshot) string {
	switch {
	case snap.Deleted:
		return "deleted"
	case snap.Status == store.UserDisabled:
		return "disabled"
	}
	return "active"
}

// Render produces the recipient-specific view of an event.
func (f *Feed) Render(cl *store.Client, r rawEvent) (*Event, error) {
	var snap account.Snapshot
	if err := json.Unmarshal(r.payload, &snap); err != nil {
		return nil, err
	}
	data := map[string]any{
		"sub":             f.OIDC.SubjectForUserID(cl, snap.UserID, snap.PublicSub),
		"status":          statusName(&snap),
		"profile_version": snap.ProfileVersion,
		"updated_at":      snap.UpdatedAt.Unix(),
	}
	if !snap.Deleted {
		name := snap.DisplayName
		if name == "" {
			name = snap.Username
		}
		data["preferred_username"] = snap.Username
		data["name"] = name
		data["nickname"] = snap.DisplayName
		if snap.AvatarKey != "" {
			data["picture"] = f.PublicURL + "/avatars/" + snap.AvatarKey
		} else {
			data["picture"] = nil
		}
	}
	if len(snap.Changed) > 0 {
		data["changed"] = snap.Changed
	}
	return &Event{ID: "evt_" + strconv.FormatUint(r.seq, 10), Seq: r.seq, Type: r.typ, OccurredAt: r.created, Data: data}, nil
}

// load reads events for a client after seq, optionally for one user.
func (f *Feed) load(ctx context.Context, clientID string, after uint64, user *uuid.UUID, limit int) ([]rawEvent, error) {
	q := `SELECT e.seq, o.event_type, o.payload, o.created_at FROM client_events e JOIN outbox_events o ON o.id = e.event_id
		WHERE e.client_id = ? AND e.seq > ?`
	args := []any{clientID, after}
	if user != nil {
		q += " AND e.user_id = ?"
		args = append(args, user[:])
	}
	q += " ORDER BY e.seq LIMIT ?"
	args = append(args, limit)
	rows, err := f.DB.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []rawEvent
	for rows.Next() {
		var r rawEvent
		if err := rows.Scan(&r.seq, &r.typ, &r.payload, &r.created); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

const purgedKey = "events_purged_seq"

// PurgedSeq is the highest sequence number already deleted by retention.
func (f *Feed) PurgedSeq(ctx context.Context) uint64 {
	var raw []byte
	if err := f.DB.QueryRowContext(ctx, "SELECT v FROM settings WHERE k=?", purgedKey).Scan(&raw); err != nil {
		return 0
	}
	n, _ := strconv.ParseUint(strings.Trim(string(raw), `"`), 10, 64)
	return n
}

// LatestSeq is the newest sequence delivered to a client (the bulk-sync watermark).
func (f *Feed) LatestSeq(ctx context.Context, clientID string) uint64 {
	var n sql.NullInt64
	_ = f.DB.QueryRowContext(ctx, "SELECT MAX(seq) FROM client_events WHERE client_id=?", clientID).Scan(&n)
	return uint64(n.Int64)
}

// Retain deletes events older than keep, recording the purge watermark.
func (f *Feed) Retain(ctx context.Context, keep time.Duration) error {
	var maxSeq sql.NullInt64
	if err := f.DB.QueryRowContext(ctx, "SELECT MAX(seq) FROM outbox_events WHERE created_at < ? AND seq IS NOT NULL", time.Now().UTC().Add(-keep)).Scan(&maxSeq); err != nil {
		return err
	}
	if !maxSeq.Valid {
		return nil
	}
	// Never purge past an endpoint's undelivered cursor while it is enabled.
	var minCursor sql.NullInt64
	_ = f.DB.QueryRowContext(ctx, "SELECT MIN(webhook_cursor_seq) FROM clients WHERE webhook_url<>'' AND webhook_disabled_at IS NULL AND status=1").Scan(&minCursor)
	upto := uint64(maxSeq.Int64)
	if minCursor.Valid && uint64(minCursor.Int64) < upto {
		upto = uint64(minCursor.Int64)
	}
	if upto == 0 || upto <= f.PurgedSeq(ctx) {
		return nil
	}
	for {
		res, err := f.DB.ExecContext(ctx, "DELETE FROM client_events WHERE seq <= ? LIMIT 5000", upto)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n < 5000 {
			break
		}
	}
	for {
		res, err := f.DB.ExecContext(ctx, "DELETE FROM outbox_events WHERE seq <= ? LIMIT 5000", upto)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n < 5000 {
			break
		}
	}
	return store.PutSetting(ctx, f.DB, purgedKey, strconv.FormatUint(upto, 10), time.Now().UTC())
}

// ---- webhook secrets (Standard Webhooks) ----

// NewWebhookSecret returns a "whsec_" secret and its sealed form for storage.
func (f *Feed) NewWebhookSecret(clientID string) (string, []byte) {
	secret := "whsec_" + base64.StdEncoding.EncodeToString(crypto.RandomBytes(32))
	return secret, f.AtRest.Seal([]byte(secret), []byte("whsec:"+clientID))
}

func (f *Feed) webhookKey(cl *store.Client) ([]byte, error) {
	if len(cl.WebhookSecretEnc) == 0 {
		return nil, errors.New("no webhook secret")
	}
	pt, err := f.AtRest.Open(cl.WebhookSecretEnc, []byte("whsec:"+cl.ID))
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(strings.TrimPrefix(string(pt), "whsec_"))
}

// Sign computes the Standard Webhooks v1 signature header value.
func Sign(key []byte, msgID string, ts int64, body []byte) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(msgID + "." + strconv.FormatInt(ts, 10) + "."))
	m.Write(body)
	return "v1," + base64.StdEncoding.EncodeToString(m.Sum(nil))
}

// Page returns rendered events for a client after cursor.
func (f *Feed) Page(ctx context.Context, cl *store.Client, after uint64, limit int) ([]*Event, uint64, bool, error) {
	raw, err := f.load(ctx, cl.ID, after, nil, limit+1)
	if err != nil {
		return nil, after, false, err
	}
	more := len(raw) > limit
	if more {
		raw = raw[:limit]
	}
	out := make([]*Event, 0, len(raw))
	next := after
	for _, r := range raw {
		ev, err := f.Render(cl, r)
		if err != nil {
			return nil, after, false, err
		}
		out = append(out, ev)
		next = r.seq
	}
	return out, next, more, nil
}

// Package events moves domain events from the outbox to integrated
// applications: a single sequencer assigns commit-ordered sequence numbers
// and fans events out per recipient; workers deliver webhooks, back-channel
// logout tokens and live SSE notifications.
package events

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	"moon-sso/server/internal/db"
)

// Notice is published to in-process subscribers after events are sequenced.
type Notice struct {
	Seq     uint64
	EventID uint64
	Type    string
	UserID  uuid.UUID
	HasUser bool
	Clients []string
}

// Bus fans notices out to subscribers (SSE hub, webhook dispatcher).
type Bus struct {
	mu   sync.RWMutex
	subs map[int]func([]Notice)
	next int
}

func NewBus() *Bus { return &Bus{subs: map[int]func([]Notice){}} }

func (b *Bus) Subscribe(f func([]Notice)) func() {
	b.mu.Lock()
	id := b.next
	b.next++
	b.subs[id] = f
	b.mu.Unlock()
	return func() { b.mu.Lock(); delete(b.subs, id); b.mu.Unlock() }
}

func (b *Bus) publish(ns []Notice) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, f := range b.subs {
		f(ns)
	}
}

// Sequencer assigns seq to committed outbox rows in id order. Only one
// process sequences at a time (MySQL advisory lock); a transaction that
// commits late simply receives a later seq, so readers that page with
// "seq > cursor" can never skip an event.
type Sequencer struct {
	DB   *db.DB
	Bus  *Bus
	Log  *slog.Logger
	wake chan struct{}
}

func NewSequencer(d *db.DB, bus *Bus, log *slog.Logger) *Sequencer {
	return &Sequencer{DB: d, Bus: bus, Log: log, wake: make(chan struct{}, 1)}
}

// Wake requests a sequencing pass soon.
func (s *Sequencer) Wake() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *Sequencer) Run(ctx context.Context) {
	for ctx.Err() == nil {
		release, err := s.DB.Lock(ctx, "sequencer", 5*time.Second)
		if err != nil {
			if !errors.Is(err, db.ErrLockBusy) && ctx.Err() == nil {
				s.Log.Warn("sequencer lock failed", "err", err)
			}
			sleep(ctx, 5*time.Second)
			continue
		}
		s.loop(ctx)
		release()
	}
}

func (s *Sequencer) loop(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		for {
			n, err := s.pass(ctx)
			if err != nil {
				if ctx.Err() == nil {
					s.Log.Error("sequencer pass failed", "err", err)
				}
				return // re-acquire the lock (the connection may be broken)
			}
			if n < batch {
				break
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-s.wake:
		case <-t.C:
		}
	}
}

const batch = 500

func (s *Sequencer) pass(ctx context.Context) (int, error) {
	var notices []Notice
	err := s.DB.Tx(ctx, sql.LevelReadCommitted, func(tx *sql.Tx) error {
		notices = notices[:0]
		var maxSeq sql.NullInt64
		if err := tx.QueryRowContext(ctx, "SELECT MAX(seq) FROM outbox_events").Scan(&maxSeq); err != nil {
			return err
		}
		next := uint64(maxSeq.Int64) + 1
		rows, err := tx.QueryContext(ctx, "SELECT id, event_type, user_id, recipients FROM outbox_events WHERE seq IS NULL ORDER BY id LIMIT ? FOR UPDATE", batch)
		if err != nil {
			return err
		}
		type row struct {
			id   uint64
			typ  string
			uid  []byte
			rcpt []string
		}
		var list []row
		for rows.Next() {
			var r row
			var rc []byte
			if err := rows.Scan(&r.id, &r.typ, &r.uid, &rc); err != nil {
				rows.Close()
				return err
			}
			_ = json.Unmarshal(rc, &r.rcpt)
			list = append(list, r)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, r := range list {
			seq := next
			next++
			if _, err := tx.ExecContext(ctx, "UPDATE outbox_events SET seq=? WHERE id=?", seq, r.id); err != nil {
				return err
			}
			for _, cid := range r.rcpt {
				if _, err := tx.ExecContext(ctx, "INSERT IGNORE INTO client_events (client_id, seq, event_id, user_id) VALUES (?,?,?,?)",
					cid, seq, r.id, nullBytes(r.uid)); err != nil {
					return err
				}
			}
			n := Notice{Seq: seq, EventID: r.id, Type: r.typ, Clients: r.rcpt}
			if len(r.uid) == 16 {
				n.UserID, _ = uuid.FromBytes(r.uid)
				n.HasUser = true
			}
			notices = append(notices, n)
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	if len(notices) > 0 {
		s.Bus.publish(notices)
	}
	return len(notices), nil
}

func nullBytes(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
}

func sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

package feed

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"moon-sso/server/internal/db"
	"moon-sso/server/internal/httpx"
	"moon-sso/server/internal/safehttp"
	"moon-sso/server/internal/store"
)

// Per-endpoint retry ladder; after the last step the head event is moved to
// the dead-letter table so later events keep flowing.
var webhookBackoff = []time.Duration{time.Minute, 5 * time.Minute, 30 * time.Minute, 2 * time.Hour, 6 * time.Hour, 12 * time.Hour, 24 * time.Hour}

const disableAfter = 72 * time.Hour

// RunWebhooks delivers events to each endpoint strictly in sequence order.
// One process dispatches at a time (advisory lock); endpoints are handled
// concurrently with a bounded pool so a slow endpoint cannot starve others.
func (f *Feed) RunWebhooks(ctx context.Context) {
	secure := safehttp.Client(10 * time.Second)
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-f.wake:
		case <-t.C:
		}
		release, err := f.DB.Lock(ctx, "webhooks", 0)
		if err != nil {
			continue
		}
		f.dispatchDue(ctx, secure)
		release()
	}
}

func (f *Feed) dispatchDue(ctx context.Context, client *http.Client) {
	now := time.Now().UTC()
	rows, err := f.DB.QueryContext(ctx, `SELECT c.id FROM clients c
		WHERE c.webhook_url <> '' AND c.webhook_disabled_at IS NULL AND c.status = 1
		  AND (c.webhook_next_attempt_at IS NULL OR c.webhook_next_attempt_at <= ?)
		  AND EXISTS (SELECT 1 FROM client_events e WHERE e.client_id = c.id AND e.seq > c.webhook_cursor_seq)
		LIMIT 200`, now)
	if err != nil {
		if ctx.Err() == nil {
			f.Log.Warn("webhook scan failed", "err", err)
		}
		return
	}
	var ids []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	rows.Close()
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for _, id := range ids {
		sem <- struct{}{}
		wg.Add(1)
		go func(id string) {
			defer func() { <-sem; wg.Done() }()
			f.deliverClient(ctx, client, id)
		}(id)
	}
	wg.Wait()
}

// deliverClient sends up to 50 pending events for one endpoint in order.
func (f *Feed) deliverClient(ctx context.Context, hc *http.Client, clientID string) {
	cl, err := store.GetClient(ctx, f.DB, clientID)
	if err != nil || cl.WebhookURL == "" {
		return
	}
	if cl.WebhookAllowInsecure {
		hc = insecureClient
	}
	key, err := f.webhookKey(cl)
	if err != nil {
		f.Log.Warn("webhook secret unavailable", "client", clientID, "err", err)
		return
	}
	evs, err := f.load(ctx, clientID, cl.WebhookCursorSeq, nil, 50)
	if err != nil {
		return
	}
	for _, r := range evs {
		if ctx.Err() != nil {
			return
		}
		if !cl.WantsEvent(r.typ) {
			if err := f.advance(ctx, clientID, r.seq); err != nil {
				return
			}
			continue
		}
		ev, err := f.Render(cl, r)
		if err == nil {
			err = f.post(ctx, hc, cl.WebhookURL, key, ev)
		}
		if err == nil {
			httpx.Metrics.Inc("webhooks_delivered_total")
			if err := f.advance(ctx, clientID, r.seq); err != nil {
				return
			}
			continue
		}
		httpx.Metrics.Inc("webhooks_failed_total")
		f.fail(ctx, cl, r, err)
		return
	}
}

func (f *Feed) post(ctx context.Context, hc *http.Client, url string, key []byte, ev *Event) error {
	body, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	ts := time.Now().Unix()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "moon-sso-webhooks/1")
	req.Header.Set("webhook-id", ev.ID)
	req.Header.Set("webhook-timestamp", fmt.Sprint(ts))
	req.Header.Set("webhook-signature", Sign(key, ev.ID, ts, body))
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	safehttp.ReadLimited(resp.Body, 4096)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

func (f *Feed) advance(ctx context.Context, clientID string, seq uint64) error {
	_, err := f.DB.ExecContext(ctx, `UPDATE clients SET webhook_cursor_seq=?, webhook_attempts=0, webhook_next_attempt_at=NULL,
		webhook_last_error='', webhook_fail_since=NULL WHERE id=? AND webhook_cursor_seq < ?`, seq, clientID, seq)
	return err
}

func (f *Feed) fail(ctx context.Context, cl *store.Client, r rawEvent, cause error) {
	now := time.Now().UTC()
	msg := cause.Error()
	if len(msg) > 450 {
		msg = msg[:450]
	}
	attempts := cl.WebhookAttempts + 1
	failSince := now
	if cl.WebhookFailSince != nil {
		failSince = *cl.WebhookFailSince
	}
	if now.Sub(failSince) > disableAfter {
		_, _ = f.DB.ExecContext(ctx, "UPDATE clients SET webhook_disabled_at=?, webhook_last_error=? WHERE id=?", now, "已连续失败 3 天，自动停用："+msg, cl.ID)
		f.Log.Warn("webhook endpoint disabled", "client", cl.ID)
		return
	}
	if attempts > len(webhookBackoff) {
		err := f.DB.Tx(ctx, 0, func(tx *sql.Tx) error {
			if _, err := tx.ExecContext(ctx, `INSERT INTO webhook_dead_letters (client_id, seq, event_id, attempts, last_error, created_at)
				SELECT ?, seq, event_id, ?, ?, ? FROM client_events WHERE client_id=? AND seq=?`, cl.ID, attempts, msg, now, cl.ID, r.seq); err != nil {
				return err
			}
			_, err := tx.ExecContext(ctx, `UPDATE clients SET webhook_cursor_seq=?, webhook_attempts=0, webhook_next_attempt_at=NULL,
				webhook_last_error=? WHERE id=?`, r.seq, msg, cl.ID)
			return err
		})
		if err != nil {
			f.Log.Warn("dead-letter failed", "client", cl.ID, "err", err)
		}
		return
	}
	next := now.Add(webhookBackoff[attempts-1])
	_, _ = f.DB.ExecContext(ctx, `UPDATE clients SET webhook_attempts=?, webhook_next_attempt_at=?, webhook_last_error=?, webhook_fail_since=? WHERE id=?`,
		attempts, next, msg, failSince, cl.ID)
}

// insecureClient is used only for endpoints an administrator explicitly allowed
// to use plain http or private addresses (e.g. an app on the same host).
var insecureClient = &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

// Redrive delivers a dead-lettered event once more, immediately. Moving the
// endpoint cursor back would replay later events out of order, so it is not done.
func (f *Feed) Redrive(ctx context.Context, deadID uint64) error {
	var clientID string
	var seq uint64
	if err := f.DB.QueryRowContext(ctx, "SELECT client_id, seq FROM webhook_dead_letters WHERE id=? AND resolved_at IS NULL", deadID).Scan(&clientID, &seq); err != nil {
		return err
	}
	cl, err := store.GetClient(ctx, f.DB, clientID)
	if err != nil {
		return err
	}
	key, err := f.webhookKey(cl)
	if err != nil {
		return err
	}
	evs, err := f.load(ctx, clientID, seq-1, nil, 1)
	if err != nil || len(evs) == 0 || evs[0].seq != seq {
		return fmt.Errorf("事件已过保留期，无法重投")
	}
	ev, err := f.Render(cl, evs[0])
	if err != nil {
		return err
	}
	hc := safehttp.Client(10 * time.Second)
	if cl.WebhookAllowInsecure {
		hc = insecureClient
	}
	if err := f.post(ctx, hc, cl.WebhookURL, key, ev); err != nil {
		return err
	}
	_, err = f.DB.ExecContext(ctx, "UPDATE webhook_dead_letters SET resolved_at=? WHERE id=?", time.Now().UTC(), deadID)
	return err
}

// TestDelivery sends a signed "ping" event to an endpoint and reports the result.
func (f *Feed) TestDelivery(ctx context.Context, cl *store.Client) error {
	key, err := f.webhookKey(cl)
	if err != nil {
		return err
	}
	hc := safehttp.Client(10 * time.Second)
	if cl.WebhookAllowInsecure {
		hc = insecureClient
	}
	ev := &Event{ID: "evt_ping_" + fmt.Sprint(time.Now().UnixNano()), Type: "ping", OccurredAt: time.Now().UTC(), Data: map[string]any{"client_id": cl.ID}}
	return f.post(ctx, hc, cl.WebhookURL, key, ev)
}

// ReenableWebhook clears the disabled state of an endpoint.
func ReenableWebhook(ctx context.Context, d *db.DB, clientID string) error {
	_, err := d.ExecContext(ctx, `UPDATE clients SET webhook_disabled_at=NULL, webhook_fail_since=NULL, webhook_attempts=0,
		webhook_next_attempt_at=NULL, webhook_last_error='' WHERE id=?`, clientID)
	return err
}

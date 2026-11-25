package feed

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v5"

	"moon-sso/server/internal/events"
)

// hub routes sequenced notices to live SSE connections keyed by client+user.
type hub struct {
	mu   sync.RWMutex
	subs map[string]map[chan uint64]struct{}
}

func newHub() *hub { return &hub{subs: map[string]map[chan uint64]struct{}{}} }

func hubKey(clientID string, uid uuid.UUID) string { return clientID + "|" + uid.String() }

func (h *hub) add(key string) chan uint64 {
	ch := make(chan uint64, 32)
	h.mu.Lock()
	if h.subs[key] == nil {
		h.subs[key] = map[chan uint64]struct{}{}
	}
	h.subs[key][ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

func (h *hub) remove(key string, ch chan uint64) {
	h.mu.Lock()
	delete(h.subs[key], ch)
	if len(h.subs[key]) == 0 {
		delete(h.subs, key)
	}
	h.mu.Unlock()
}

func (h *hub) dispatch(ns []events.Notice) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, n := range ns {
		if !n.HasUser {
			continue
		}
		for _, cid := range n.Clients {
			for ch := range h.subs[hubKey(cid, n.UserID)] {
				select {
				case ch <- n.Seq:
				default: // slow consumer; it will catch up from the database
				}
			}
		}
	}
}

func (h *hub) count() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	n := 0
	for _, s := range h.subs {
		n += len(s)
	}
	return n
}

// Connections reports the number of open SSE streams.
func (f *Feed) Connections() int { return f.hub.count() }

// Stream serves GET /api/v1/me/events for the token's user and client.
// Authentication uses the Authorization header only (never the URL). The
// stream ends when the access token expires; SDKs reconnect with a fresh
// token and Last-Event-ID and receive everything they missed.
func (f *Feed) Stream(c *echo.Context) error {
	a, err := f.OIDC.Authenticate(c)
	if err != nil {
		return err
	}
	if a.User == nil {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "insufficient_scope", "error_description": "需要用户令牌"})
	}
	ctx := c.Request().Context()
	var last uint64
	if v := c.Request().Header.Get("Last-Event-ID"); v != "" {
		last, _ = strconv.ParseUint(v, 10, 64)
	}
	w := c.Response()
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Accel-Buffering", "no")
	if o := c.Request().Header.Get("Origin"); o != "" {
		f.OIDC.CORS(c, a.Client)
	}
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{})
	w.WriteHeader(http.StatusOK)

	key := hubKey(a.Client.ID, a.User.ID)
	ch := f.hub.add(key)
	defer f.hub.remove(key, ch)

	retry := 3000 + rand.IntN(5000)
	if _, err := fmt.Fprintf(w, "retry: %d\n\n", retry); err != nil {
		return nil
	}
	uid := a.User.ID
	send := func() (bool, error) {
		if last > 0 && last < f.PurgedSeq(ctx) {
			if _, err := fmt.Fprintf(w, "event: resync\ndata: {}\n\n"); err != nil {
				return false, err
			}
			last = f.LatestSeq(ctx, a.Client.ID)
		}
		evs, err := f.load(ctx, a.Client.ID, last, &uid, 100)
		if err != nil {
			return false, err
		}
		closeAfter := false
		for _, r := range evs {
			ev, err := f.Render(a.Client, r)
			if err != nil {
				return false, err
			}
			b, _ := json.Marshal(ev)
			if _, err := fmt.Fprintf(w, "id: %d\nevent: %s\ndata: %s\n\n", r.seq, r.typ, b); err != nil {
				return false, err
			}
			last = r.seq
			switch r.typ {
			case "user.disabled", "user.deleted", "user.password_changed", "consent.revoked":
				closeAfter = true
			}
		}
		return closeAfter, rc.Flush()
	}
	if last == 0 {
		// A fresh subscriber starts from "now" rather than replaying history.
		last = f.LatestSeq(ctx, a.Client.ID)
	}
	if done, err := send(); err != nil || done {
		return nil
	}
	expires := time.Until(time.Unix(a.Claims.Exp, 0))
	if expires <= 0 {
		return nil
	}
	expiry := time.NewTimer(expires)
	defer expiry.Stop()
	ping := time.NewTicker(25 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-expiry.C:
			_, _ = fmt.Fprint(w, "event: token_expired\ndata: {}\n\n")
			_ = rc.Flush()
			return nil
		case <-ping.C:
			if _, err := fmt.Fprint(w, ": ping\n\n"); err != nil {
				return nil
			}
			if rc.Flush() != nil {
				return nil
			}
		case <-ch:
			if done, err := send(); err != nil || done {
				return nil
			}
		}
	}
}

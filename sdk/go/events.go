package moonsso

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Event is a profile event (identical for webhooks, the changes feed and SSE).
type Event struct {
	ID         string    `json:"id"`
	Seq        uint64    `json:"seq"`
	Type       string    `json:"type"`
	OccurredAt time.Time `json:"occurred_at"`
	Data       EventData `json:"data"`
}

// EventData is the recipient-specific user snapshot carried by an event.
type EventData struct {
	Sub               string   `json:"sub"`
	Status            string   `json:"status"`
	PreferredUsername string   `json:"preferred_username"`
	Name              string   `json:"name"`
	Nickname          string   `json:"nickname"`
	Picture           *string  `json:"picture"`
	ProfileVersion    uint64   `json:"profile_version"`
	UpdatedAt         int64    `json:"updated_at"`
	Changed           []string `json:"changed,omitempty"`
}

// Profile converts the snapshot to a Profile.
func (d EventData) Profile() *Profile {
	return &Profile{Sub: d.Sub, PreferredUsername: d.PreferredUsername, Name: d.Name, Nickname: d.Nickname,
		Picture: d.Picture, UpdatedAt: d.UpdatedAt, ProfileVersion: d.ProfileVersion, Status: d.Status}
}

// Event types.
const (
	EventUserUpdated     = "user.updated"
	EventPasswordChanged = "user.password_changed"
	EventUserDisabled    = "user.disabled"
	EventUserEnabled     = "user.enabled"
	EventUserDeleted     = "user.deleted"
	EventConsentRevoked  = "consent.revoked"
)

// sseFrame is one parsed Server-Sent Events message.
type sseFrame struct {
	ID, Event, Data string
	Retry           int
}

// parseSSE reads frames until the reader ends, calling fn for each.
func parseSSE(r *bufio.Reader, fn func(sseFrame) error) error {
	var f sseFrame
	var data []string
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			if len(data) > 0 || f.Event != "" || f.Retry > 0 {
				f.Data = strings.Join(data, "\n")
				if f.Event == "" {
					f.Event = "message"
				}
				if err := fn(f); err != nil {
					return err
				}
			}
			f, data = sseFrame{}, nil
			continue
		}
		if strings.HasPrefix(line, ":") {
			continue
		}
		field, value, _ := strings.Cut(line, ":")
		value = strings.TrimPrefix(value, " ")
		switch field {
		case "id":
			f.ID = value
		case "event":
			f.Event = value
		case "data":
			data = append(data, value)
		case "retry":
			f.Retry, _ = strconv.Atoi(value)
		}
	}
}

// Listen streams live profile events for the signed-in user until ctx ends.
// It reconnects with Last-Event-ID (so nothing is missed), keeps the cached
// profile current and detects remote sign-out. handler may be nil.
func (s *Session) Listen(ctx context.Context, handler func(Event)) error {
	retry := time.Duration(3000+rand.IntN(5000)) * time.Millisecond
	for ctx.Err() == nil {
		err := s.listenOnce(ctx, handler, &retry)
		if errors.Is(err, ErrSessionExpired) || errors.Is(err, ErrNotSignedIn) {
			return err
		}
		jitter := time.Duration(rand.IntN(1000)) * time.Millisecond
		select {
		case <-ctx.Done():
		case <-time.After(retry + jitter):
		}
	}
	return ctx.Err()
}

func (s *Session) listenOnce(ctx context.Context, handler func(Event), retry *time.Duration) error {
	tok, err := s.AccessToken(ctx)
	if err != nil {
		return err
	}
	u, err := s.c.endpoint(ctx, func(d *Discovery) string { return d.EventsEndpoint }, "/api/v1/me/events")
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("User-Agent", s.c.ua)
	if st := s.Stored(ctx); st != nil && st.LastEventID != "" {
		req.Header.Set("Last-Event-ID", st.LastEventID)
	}
	hc := &http.Client{Transport: s.c.http.Transport} // no overall timeout for streams
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return s.Refresh(ctx)
	}
	if resp.StatusCode != http.StatusOK {
		return decodeResponse(resp, nil)
	}
	return parseSSE(bufio.NewReader(resp.Body), func(f sseFrame) error {
		if f.Retry > 0 {
			*retry = time.Duration(f.Retry) * time.Millisecond
		}
		switch f.Event {
		case "token_expired":
			return s.Refresh(ctx)
		case "resync":
			_, err := s.GetMe(ctx)
			return err
		case "message":
			return nil
		}
		var ev Event
		if err := json.Unmarshal([]byte(f.Data), &ev); err != nil {
			return nil
		}
		if f.ID != "" {
			s.setLastEventID(ctx, f.ID)
		}
		switch ev.Type {
		case EventUserUpdated, EventUserEnabled:
			s.setProfile(ctx, ev.Data.Profile())
		case EventPasswordChanged, EventUserDisabled, EventUserDeleted, EventConsentRevoked:
			// Find out whether this device is still signed in.
			if err := s.Refresh(ctx); errors.Is(err, ErrSessionExpired) {
				if handler != nil {
					handler(ev)
				}
				return err
			}
		}
		if handler != nil {
			handler(ev)
		}
		return nil
	})
}

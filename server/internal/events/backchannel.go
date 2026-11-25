package events

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"moon-sso/server/internal/db"
	"moon-sso/server/internal/safehttp"
	"moon-sso/server/internal/store"
)

// LogoutSigner mints a back-channel logout token for a client.
type LogoutSigner interface {
	LogoutTokenFor(ctx context.Context, clientID string, userID uuid.UUID, sid string) (token, uri string, err error)
}

// Backchannel delivers OIDC Back-Channel Logout requests with retries.
type Backchannel struct {
	DB     *db.DB
	Signer LogoutSigner
	Log    *slog.Logger
	HTTP   *http.Client
	wake   chan struct{}
}

func NewBackchannel(d *db.DB, s LogoutSigner, log *slog.Logger) *Backchannel {
	return &Backchannel{DB: d, Signer: s, Log: log, HTTP: safehttp.Client(10 * time.Second), wake: make(chan struct{}, 1)}
}

func (b *Backchannel) Wake() {
	select {
	case b.wake <- struct{}{}:
	default:
	}
}

var bcBackoff = []time.Duration{10 * time.Second, time.Minute, 5 * time.Minute, 30 * time.Minute, 2 * time.Hour}

func (b *Backchannel) Run(ctx context.Context) {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-b.wake:
		case <-t.C:
		}
		release, err := b.DB.Lock(ctx, "backchannel", 0)
		if err != nil {
			continue
		}
		b.drain(ctx)
		release()
	}
}

func (b *Backchannel) drain(ctx context.Context) {
	jobs, err := store.DueBackchannelJobs(ctx, b.DB, time.Now().UTC(), 100)
	if err != nil {
		if ctx.Err() == nil {
			b.Log.Warn("backchannel query failed", "err", err)
		}
		return
	}
	sem := make(chan struct{}, 8)
	done := make(chan struct{}, len(jobs))
	for _, j := range jobs {
		sem <- struct{}{}
		go func(j *store.BackchannelJob) {
			defer func() { <-sem; done <- struct{}{} }()
			b.deliver(ctx, j)
		}(j)
	}
	for range jobs {
		<-done
	}
}

func (b *Backchannel) deliver(ctx context.Context, j *store.BackchannelJob) {
	now := time.Now().UTC()
	tok, uri, err := b.Signer.LogoutTokenFor(ctx, j.ClientID, j.UserID, j.SID)
	if err == nil && uri == "" {
		_ = store.FinishBackchannelJob(ctx, b.DB, j.ID, 1, j.Attempts, now, "no endpoint")
		return
	}
	if err == nil {
		err = b.post(ctx, uri, tok)
	}
	attempts := j.Attempts + 1
	if err == nil {
		_ = store.FinishBackchannelJob(ctx, b.DB, j.ID, 1, attempts, now, "")
		return
	}
	if attempts > len(bcBackoff) {
		b.Log.Warn("backchannel logout gave up", "client", j.ClientID, "err", err)
		_ = store.FinishBackchannelJob(ctx, b.DB, j.ID, 2, attempts, now, err.Error())
		return
	}
	_ = store.FinishBackchannelJob(ctx, b.DB, j.ID, 0, attempts, now.Add(bcBackoff[attempts-1]), err.Error())
}

func (b *Backchannel) post(ctx context.Context, uri, tok string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uri, strings.NewReader(url.Values{"logout_token": {tok}}.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "moon-sso-backchannel/1")
	resp, err := b.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	safehttp.ReadLimited(resp.Body, 4096)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}

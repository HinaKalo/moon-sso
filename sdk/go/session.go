package moonsso

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"
)

// Stored is what a Session persists. RefreshToken and DPoPKey are secrets.
type Stored struct {
	Token   Token    `json:"token"`
	Profile *Profile `json:"profile,omitempty"`
	DPoPKey string   `json:"dpop_key,omitempty"`
	// LastEventID lets live updates resume after restarts.
	LastEventID string `json:"last_event_id,omitempty"`
}

// Store persists a session. Implementations must make Save atomic: a
// rotated refresh token that is lost cannot be recovered.
type Store interface {
	Load(ctx context.Context) (*Stored, error) // (nil, nil) when empty
	Save(ctx context.Context, s *Stored) error
	Clear(ctx context.Context) error
}

// Locker serializes refreshes across processes sharing one Store (several
// instances of a desktop app). It may be nil for single-process use.
type Locker interface {
	Lock(ctx context.Context) (unlock func(), err error)
}

// MemoryStore keeps a session in memory (tests, short-lived tools).
type MemoryStore struct {
	mu sync.Mutex
	s  *Stored
}

func (m *MemoryStore) Load(context.Context) (*Stored, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.s == nil {
		return nil, nil
	}
	cp := *m.s
	return &cp, nil
}
func (m *MemoryStore) Save(_ context.Context, s *Stored) error {
	m.mu.Lock()
	cp := *s
	m.s = &cp
	m.mu.Unlock()
	return nil
}
func (m *MemoryStore) Clear(context.Context) error { m.mu.Lock(); m.s = nil; m.mu.Unlock(); return nil }

// SessionOptions tune renewal.
type SessionOptions struct {
	// RefreshAt is the fraction of the access-token lifetime after which it is
	// renewed proactively (default 0.75, i.e. 7.5 of 10 minutes).
	RefreshAt float64
	// MinRemaining forces a refresh when less than this remains (default 30s).
	MinRemaining time.Duration
	Locker       Locker
	// OnSessionExpired runs once when the refresh token is rejected.
	OnSessionExpired func()
	// OnRefresh runs after every successful refresh.
	OnRefresh func(*Token)
	// OnProfile runs when the cached profile changes (API calls or live events).
	OnProfile func(*Profile)
}

// Session owns one signed-in user's tokens and renews them silently. All
// methods are safe for concurrent use; refreshes are single-flight within a
// process and, with a Locker, across processes.
type Session struct {
	c     *Client
	store Store
	opts  SessionOptions

	mu      sync.Mutex // guards cur and serializes refreshes
	cur     *Stored
	expired bool
}

// NewSession binds a client to a store.
func (c *Client) NewSession(store Store, opts SessionOptions) *Session {
	if opts.RefreshAt <= 0 || opts.RefreshAt >= 1 {
		opts.RefreshAt = 0.75
	}
	if opts.MinRemaining <= 0 {
		opts.MinRemaining = 30 * time.Second
	}
	return &Session{c: c, store: store, opts: opts}
}

// Client returns the session's client.
func (s *Session) Client() *Client { return s.c }

// Begin stores freshly obtained tokens (after login).
func (s *Session) Begin(ctx context.Context, tok *Token, claims Claims) error {
	st := &Stored{Token: *tok}
	if s.c.cfg.DPoP != nil {
		k, err := MarshalDPoPKey(s.c.cfg.DPoP)
		if err != nil {
			return err
		}
		st.DPoPKey = k
	}
	if claims != nil {
		st.Profile = profileFromClaims(claims)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.store.Save(ctx, st); err != nil {
		return err
	}
	s.cur, s.expired = st, false
	return nil
}

func (s *Session) needsRefresh(t *Token) bool {
	life := t.Lifetime()
	if life <= 0 {
		return true
	}
	refreshAt := t.IssuedAt.Add(time.Duration(float64(life) * s.opts.RefreshAt))
	return time.Now().After(refreshAt) || t.Remaining() < s.opts.MinRemaining
}

func (s *Session) loadLocked(ctx context.Context) error {
	if s.cur != nil {
		return nil
	}
	st, err := s.store.Load(ctx)
	if err != nil {
		return err
	}
	if st == nil {
		return ErrNotSignedIn
	}
	s.cur = st
	return nil
}

// AccessToken returns a valid access token, refreshing first when it is
// close to expiry. The check runs on every call, which also covers a
// computer waking from sleep.
func (s *Session) AccessToken(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.loadLocked(ctx); err != nil {
		return "", err
	}
	if s.needsRefresh(&s.cur.Token) {
		if err := s.refreshLocked(ctx, false); err != nil {
			// Transient failure: keep using the current token while it is valid.
			if !errors.Is(err, ErrSessionExpired) && s.cur != nil && s.cur.Token.Remaining() > 5*time.Second {
				return s.cur.Token.AccessToken, nil
			}
			return "", err
		}
	}
	return s.cur.Token.AccessToken, nil
}

// Refresh forces a refresh (e.g. after a 401 from a resource server).
func (s *Session) Refresh(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.loadLocked(ctx); err != nil {
		return err
	}
	return s.refreshLocked(ctx, true)
}

func (s *Session) refreshLocked(ctx context.Context, force bool) error {
	if s.expired {
		return ErrSessionExpired
	}
	before := s.cur.Token.RefreshToken
	if s.opts.Locker != nil {
		unlock, err := s.opts.Locker.Lock(ctx)
		if err != nil {
			return err
		}
		defer unlock()
		// Another process may have refreshed while we waited for the lock.
		if st, err := s.store.Load(ctx); err == nil && st != nil {
			if st.Token.RefreshToken != before && (!force || st.Token.AccessToken != s.cur.Token.AccessToken) {
				s.cur = st
				if !s.needsRefresh(&st.Token) {
					return nil
				}
			}
		}
	}
	if s.cur.Token.RefreshToken == "" {
		return errors.Join(ErrSessionExpired, errors.New("no refresh token"))
	}
	tok, err := s.c.Refresh(ctx, s.cur.Token.RefreshToken)
	if err != nil {
		if errors.Is(err, ErrSessionExpired) {
			s.expire(ctx)
		}
		return err
	}
	next := *s.cur
	next.Token = *tok
	if tok.RefreshToken == "" {
		next.Token.RefreshToken = s.cur.Token.RefreshToken
	}
	if tok.IDToken != "" {
		if cl, err := s.c.VerifyIDToken(ctx, tok.IDToken, "", tok.AccessToken); err == nil {
			p := profileFromClaims(cl)
			if next.Profile == nil || next.Profile.ProfileVersion != p.ProfileVersion {
				next.Profile = p
				if s.opts.OnProfile != nil {
					go s.opts.OnProfile(p)
				}
			}
		}
	}
	if err := s.store.Save(ctx, &next); err != nil {
		return err
	}
	s.cur = &next
	if s.opts.OnRefresh != nil {
		go s.opts.OnRefresh(tok)
	}
	return nil
}

func (s *Session) expire(ctx context.Context) {
	if s.expired {
		return
	}
	s.expired = true
	_ = s.store.Clear(ctx)
	s.cur = nil
	if s.opts.OnSessionExpired != nil {
		go s.opts.OnSessionExpired()
	}
}

// Stored returns a copy of the current session state, or nil.
func (s *Session) Stored(ctx context.Context) *Stored {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.loadLocked(ctx) != nil {
		return nil
	}
	cp := *s.cur
	return &cp
}

// SignedIn reports whether tokens are present.
func (s *Session) SignedIn(ctx context.Context) bool { return s.Stored(ctx) != nil }

// Profile returns the cached profile (from the ID token or the last API call).
func (s *Session) Profile(ctx context.Context) *Profile {
	if st := s.Stored(ctx); st != nil {
		return st.Profile
	}
	return nil
}

func (s *Session) setProfile(ctx context.Context, p *Profile) {
	s.mu.Lock()
	if s.cur != nil {
		next := *s.cur
		next.Profile = p
		if s.store.Save(ctx, &next) == nil {
			s.cur = &next
		}
	}
	s.mu.Unlock()
	if s.opts.OnProfile != nil {
		s.opts.OnProfile(p)
	}
}

func (s *Session) setLastEventID(ctx context.Context, id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cur == nil || s.cur.LastEventID == id {
		return
	}
	next := *s.cur
	next.LastEventID = id
	if s.store.Save(ctx, &next) == nil {
		s.cur = &next
	}
}

// Logout revokes the refresh token (best effort) and clears local state.
func (s *Session) Logout(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.loadLocked(ctx) == nil && s.cur.Token.RefreshToken != "" {
		rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		_ = s.c.Revoke(rctx, s.cur.Token.RefreshToken)
		cancel()
	}
	s.cur = nil
	return s.store.Clear(ctx)
}

// KeepFresh refreshes in the background shortly before expiry until ctx ends.
// Desktop apps run it so that tokens are fresh even when idle.
func (s *Session) KeepFresh(ctx context.Context) {
	for {
		wait := time.Minute
		if st := s.Stored(ctx); st != nil {
			life := st.Token.Lifetime()
			at := st.Token.IssuedAt.Add(time.Duration(float64(life) * s.opts.RefreshAt))
			wait = time.Until(at)
			if wait < time.Second {
				wait = time.Second
			}
			if wait > time.Minute {
				wait = time.Minute // re-check regularly: sleep/wake shifts clocks
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		if s.SignedIn(ctx) {
			_, _ = s.AccessToken(ctx)
		}
	}
}

// Transport returns an http.RoundTripper that authenticates requests with the
// session's access token and, on a 401, refreshes once and replays once.
func (s *Session) Transport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return &authTransport{s: s, base: base}
}

// HTTPClient returns an *http.Client using Transport.
func (s *Session) HTTPClient() *http.Client {
	return &http.Client{Transport: s.Transport(s.c.http.Transport), Timeout: s.c.http.Timeout}
}

type authTransport struct {
	s    *Session
	base http.RoundTripper
}

func (t *authTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var body []byte
	if req.Body != nil && req.GetBody == nil {
		b, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		req.Body.Close()
		body = b
	}
	clone := func() (*http.Request, error) {
		r := req.Clone(req.Context())
		if req.GetBody != nil {
			b, err := req.GetBody()
			if err != nil {
				return nil, err
			}
			r.Body = b
		} else if body != nil {
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
		return r, nil
	}
	tok, err := t.s.AccessToken(req.Context())
	if err != nil {
		return nil, err
	}
	r, err := clone()
	if err != nil {
		return nil, err
	}
	r.Header.Set("Authorization", "Bearer "+tok)
	resp, err := t.base.RoundTrip(r)
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		return resp, err
	}
	resp.Body.Close()
	if err := t.s.Refresh(req.Context()); err != nil {
		return nil, err
	}
	tok, err = t.s.AccessToken(req.Context())
	if err != nil {
		return nil, err
	}
	r, err = clone()
	if err != nil {
		return nil, err
	}
	r.Header.Set("Authorization", "Bearer "+tok)
	return t.base.RoundTrip(r)
}

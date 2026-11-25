// Package web adds Moon SSO login to net/http (and Echo, Gin, Chi … through
// their net/http adapters) for server-side web applications.
//
//	m, _ := web.New(web.Options{Client: client, CookieSecure: true})
//	mux.Handle("/auth/", m.Routes())               // login, callback, logout, back-channel
//	mux.Handle("/app/", m.Require(appHandler))     // signed-in area
//	// Echo: e.Use(echo.WrapMiddleware(m.Require))
//
// Tokens stay on the server (SessionStore); the browser only holds an opaque
// session cookie. Access tokens are renewed silently before they expire, and
// when the refresh token is gone the user is re-authenticated with prompt=none
// through their SSO session before falling back to the login page. HTMX
// requests receive HX-Redirect instead of a 302.
package web

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	moonsso "sso.moonl.cloud/sdk/go"
)

// SessionData is stored server-side per browser session.
type SessionData struct {
	Token   *moonsso.Token       `json:"token,omitempty"`
	Profile *moonsso.Profile     `json:"profile,omitempty"`
	SID     string               `json:"sid,omitempty"`
	Pending *moonsso.AuthRequest `json:"pending,omitempty"`
	Return  string               `json:"return,omitempty"`
	Silent  bool                 `json:"silent,omitempty"`
}

// SessionStore keeps sessions server-side (memory, Redis, SQL…).
type SessionStore interface {
	Get(ctx context.Context, id string) (*SessionData, error) // nil, nil if absent
	Set(ctx context.Context, id string, d *SessionData, ttl time.Duration) error
	Delete(ctx context.Context, id string) error
	// DeleteWhere removes sessions matching the predicate (back-channel logout).
	DeleteWhere(ctx context.Context, match func(*SessionData) bool) error
}

// MemoryStore is an in-process SessionStore for single-instance apps.
type MemoryStore struct {
	mu sync.Mutex
	m  map[string]memEntry
}

type memEntry struct {
	d   []byte
	exp time.Time
}

func NewMemoryStore() *MemoryStore { return &MemoryStore{m: map[string]memEntry{}} }

func (s *MemoryStore) Get(_ context.Context, id string) (*SessionData, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[id]
	if !ok || time.Now().After(e.exp) {
		delete(s.m, id)
		return nil, nil
	}
	var d SessionData
	return &d, json.Unmarshal(e.d, &d)
}

func (s *MemoryStore) Set(_ context.Context, id string, d *SessionData, ttl time.Duration) error {
	b, err := json.Marshal(d)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.m[id] = memEntry{d: b, exp: time.Now().Add(ttl)}
	s.mu.Unlock()
	return nil
}

func (s *MemoryStore) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	delete(s.m, id)
	s.mu.Unlock()
	return nil
}

func (s *MemoryStore) DeleteWhere(_ context.Context, match func(*SessionData) bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, e := range s.m {
		var d SessionData
		if json.Unmarshal(e.d, &d) == nil && match(&d) {
			delete(s.m, id)
		}
	}
	return nil
}

// Options configure the Manager.
type Options struct {
	Client       *moonsso.Client // confidential web client with RedirectURL set
	Store        SessionStore    // default: NewMemoryStore()
	CookieName   string          // default "moonsso_session" (prefixed __Host- when secure)
	CookieSecure bool            // set true in production (https)
	SessionTTL   time.Duration   // default 30 days (matches the SSO refresh lifetime)
	BasePath     string          // routes prefix, default "/auth"
	AfterLogin   string          // default "/"
	// PostLogoutRedirect must be registered as a post-logout redirect URI.
	PostLogoutRedirect string
	// RefreshBefore renews access tokens this long before expiry (default 2 minutes).
	RefreshBefore time.Duration
	// OnLogin runs after a successful login (e.g. to upsert the local user).
	OnLogin func(ctx context.Context, p *moonsso.Profile) error
}

// Manager implements login, callback, logout, session lookup and renewal.
type Manager struct {
	o     Options
	locks sync.Map // session id -> *sync.Mutex (single-flight refresh)
}

func New(o Options) (*Manager, error) {
	if o.Client == nil || o.Client.Config().RedirectURL == "" {
		return nil, errors.New("web: Client with RedirectURL is required")
	}
	if o.Store == nil {
		o.Store = NewMemoryStore()
	}
	if o.CookieName == "" {
		o.CookieName = "moonsso_session"
	}
	if o.CookieSecure && !strings.HasPrefix(o.CookieName, "__Host-") {
		o.CookieName = "__Host-" + o.CookieName
	}
	if o.SessionTTL <= 0 {
		o.SessionTTL = 30 * 24 * time.Hour
	}
	if o.BasePath == "" {
		o.BasePath = "/auth"
	}
	if o.AfterLogin == "" {
		o.AfterLogin = "/"
	}
	if o.RefreshBefore <= 0 {
		o.RefreshBefore = 2 * time.Minute
	}
	return &Manager{o: o}, nil
}

type ctxKey struct{}

type current struct {
	id string
	d  *SessionData
}

// Routes serves BasePath/login, /callback, /logout and /backchannel-logout.
func (m *Manager) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(m.o.BasePath+"/login", m.login)
	mux.HandleFunc(m.o.BasePath+"/callback", m.callback)
	mux.HandleFunc(m.o.BasePath+"/logout", m.logout)
	mux.Handle(m.o.BasePath+"/backchannel-logout", m.o.Client.BackchannelLogoutHandler(func(ctx context.Context, sub, sid string) error {
		return m.o.Store.DeleteWhere(ctx, func(d *SessionData) bool {
			return (sid != "" && d.SID == sid) || (sid == "" && d.Profile != nil && d.Profile.Sub == sub)
		})
	}))
	return mux
}

func newID() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (m *Manager) cookie(id string, maxAge int) *http.Cookie {
	return &http.Cookie{Name: m.o.CookieName, Value: id, Path: "/", HttpOnly: true, Secure: m.o.CookieSecure,
		SameSite: http.SameSiteLaxMode, MaxAge: maxAge}
}

func (m *Manager) load(r *http.Request) (string, *SessionData) {
	ck, err := r.Cookie(m.o.CookieName)
	if err != nil || ck.Value == "" || len(ck.Value) > 100 {
		return "", nil
	}
	d, err := m.o.Store.Get(r.Context(), ck.Value)
	if err != nil || d == nil {
		return ck.Value, nil
	}
	return ck.Value, d
}

// redirect sends a browser (or HTMX) redirect.
func redirect(w http.ResponseWriter, r *http.Request, to string) {
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", to)
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, to, http.StatusFound)
}

func safeReturn(s string) string {
	if s == "" || !strings.HasPrefix(s, "/") || strings.HasPrefix(s, "//") || strings.HasPrefix(s, "/\\") {
		return ""
	}
	return s
}

func (m *Manager) startLogin(w http.ResponseWriter, r *http.Request, ret string, silent bool) {
	opts := moonsso.AuthOptions{}
	if silent {
		opts.Prompt = "none"
	}
	if h := r.URL.Query().Get("login_hint"); h != "" {
		opts.LoginHint = h
	}
	ar, err := m.o.Client.AuthCodeURL(r.Context(), opts)
	if err != nil {
		http.Error(w, "SSO unavailable", http.StatusBadGateway)
		return
	}
	id, d := m.load(r)
	if d == nil || id == "" {
		id, d = newID(), &SessionData{}
	}
	d.Pending, d.Return, d.Silent = ar, ret, silent
	if err := m.o.Store.Set(r.Context(), id, d, m.o.SessionTTL); err != nil {
		http.Error(w, "session store error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, m.cookie(id, int(m.o.SessionTTL.Seconds())))
	redirect(w, r, ar.URL)
}

func (m *Manager) login(w http.ResponseWriter, r *http.Request) {
	ret := safeReturn(r.URL.Query().Get("return_to"))
	if ret == "" {
		ret = m.o.AfterLogin
	}
	m.startLogin(w, r, ret, r.URL.Query().Get("silent") == "1")
}

func (m *Manager) callback(w http.ResponseWriter, r *http.Request) {
	id, d := m.load(r)
	if d == nil || d.Pending == nil {
		redirect(w, r, m.o.BasePath+"/login")
		return
	}
	ar, ret, silent := d.Pending, d.Return, d.Silent
	d.Pending, d.Silent = nil, false
	q := r.URL.Query()
	if silent && (q.Get("error") == "login_required" || q.Get("error") == "consent_required" || q.Get("error") == "interaction_required") {
		// Silent re-authentication failed: show the login page.
		m.startLogin(w, r, ret, false)
		return
	}
	tok, claims, err := m.o.Client.Exchange(r.Context(), ar, q)
	if err != nil {
		var e *moonsso.Error
		if errors.As(err, &e) && e.Code == "access_denied" {
			http.Error(w, "登录已取消", http.StatusForbidden)
			return
		}
		http.Error(w, "登录失败，请重试", http.StatusBadRequest)
		return
	}
	// New session id after login (session fixation defence).
	_ = m.o.Store.Delete(r.Context(), id)
	id = newID()
	nd := &SessionData{Token: tok, SID: claims.String("sid")}
	nd.Profile = profileOf(claims)
	if m.o.OnLogin != nil {
		if err := m.o.OnLogin(r.Context(), nd.Profile); err != nil {
			http.Error(w, "登录处理失败", http.StatusInternalServerError)
			return
		}
	}
	if err := m.o.Store.Set(r.Context(), id, nd, m.o.SessionTTL); err != nil {
		http.Error(w, "session store error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, m.cookie(id, int(m.o.SessionTTL.Seconds())))
	if ret == "" {
		ret = m.o.AfterLogin
	}
	http.Redirect(w, r, ret, http.StatusFound)
}

func profileOf(c moonsso.Claims) *moonsso.Profile {
	p := &moonsso.Profile{Sub: c.Subject(), PreferredUsername: c.String("preferred_username"), Name: c.String("name"),
		Nickname: c.String("nickname"), UpdatedAt: c.Int("updated_at"), ProfileVersion: uint64(c.Int("profile_version"))}
	if pic := c.String("picture"); pic != "" {
		p.Picture = &pic
	}
	return p
}

func (m *Manager) logout(w http.ResponseWriter, r *http.Request) {
	id, d := m.load(r)
	idHint := ""
	if d != nil && d.Token != nil {
		idHint = d.Token.IDToken
		if d.Token.RefreshToken != "" {
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			_ = m.o.Client.Revoke(ctx, d.Token.RefreshToken)
			cancel()
		}
	}
	if id != "" {
		_ = m.o.Store.Delete(r.Context(), id)
	}
	http.SetCookie(w, m.cookie("", -1))
	if m.o.PostLogoutRedirect != "" {
		if u, err := m.o.Client.EndSessionURL(r.Context(), idHint, m.o.PostLogoutRedirect, ""); err == nil {
			redirect(w, r, u)
			return
		}
	}
	redirect(w, r, "/")
}

// Require protects next: anonymous visitors are sent to the SSO (silently
// first when they had a session), and tokens are renewed transparently.
func (m *Manager) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, d := m.load(r)
		ret := r.URL.RequestURI()
		if r.Method != http.MethodGet {
			ret = r.Header.Get("HX-Current-URL")
			if u, err := url.Parse(ret); err == nil {
				ret = u.RequestURI()
			}
		}
		if d == nil || d.Token == nil {
			m.startLogin(w, r, safeReturn(ret), false)
			return
		}
		if err := m.ensureFresh(r.Context(), id, d); err != nil {
			if errors.Is(err, moonsso.ErrSessionExpired) {
				_ = m.o.Store.Delete(r.Context(), id)
				m.startLogin(w, r, safeReturn(ret), true)
				return
			}
			if d.Token.Remaining() <= 0 {
				http.Error(w, "SSO 暂时不可用，请稍后重试", http.StatusServiceUnavailable)
				return
			}
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, &current{id: id, d: d})))
	})
}

func (m *Manager) lock(id string) *sync.Mutex {
	v, _ := m.locks.LoadOrStore(id, &sync.Mutex{})
	return v.(*sync.Mutex)
}

// ensureFresh refreshes the session's access token if it is about to expire.
func (m *Manager) ensureFresh(ctx context.Context, id string, d *SessionData) error {
	if d.Token.Remaining() > m.o.RefreshBefore {
		return nil
	}
	mu := m.lock(id)
	mu.Lock()
	defer mu.Unlock()
	// Another request may have refreshed already.
	if fresh, err := m.o.Store.Get(ctx, id); err == nil && fresh != nil && fresh.Token != nil && fresh.Token.Remaining() > m.o.RefreshBefore {
		*d = *fresh
		return nil
	}
	tok, err := m.o.Client.Refresh(ctx, d.Token.RefreshToken)
	if err != nil {
		return err
	}
	if tok.RefreshToken == "" {
		tok.RefreshToken = d.Token.RefreshToken
	}
	if tok.IDToken != "" {
		if cl, err := m.o.Client.VerifyIDToken(ctx, tok.IDToken, "", tok.AccessToken); err == nil {
			d.Profile = profileOf(cl)
		}
	}
	d.Token = tok
	return m.o.Store.Set(ctx, id, d, m.o.SessionTTL)
}

// Profile returns the signed-in user's profile inside a Require'd handler.
func Profile(r *http.Request) *moonsso.Profile {
	if c, ok := r.Context().Value(ctxKey{}).(*current); ok {
		return c.d.Profile
	}
	return nil
}

// AccessToken returns the user's current access token inside a Require'd
// handler, e.g. to call /api/v1/me or your own APIs.
func AccessToken(r *http.Request) string {
	if c, ok := r.Context().Value(ctxKey{}).(*current); ok && c.d.Token != nil {
		return c.d.Token.AccessToken
	}
	return ""
}

// Bearer protects an API with access-token verification (resource server).
// audience defaults to the client's id.
func Bearer(c *moonsso.Client, next http.Handler, audience ...string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := r.Header.Get("Authorization")
		if len(h) < 8 || !strings.EqualFold(h[:7], "Bearer ") {
			w.Header().Set("WWW-Authenticate", `Bearer`)
			http.Error(w, `{"error":"invalid_request"}`, http.StatusUnauthorized)
			return
		}
		claims, err := c.VerifyAccessToken(r.Context(), strings.TrimSpace(h[7:]), audience...)
		if err != nil {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			http.Error(w, `{"error":"invalid_token"}`, http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), claimsKey{}, claims)))
	})
}

type claimsKey struct{}

// TokenClaims returns the verified access-token claims inside a Bearer handler.
func TokenClaims(r *http.Request) moonsso.Claims {
	c, _ := r.Context().Value(claimsKey{}).(moonsso.Claims)
	return c
}

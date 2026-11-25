package moonsso

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// WebhookVerifier checks Standard Webhooks signatures sent by Moon SSO.
type WebhookVerifier struct {
	key       []byte
	Tolerance time.Duration // default 5 minutes
}

// NewWebhookVerifier takes the "whsec_..." secret shown when the webhook was configured.
func NewWebhookVerifier(secret string) (*WebhookVerifier, error) {
	key, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(secret, "whsec_"))
	if err != nil || len(key) == 0 {
		return nil, errors.New("moonsso: invalid webhook secret")
	}
	return &WebhookVerifier{key: key, Tolerance: 5 * time.Minute}, nil
}

// Sign computes the v1 signature (exported for tests and tooling).
func (v *WebhookVerifier) Sign(id string, ts int64, body []byte) string {
	m := hmac.New(sha256.New, v.key)
	m.Write([]byte(id + "." + strconv.FormatInt(ts, 10) + "."))
	m.Write(body)
	return "v1," + base64.StdEncoding.EncodeToString(m.Sum(nil))
}

// Verify checks the headers against body and decodes the event.
func (v *WebhookVerifier) Verify(h http.Header, body []byte) (*Event, error) {
	id, tsRaw, sigs := h.Get("webhook-id"), h.Get("webhook-timestamp"), h.Get("webhook-signature")
	if id == "" || tsRaw == "" || sigs == "" {
		return nil, errors.New("moonsso: missing webhook headers")
	}
	ts, err := strconv.ParseInt(tsRaw, 10, 64)
	if err != nil {
		return nil, errors.New("moonsso: bad webhook timestamp")
	}
	tol := v.Tolerance
	if tol <= 0 {
		tol = 5 * time.Minute
	}
	if d := time.Since(time.Unix(ts, 0)); d > tol || d < -tol {
		return nil, errors.New("moonsso: webhook timestamp outside tolerance")
	}
	want := v.Sign(id, ts, body)
	ok := false
	for _, s := range strings.Fields(sigs) {
		if hmac.Equal([]byte(s), []byte(want)) {
			ok = true
		}
	}
	if !ok {
		return nil, errors.New("moonsso: webhook signature mismatch")
	}
	var ev Event
	if err := json.Unmarshal(body, &ev); err != nil {
		return nil, errors.New("moonsso: malformed webhook body")
	}
	return &ev, nil
}

// Handler returns an http.Handler that verifies deliveries and calls fn.
// fn returning an error makes the SSO retry the delivery later.
func (v *WebhookVerifier) Handler(fn func(context.Context, *Event) error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		ev, err := v.Verify(r.Header, body)
		if err != nil {
			http.Error(w, "invalid signature", http.StatusUnauthorized)
			return
		}
		if err := fn(r.Context(), ev); err != nil {
			http.Error(w, "retry later", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

// ---- back-channel logout ----

// LogoutToken is a verified OIDC back-channel logout request.
type LogoutToken struct {
	Sub string
	SID string
}

type jtiCache struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

var logoutJTIs = &jtiCache{seen: map[string]time.Time{}}

func (j *jtiCache) firstUse(jti string) bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	now := time.Now()
	for k, exp := range j.seen {
		if now.After(exp) {
			delete(j.seen, k)
		}
	}
	if _, ok := j.seen[jti]; ok {
		return false
	}
	j.seen[jti] = now.Add(5 * time.Minute)
	return true
}

// VerifyLogoutToken validates a back-channel logout token (OIDC
// Back-Channel Logout 1.0 §2.6).
func (c *Client) VerifyLogoutToken(ctx context.Context, token string) (*LogoutToken, error) {
	payload, err := c.verifyJWS(ctx, token, "logout+jwt")
	if err != nil {
		return nil, err
	}
	var cl Claims
	if err := json.Unmarshal(payload, &cl); err != nil {
		return nil, errors.New("moonsso: malformed logout token")
	}
	now := time.Now()
	switch {
	case cl.String("iss") != c.cfg.Issuer:
		return nil, errors.New("moonsso: logout token issuer mismatch")
	case !slices.Contains(cl.Audience(), c.cfg.ClientID):
		return nil, errors.New("moonsso: logout token audience mismatch")
	case cl.Int("iat") == 0 || time.Unix(cl.Int("iat"), 0).After(now.Add(leeway)):
		return nil, errors.New("moonsso: logout token iat invalid")
	case cl.Int("exp") != 0 && now.After(time.Unix(cl.Int("exp"), 0).Add(leeway)):
		return nil, errors.New("moonsso: logout token expired")
	case cl["nonce"] != nil:
		return nil, errors.New("moonsso: logout token must not contain nonce")
	case cl.Subject() == "" && cl.String("sid") == "":
		return nil, errors.New("moonsso: logout token without sub or sid")
	}
	events, _ := cl["events"].(map[string]any)
	if _, ok := events["http://schemas.openid.net/event/backchannel-logout"]; !ok {
		return nil, errors.New("moonsso: logout token without logout event")
	}
	if jti := cl.String("jti"); jti == "" || !logoutJTIs.firstUse(c.cfg.ClientID+"|"+jti) {
		return nil, errors.New("moonsso: logout token replayed")
	}
	return &LogoutToken{Sub: cl.Subject(), SID: cl.String("sid")}, nil
}

// BackchannelLogoutHandler serves the back-channel logout endpoint and calls
// fn to end the matching local sessions.
func (c *Client) BackchannelLogoutHandler(fn func(ctx context.Context, sub, sid string) error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		lt, err := c.VerifyLogoutToken(r.Context(), r.PostFormValue("logout_token"))
		if err != nil {
			http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
			return
		}
		if err := fn(r.Context(), lt.Sub, lt.SID); err != nil {
			http.Error(w, "logout failed", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
}

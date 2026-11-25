// Package moonsso is the Go SDK for Moon SSO (https://sso.moonl.cloud).
//
// It covers every way an application integrates with the SSO:
//
//   - server-side web apps: authorization code + PKCE, sessions with silent
//     token renewal (see the web subpackage);
//   - desktop and CLI apps: system browser + loopback redirect, OS secure
//     storage, cross-process safe refresh (see the desktop subpackage);
//   - first-party apps: in-app username/password login and registration;
//   - resource servers: access-token verification;
//   - profile sync: account API, live events (SSE), signed webhooks,
//     back-channel logout and the changes feed.
//
// The behaviour follows docs/sdk-spec.md, which all language SDKs share.
package moonsso

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Version of this SDK, sent in the User-Agent header.
const Version = "1.0.0"

// Config configures a Client.
type Config struct {
	// Issuer is the SSO base URL, e.g. "https://sso.moonl.cloud".
	Issuer       string
	ClientID     string
	ClientSecret string // empty for public clients (desktop, mobile, SPA)
	// RedirectURL is the registered callback (web apps). Desktop apps leave it
	// empty; the desktop package picks a loopback URL.
	RedirectURL string
	// Scopes requested at login. Default: openid profile offline_access.
	Scopes []string
	// DPoP binds refresh tokens of public clients to a key (recommended, and
	// mandatory when the client was registered with require_dpop).
	DPoP *DPoPKey
	// HTTPClient used for all requests. Default: a client with a 15s timeout.
	HTTPClient *http.Client
	// UserAgent suffix appended to the SDK's own user agent.
	UserAgent string
}

// Client talks to one SSO issuer as one OAuth client. It is safe for concurrent use.
type Client struct {
	cfg  Config
	http *http.Client
	ua   string

	discMu  sync.Mutex
	disc    *Discovery
	discExp time.Time

	jwks  *jwksCache
	dpop  *dpopState
	ccMu  sync.Mutex
	ccTok map[string]*Token
}

// NewClient validates cfg and returns a Client. Discovery happens lazily.
func NewClient(cfg Config) (*Client, error) {
	cfg.Issuer = strings.TrimSuffix(cfg.Issuer, "/")
	u, err := url.Parse(cfg.Issuer)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, fmt.Errorf("moonsso: invalid issuer %q", cfg.Issuer)
	}
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("moonsso: ClientID is required")
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid", "profile", "offline_access"}
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}
	ua := "moon-sso-sdk-go/" + Version
	if cfg.UserAgent != "" {
		ua += " " + cfg.UserAgent
	}
	c := &Client{cfg: cfg, http: hc, ua: ua, ccTok: map[string]*Token{}}
	c.jwks = newJWKSCache(c)
	if cfg.DPoP != nil {
		c.dpop = &dpopState{key: cfg.DPoP}
	}
	return c, nil
}

// Config returns the client configuration.
func (c *Client) Config() Config { return c.cfg }

// IsPublic reports whether the client authenticates without a secret.
func (c *Client) IsPublic() bool { return c.cfg.ClientSecret == "" }

// Discovery is the subset of the OpenID Provider metadata the SDK uses.
type Discovery struct {
	Issuer                         string `json:"issuer"`
	AuthorizationEndpoint          string `json:"authorization_endpoint"`
	TokenEndpoint                  string `json:"token_endpoint"`
	UserinfoEndpoint               string `json:"userinfo_endpoint"`
	JWKSURI                        string `json:"jwks_uri"`
	RegistrationEndpoint           string `json:"registration_endpoint"`
	RevocationEndpoint             string `json:"revocation_endpoint"`
	IntrospectionEndpoint          string `json:"introspection_endpoint"`
	EndSessionEndpoint             string `json:"end_session_endpoint"`
	AuthorizationChallengeEndpoint string `json:"authorization_challenge_endpoint"`
	APIAudience                    string `json:"moon_api_audience"`
	EventsEndpoint                 string `json:"moon_events_endpoint"`
}

// Discover fetches (and caches for an hour) the provider metadata. A stale
// copy is used when a refresh fails.
func (c *Client) Discover(ctx context.Context) (*Discovery, error) {
	c.discMu.Lock()
	defer c.discMu.Unlock()
	if c.disc != nil && time.Now().Before(c.discExp) {
		return c.disc, nil
	}
	var d Discovery
	err := c.getJSON(ctx, c.cfg.Issuer+"/.well-known/openid-configuration", &d)
	if err == nil && d.Issuer != c.cfg.Issuer {
		err = fmt.Errorf("moonsso: discovery issuer %q does not match %q", d.Issuer, c.cfg.Issuer)
	}
	if err != nil {
		if c.disc != nil {
			return c.disc, nil
		}
		return nil, err
	}
	c.disc, c.discExp = &d, time.Now().Add(time.Hour)
	return c.disc, nil
}

func (c *Client) endpoint(ctx context.Context, pick func(*Discovery) string, fallback string) (string, error) {
	d, err := c.Discover(ctx)
	if err != nil {
		return "", err
	}
	if v := pick(d); v != "" {
		return v, nil
	}
	return c.cfg.Issuer + fallback, nil
}

func (c *Client) newRequest(ctx context.Context, method, u string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.ua)
	req.Header.Set("Accept", "application/json")
	return req, nil
}

func (c *Client) getJSON(ctx context.Context, u string, out any) error {
	req, err := c.newRequest(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return &Error{Code: "network", Description: err.Error()}
	}
	defer resp.Body.Close()
	return decodeResponse(resp, out)
}

// decodeResponse maps non-2xx answers to *Error and decodes JSON bodies.
func decodeResponse(resp *http.Response, out any) error {
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return &Error{Code: "network", Description: err.Error(), Status: resp.StatusCode}
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		e := &Error{Status: resp.StatusCode}
		var raw map[string]any
		if json.Unmarshal(body, &raw) == nil {
			e.Code, _ = raw["error"].(string)
			e.Description, _ = raw["error_description"].(string)
			e.Field, _ = raw["field"].(string)
			e.Extra = raw
		}
		if e.Code == "" {
			e.Code = "http_" + fmt.Sprint(resp.StatusCode)
			e.Description = strings.TrimSpace(string(body))
		}
		return e
	}
	if out == nil || len(body) == 0 {
		return nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return &Error{Code: "invalid_response", Description: err.Error(), Status: resp.StatusCode}
	}
	return nil
}

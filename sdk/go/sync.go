package moonsso

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
)

// ChangesPage is one page of the changes feed.
type ChangesPage struct {
	Events     []Event `json:"events"`
	NextCursor string  `json:"next_cursor"`
	HasMore    bool    `json:"has_more"`
}

// UsersPage is one page of the bulk user snapshot.
type UsersPage struct {
	Users      []Profile `json:"users"`
	NextCursor string    `json:"next_cursor"`
	HasMore    bool      `json:"has_more"`
	Watermark  string    `json:"watermark"`
}

// ErrCursorExpired means the cursor is older than the retention window; run
// a full sync with Users and continue from its watermark.
var ErrCursorExpired = errors.New("moonsso: changes cursor expired; full resync required")

func (c *Client) syncGet(ctx context.Context, path string, q url.Values, out any) error {
	tok, err := c.ClientCredentials(ctx, "users:sync")
	if err != nil {
		return err
	}
	req, err := c.newRequest(ctx, http.MethodGet, c.cfg.Issuer+path+"?"+q.Encode(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	resp, err := c.http.Do(req)
	if err != nil {
		return &Error{Code: "network", Description: err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusGone {
		return ErrCursorExpired
	}
	return decodeResponse(resp, out)
}

// Changes returns events for users who authorized this client after cursor
// ("" or "0" for the start). Requires a confidential client with the
// users:sync scope.
func (c *Client) Changes(ctx context.Context, cursor string, limit int) (*ChangesPage, error) {
	q := url.Values{"cursor": {cursor}}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	var p ChangesPage
	return &p, c.syncGet(ctx, "/api/v1/users/changes", q, &p)
}

// Users returns one page of the current snapshot of authorized users.
func (c *Client) Users(ctx context.Context, cursor string, limit int) (*UsersPage, error) {
	q := url.Values{}
	if cursor != "" {
		q.Set("cursor", cursor)
	}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	var p UsersPage
	return &p, c.syncGet(ctx, "/api/v1/users", q, &p)
}

// Sync applies all changes after cursor and returns the new cursor. On an
// expired cursor it performs a full resync through onSnapshot first. Persist
// the returned cursor after the handlers succeed.
func (c *Client) Sync(ctx context.Context, cursor string, onEvent func(Event) error, onSnapshot func(Profile) error) (string, error) {
	for {
		page, err := c.Changes(ctx, cursor, 500)
		if errors.Is(err, ErrCursorExpired) {
			cursor, err = c.fullSync(ctx, onSnapshot)
			if err != nil {
				return cursor, err
			}
			continue
		}
		if err != nil {
			return cursor, err
		}
		for _, ev := range page.Events {
			if err := onEvent(ev); err != nil {
				return cursor, err
			}
			cursor = strconv.FormatUint(ev.Seq, 10)
		}
		if page.NextCursor != "" {
			cursor = page.NextCursor
		}
		if !page.HasMore {
			return cursor, nil
		}
	}
}

func (c *Client) fullSync(ctx context.Context, onSnapshot func(Profile) error) (string, error) {
	var watermark, next string
	for first := true; first || next != ""; first = false {
		page, err := c.Users(ctx, next, 500)
		if err != nil {
			return "", err
		}
		if first {
			watermark = page.Watermark
		}
		for _, u := range page.Users {
			if err := onSnapshot(u); err != nil {
				return "", err
			}
		}
		next = ""
		if page.HasMore {
			next = page.NextCursor
		}
	}
	return watermark, nil
}

// ---- dynamic client registration ----

// ClientMetadata is RFC 7591 client metadata accepted by Moon SSO.
type ClientMetadata struct {
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	PostLogoutRedirectURIs  []string `json:"post_logout_redirect_uris,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	ApplicationType         string   `json:"application_type,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
	BackchannelLogoutURI    string   `json:"backchannel_logout_uri,omitempty"`
	DPoPBoundAccessTokens   bool     `json:"dpop_bound_access_tokens,omitempty"`
	WebhookURL              string   `json:"webhook_url,omitempty"`
	WebhookEvents           []string `json:"webhook_events,omitempty"`
	LogoURI                 string   `json:"logo_uri,omitempty"`
	ClientURI               string   `json:"client_uri,omitempty"`
	PolicyURI               string   `json:"policy_uri,omitempty"`
	TOSURI                  string   `json:"tos_uri,omitempty"`
}

// ClientInformation is the registration result. Secrets appear only once.
type ClientInformation struct {
	ClientMetadata
	ClientID                string `json:"client_id"`
	ClientSecret            string `json:"client_secret,omitempty"`
	RegistrationAccessToken string `json:"registration_access_token,omitempty"`
	RegistrationClientURI   string `json:"registration_client_uri"`
	WebhookSecret           string `json:"webhook_secret,omitempty"`
	Status                  string `json:"status"` // active | pending_approval
}

// RegisterClient registers an application with an initial access token from
// the developer center (RFC 7591).
func RegisterClient(ctx context.Context, issuer, initialAccessToken string, m ClientMetadata) (*ClientInformation, error) {
	b, _ := json.Marshal(m)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, issuer+"/oauth/register", bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+initialAccessToken)
	req.Header.Set("User-Agent", "moon-sso-sdk-go/"+Version)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, &Error{Code: "network", Description: err.Error()}
	}
	defer resp.Body.Close()
	var ci ClientInformation
	return &ci, decodeResponse(resp, &ci)
}

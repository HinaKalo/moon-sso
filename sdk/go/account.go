package moonsso

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

// Profile is the user as this client sees it (sub is client-specific).
type Profile struct {
	Sub               string  `json:"sub"`
	PreferredUsername string  `json:"preferred_username"`
	Name              string  `json:"name"`
	Nickname          string  `json:"nickname"`
	Picture           *string `json:"picture"`
	UpdatedAt         int64   `json:"updated_at"`
	ProfileVersion    uint64  `json:"profile_version"`
	TOTPEnabled       bool    `json:"totp_enabled"`
	Status            string  `json:"status,omitempty"`
}

func profileFromClaims(c Claims) *Profile {
	p := &Profile{Sub: c.Subject(), PreferredUsername: c.String("preferred_username"), Name: c.String("name"),
		Nickname: c.String("nickname"), UpdatedAt: c.Int("updated_at"), ProfileVersion: uint64(c.Int("profile_version"))}
	if pic := c.String("picture"); pic != "" {
		p.Picture = &pic
	}
	return p
}

// do sends an authenticated API request and decodes the JSON answer.
func (s *Session) do(ctx context.Context, method, path string, body io.Reader, ctype string, out any) error {
	req, err := s.c.newRequest(ctx, method, s.c.cfg.Issuer+path, body)
	if err != nil {
		return err
	}
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	resp, err := s.HTTPClient().Do(req)
	if err != nil {
		var e *Error
		if errorsAs(err, &e) {
			return e
		}
		if err == ErrSessionExpired || err == ErrNotSignedIn {
			return err
		}
		return &Error{Code: "network", Description: err.Error()}
	}
	defer resp.Body.Close()
	return decodeResponse(resp, out)
}

// GetMe fetches the current profile and updates the cache.
func (s *Session) GetMe(ctx context.Context) (*Profile, error) {
	var p Profile
	if err := s.do(ctx, http.MethodGet, "/api/v1/me", nil, "", &p); err != nil {
		return nil, err
	}
	s.setProfile(ctx, &p)
	return &p, nil
}

// ProfileUpdate changes username and/or nickname; nil fields stay unchanged.
type ProfileUpdate struct {
	Username    *string `json:"username,omitempty"`
	DisplayName *string `json:"display_name,omitempty"`
}

// UpdateProfile requires scope profile:write. The change is propagated to
// every application the user has authorized.
func (s *Session) UpdateProfile(ctx context.Context, u ProfileUpdate) (*Profile, error) {
	b, _ := json.Marshal(u)
	var p Profile
	if err := s.do(ctx, http.MethodPatch, "/api/v1/me", bytes.NewReader(b), "application/json", &p); err != nil {
		return nil, err
	}
	s.setProfile(ctx, &p)
	return &p, nil
}

// UploadAvatar sets the avatar from image bytes (PNG, JPEG, GIF or WebP, ≤5 MB).
func (s *Session) UploadAvatar(ctx context.Context, image []byte, contentType string) (*Profile, error) {
	if contentType == "" {
		contentType = http.DetectContentType(image)
	}
	var p Profile
	if err := s.do(ctx, http.MethodPut, "/api/v1/me/avatar", bytes.NewReader(image), contentType, &p); err != nil {
		return nil, err
	}
	s.setProfile(ctx, &p)
	return &p, nil
}

// DeleteAvatar removes the avatar.
func (s *Session) DeleteAvatar(ctx context.Context) (*Profile, error) {
	var p Profile
	if err := s.do(ctx, http.MethodDelete, "/api/v1/me/avatar", nil, "", &p); err != nil {
		return nil, err
	}
	s.setProfile(ctx, &p)
	return &p, nil
}

// ChangePassword requires scope password:write. Other devices are signed
// out; this one stays signed in unless keepThisDevice is false.
func (s *Session) ChangePassword(ctx context.Context, current, next string, keepThisDevice bool) error {
	b, _ := json.Marshal(map[string]any{"current_password": current, "new_password": next, "keep_this_device": keepThisDevice})
	return s.do(ctx, http.MethodPost, "/api/v1/me/password", bytes.NewReader(b), "application/json", nil)
}

// ---- registration ----

// RegistrationInfo describes whether self-service registration is open.
type RegistrationInfo struct {
	RegistrationOpen   bool   `json:"registration_open"`
	PasswordMinLength  int    `json:"password_min_length"`
	UsernamePattern    string `json:"username_pattern"`
	ClientRegistration string `json:"client_registration"`
}

func (c *Client) RegistrationInfo(ctx context.Context) (*RegistrationInfo, error) {
	var ri RegistrationInfo
	return &ri, c.getJSON(ctx, c.cfg.Issuer+"/api/v1/registration", &ri)
}

// RegisterUser creates an account from an application's server (client
// authentication required). The user then signs in normally; pass the
// username as login hint.
func (c *Client) RegisterUser(ctx context.Context, username, password, displayName string) error {
	b, _ := json.Marshal(map[string]string{"username": username, "password": password, "display_name": displayName})
	req, err := c.newRequest(ctx, http.MethodPost, c.cfg.Issuer+"/api/v1/register", bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.IsPublic() {
		q := req.URL.Query()
		q.Set("client_id", c.cfg.ClientID)
		req.URL.RawQuery = q.Encode()
	} else {
		req.SetBasicAuth(c.cfg.ClientID, c.cfg.ClientSecret)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return &Error{Code: "network", Description: err.Error()}
	}
	defer resp.Body.Close()
	return decodeResponse(resp, nil)
}

func errorsAs(err error, target any) bool { return errors.As(err, target) }

package clients

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"moon-sso/server/internal/store"
)

// flagsJSON is the API representation of administrator-only client flags.
type flagsJSON struct {
	FirstParty            bool   `json:"first_party"`
	NativeLogin           bool   `json:"native_login"`
	SkipConsent           bool   `json:"skip_consent"`
	AllowRegistration     bool   `json:"allow_registration"`
	Verified              bool   `json:"verified"`
	RequireOTP            bool   `json:"require_otp"`
	SubjectType           string `json:"subject_type"`
	WebhookAllowInsecure  bool   `json:"webhook_allow_insecure"`
	AccessTokenTTLSeconds *int   `json:"access_token_ttl_seconds"`
}

func metadataJSONOf(c *store.Client) dcrMetadata {
	return dcrMetadata{ClientName: c.Name, Description: c.Description, ClientURI: c.ClientURI, LogoURI: c.LogoURI, PolicyURI: c.PolicyURI,
		TOSURI: c.TOSURI, RedirectURIs: c.RedirectURIs, PostLogoutRedirectURIs: c.PostLogoutRedirectURIs, GrantTypes: c.GrantTypes,
		TokenEndpointAuthMethod: c.TokenEndpointAuthMethod, ApplicationType: c.ApplicationType, Scope: strings.Join(c.Scopes, " "),
		IDTokenSignedAlg: c.IDTokenAlg, BackchannelLogoutURI: c.BackchannelLogoutURI, RequireDPoP: &c.RequireDPoP,
		WebhookURL: c.WebhookURL, WebhookEvents: c.WebhookEvents}
}

func flagsJSONOf(c *store.Client) flagsJSON {
	return flagsJSON{FirstParty: c.FirstParty, NativeLogin: c.NativeLogin, SkipConsent: c.SkipConsent, AllowRegistration: c.AllowRegistration,
		Verified: c.Verified, RequireOTP: c.RequireAMR == "otp", SubjectType: c.SubjectType, WebhookAllowInsecure: c.WebhookAllowInsecure,
		AccessTokenTTLSeconds: c.AccessTokenTTLSeconds}
}

func (f flagsJSON) toFlags() (*AdminFlags, error) {
	out := &AdminFlags{FirstParty: f.FirstParty, NativeLogin: f.NativeLogin, SkipConsent: f.SkipConsent, AllowRegistration: f.AllowRegistration,
		Verified: f.Verified, SubjectType: f.SubjectType, WebhookAllowInsecure: f.WebhookAllowInsecure, AccessTokenTTL: f.AccessTokenTTLSeconds}
	if f.RequireOTP {
		out.RequireAMR = "otp"
	}
	if f.SubjectType != "public" && f.SubjectType != "pairwise" {
		return nil, ferr("subject_type", "subject_type 只能是 public 或 pairwise")
	}
	if t := f.AccessTokenTTLSeconds; t != nil && (*t < 60 || *t > 3600) {
		return nil, ferr("access_token_ttl_seconds", "access_token_ttl_seconds 需在 60–3600 之间")
	}
	return out, nil
}

// Fields that appear in responses but cannot be written. They are dropped
// from request bodies so a fetched app can be edited and sent back as is.
var (
	readOnlyFields = []string{"client_id", "client_id_issued_at", "registration_client_uri", "status", "created_at", "updated_at",
		"has_client_secret", "client_secret_rotated_at", "webhook_state", "owner", "client_secret", "client_secret_expires_at",
		"registration_access_token", "webhook_secret"}
	developerReadOnly = []string{"subject_type", "verified"}
)

func dropReadOnly(body []byte, withFlags bool) ([]byte, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, ferr("", "请求体必须是 JSON 对象")
	}
	drop := readOnlyFields
	if !withFlags {
		drop = append(append([]string{}, readOnlyFields...), developerReadOnly...)
	}
	for _, k := range drop {
		delete(m, k)
	}
	return json.Marshal(m)
}

// DecodeJSON reads client metadata in RFC 7591 field names. With base set
// the body is a partial update (PATCH): omitted fields keep their values.
// withFlags also accepts the administrator-only flags. Unknown fields are
// rejected, so a typo (or a developer sending an admin flag) fails loudly.
func DecodeJSON(r io.Reader, base *store.Client, withFlags bool) (Metadata, *AdminFlags, error) {
	body, err := io.ReadAll(io.LimitReader(r, 64<<10))
	if err != nil {
		return Metadata{}, nil, err
	}
	if len(bytes.TrimSpace(body)) == 0 {
		body = []byte("{}")
	}
	if body, err = dropReadOnly(body, withFlags); err != nil {
		return Metadata{}, nil, err
	}
	var meta dcrMetadata
	flags := flagsJSON{SubjectType: "pairwise"}
	if base != nil {
		meta, flags = metadataJSONOf(base), flagsJSONOf(base)
	}
	var target any = &meta
	if withFlags {
		target = &struct {
			*dcrMetadata
			*flagsJSON
		}{&meta, &flags}
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		var se *json.SyntaxError
		var te *json.UnmarshalTypeError
		switch {
		case errors.As(err, &te):
			return Metadata{}, nil, ferr(te.Field, "字段 "+te.Field+" 的类型不正确")
		case errors.As(err, &se), errors.Is(err, io.ErrUnexpectedEOF):
			return Metadata{}, nil, ferr("", "请求体不是合法的 JSON")
		case strings.HasPrefix(err.Error(), "json: unknown field "):
			f := strings.Trim(strings.TrimPrefix(err.Error(), "json: unknown field "), `"`)
			return Metadata{}, nil, ferr(f, "不支持的字段："+f)
		}
		return Metadata{}, nil, ferr("", "请求体必须是 JSON 对象")
	}
	m, err := meta.toMetadata()
	if err != nil {
		return Metadata{}, nil, err
	}
	if !withFlags {
		return m, nil, nil
	}
	f, err := flags.toFlags()
	if err != nil {
		return Metadata{}, nil, err
	}
	return m, f, nil
}

// Describe is the developer-facing JSON view of an app (RFC 7591 names);
// creds adds secrets that are shown only once.
func (s *Service) Describe(c *store.Client, creds *Credentials) map[string]any {
	out := s.describe(c, creds)
	out["created_at"] = c.CreatedAt.UTC().Format(time.RFC3339)
	out["updated_at"] = c.UpdatedAt.UTC().Format(time.RFC3339)
	out["verified"] = c.Verified
	out["has_client_secret"] = len(c.SecretHash) > 0
	if c.SecretRotatedAt != nil {
		out["client_secret_rotated_at"] = c.SecretRotatedAt.UTC().Format(time.RFC3339)
	}
	wh := map[string]any{"configured": c.WebhookURL != "", "last_error": c.WebhookLastError, "failing_since": c.WebhookFailSince,
		"disabled_at": c.WebhookDisabledAt, "cursor_seq": c.WebhookCursorSeq}
	out["webhook_state"] = wh
	return out
}

// DescribeAdmin adds administrator-only flags and the owner.
func (s *Service) DescribeAdmin(c *store.Client, creds *Credentials, owner string) map[string]any {
	out := s.Describe(c, creds)
	f := flagsJSONOf(c)
	out["first_party"], out["native_login"], out["skip_consent"] = f.FirstParty, f.NativeLogin, f.SkipConsent
	out["allow_registration"], out["require_otp"], out["webhook_allow_insecure"] = f.AllowRegistration, f.RequireOTP, f.WebhookAllowInsecure
	out["access_token_ttl_seconds"] = f.AccessTokenTTLSeconds
	out["owner"] = owner
	return out
}

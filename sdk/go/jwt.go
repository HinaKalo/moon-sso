package moonsso

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

var sigAlgs = []jose.SignatureAlgorithm{jose.RS256, jose.ES256}

type jwksCache struct {
	c         *Client
	mu        sync.Mutex
	set       *jose.JSONWebKeySet
	exp       time.Time
	lastForce time.Time
}

func newJWKSCache(c *Client) *jwksCache { return &jwksCache{c: c} }

func (j *jwksCache) key(ctx context.Context, kid string) (*jose.JSONWebKey, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	find := func() *jose.JSONWebKey {
		if j.set == nil {
			return nil
		}
		if ks := j.set.Key(kid); len(ks) > 0 {
			return &ks[0]
		}
		return nil
	}
	if time.Now().Before(j.exp) {
		if k := find(); k != nil {
			return k, nil
		}
		// Unknown kid: refetch at most every 30 seconds (key rotation).
		if time.Since(j.lastForce) < 30*time.Second {
			return nil, errors.New("moonsso: unknown signing key")
		}
		j.lastForce = time.Now()
	}
	u, err := j.c.endpoint(ctx, func(d *Discovery) string { return d.JWKSURI }, "/.well-known/jwks.json")
	if err != nil {
		return nil, err
	}
	var set jose.JSONWebKeySet
	if err := j.c.getJSON(ctx, u, &set); err != nil {
		if k := find(); k != nil {
			return k, nil
		}
		return nil, err
	}
	j.set, j.exp = &set, time.Now().Add(time.Hour)
	if k := find(); k != nil {
		return k, nil
	}
	return nil, errors.New("moonsso: unknown signing key")
}

// verifyJWS checks the signature of a compact JWS against the issuer's JWKS
// and the expected typ header, returning the payload.
func (c *Client) verifyJWS(ctx context.Context, token, wantTyp string) ([]byte, error) {
	jws, err := jose.ParseSignedCompact(token, sigAlgs)
	if err != nil || len(jws.Signatures) != 1 {
		return nil, errors.New("moonsso: malformed token")
	}
	h := jws.Signatures[0].Header
	if wantTyp != "" {
		if typ, _ := h.ExtraHeaders[jose.HeaderType].(string); typ != wantTyp {
			return nil, fmt.Errorf("moonsso: unexpected token type %q", typ)
		}
	}
	k, err := c.jwks.key(ctx, h.KeyID)
	if err != nil {
		return nil, err
	}
	payload, err := jws.Verify(k.Key)
	if err != nil {
		return nil, errors.New("moonsso: invalid token signature")
	}
	return payload, nil
}

// Claims is a decoded JWT claim set with typed accessors for common fields.
type Claims map[string]any

func (c Claims) String(k string) string { s, _ := c[k].(string); return s }
func (c Claims) Int(k string) int64 {
	switch v := c[k].(type) {
	case float64:
		return int64(v)
	case json.Number:
		n, _ := v.Int64()
		return n
	}
	return 0
}
func (c Claims) Subject() string { return c.String("sub") }

// Audience returns the aud claim as a list.
func (c Claims) Audience() []string {
	switch v := c["aud"].(type) {
	case string:
		return []string{v}
	case []any:
		var out []string
		for _, a := range v {
			if s, ok := a.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

const leeway = 60 * time.Second

func (c Claims) checkTime(now time.Time) error {
	if exp := c.Int("exp"); exp == 0 || now.After(time.Unix(exp, 0).Add(leeway)) {
		return errors.New("moonsso: token expired")
	}
	if nbf := c.Int("nbf"); nbf != 0 && now.Add(leeway).Before(time.Unix(nbf, 0)) {
		return errors.New("moonsso: token not yet valid")
	}
	if iat := c.Int("iat"); iat != 0 && now.Add(leeway).Before(time.Unix(iat, 0)) {
		return errors.New("moonsso: token issued in the future")
	}
	return nil
}

// VerifyIDToken validates an ID token issued to this client. nonce may be
// empty when the token came from a refresh. accessToken, when given, is
// checked against at_hash.
func (c *Client) VerifyIDToken(ctx context.Context, idToken, nonce, accessToken string) (Claims, error) {
	payload, err := c.verifyJWS(ctx, idToken, "")
	if err != nil {
		return nil, err
	}
	var cl Claims
	if err := json.Unmarshal(payload, &cl); err != nil {
		return nil, errors.New("moonsso: malformed ID token")
	}
	if cl.String("iss") != c.cfg.Issuer {
		return nil, errors.New("moonsso: ID token issuer mismatch")
	}
	if !slices.Contains(cl.Audience(), c.cfg.ClientID) {
		return nil, errors.New("moonsso: ID token audience mismatch")
	}
	if err := cl.checkTime(time.Now()); err != nil {
		return nil, err
	}
	if nonce != "" && cl.String("nonce") != nonce {
		return nil, errors.New("moonsso: ID token nonce mismatch")
	}
	if ah := cl.String("at_hash"); ah != "" && accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		if base64.RawURLEncoding.EncodeToString(sum[:16]) != ah {
			return nil, errors.New("moonsso: at_hash mismatch")
		}
	}
	return cl, nil
}

// VerifyAccessToken validates an access token for a resource server. The
// token must carry typ at+jwt, be issued by this issuer, be within its
// validity window and list audience in aud (default: this client's id).
func (c *Client) VerifyAccessToken(ctx context.Context, token string, audience ...string) (Claims, error) {
	payload, err := c.verifyJWS(ctx, token, "at+jwt")
	if err != nil {
		return nil, err
	}
	var cl Claims
	if err := json.Unmarshal(payload, &cl); err != nil {
		return nil, errors.New("moonsso: malformed access token")
	}
	if cl.String("iss") != c.cfg.Issuer {
		return nil, errors.New("moonsso: access token issuer mismatch")
	}
	if err := cl.checkTime(time.Now()); err != nil {
		return nil, err
	}
	if len(audience) == 0 {
		audience = []string{c.cfg.ClientID}
	}
	aud := cl.Audience()
	for _, want := range audience {
		if slices.Contains(aud, want) {
			return cl, nil
		}
	}
	return nil, errors.New("moonsso: access token audience mismatch")
}

package oidc

import (
	"crypto"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"moon-sso/server/internal/cache"
)

// DPoP validates RFC 9449 proofs. Nonces are stateless (an HMAC over a
// five-minute bucket) and proof jtis are remembered to prevent replay.
type DPoP struct {
	key  []byte
	jtis *cache.Cache[string, struct{}]
	now  func() time.Time
}

const dpopBucket = 300 // seconds

func NewDPoP(key []byte) *DPoP {
	return &DPoP{key: key, jtis: cache.New[string, struct{}](200_000, 10*time.Minute), now: time.Now}
}

func (d *DPoP) nonceFor(bucket int64) string {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(bucket))
	m := hmac.New(sha256.New, d.key)
	m.Write(b[:])
	return base64.RawURLEncoding.EncodeToString(append(b[:], m.Sum(nil)[:16]...))
}

// Nonce returns the current server nonce.
func (d *DPoP) Nonce() string { return d.nonceFor(d.now().Unix() / dpopBucket) }

func (d *DPoP) validNonce(n string) bool {
	raw, err := base64.RawURLEncoding.DecodeString(n)
	if err != nil || len(raw) != 24 {
		return false
	}
	bucket := int64(binary.BigEndian.Uint64(raw[:8]))
	cur := d.now().Unix() / dpopBucket
	if bucket != cur && bucket != cur-1 {
		return false
	}
	return hmac.Equal([]byte(d.nonceFor(bucket)), []byte(n))
}

type dpopClaims struct {
	Jti   string `json:"jti"`
	Htm   string `json:"htm"`
	Htu   string `json:"htu"`
	Iat   int64  `json:"iat"`
	Nonce string `json:"nonce"`
	Ath   string `json:"ath"`
}

var dpopAlgs = []jose.SignatureAlgorithm{jose.ES256, jose.ES384, jose.RS256, jose.PS256, jose.EdDSA}

// Verify checks the DPoP header of r for a request to htu. It returns the
// JWK thumbprint, or "" when no proof was sent. A missing or stale nonce
// yields a use_dpop_nonce error carrying a fresh nonce.
func (d *DPoP) Verify(r *http.Request, htu string) (string, *Error) {
	proofs := r.Header.Values("DPoP")
	if len(proofs) == 0 {
		return "", nil
	}
	if len(proofs) > 1 || len(proofs[0]) > 4096 {
		return "", errInvalidDPoP("DPoP 头只能出现一次")
	}
	jws, err := jose.ParseSignedCompact(proofs[0], dpopAlgs)
	if err != nil || len(jws.Signatures) != 1 {
		return "", errInvalidDPoP("DPoP 证明格式错误")
	}
	h := jws.Signatures[0].Header
	if typ, _ := h.ExtraHeaders[jose.HeaderType].(string); typ != "dpop+jwt" {
		return "", errInvalidDPoP("DPoP typ 必须为 dpop+jwt")
	}
	jwk := h.JSONWebKey
	if jwk == nil || !jwk.Valid() || !jwk.IsPublic() {
		return "", errInvalidDPoP("DPoP 缺少公钥")
	}
	payload, err := jws.Verify(jwk)
	if err != nil {
		return "", errInvalidDPoP("DPoP 签名无效")
	}
	var cl dpopClaims
	if err := json.Unmarshal(payload, &cl); err != nil {
		return "", errInvalidDPoP("DPoP 内容无效")
	}
	now := d.now().Unix()
	switch {
	case cl.Jti == "" || len(cl.Jti) > 128:
		return "", errInvalidDPoP("DPoP 缺少 jti")
	case cl.Htm != r.Method:
		return "", errInvalidDPoP("DPoP htm 不匹配")
	case !htuMatches(cl.Htu, htu):
		return "", errInvalidDPoP("DPoP htu 不匹配")
	case cl.Iat < now-300 || cl.Iat > now+60:
		return "", errInvalidDPoP("DPoP iat 超出允许范围")
	}
	if !d.validNonce(cl.Nonce) {
		return "", &Error{Status: http.StatusBadRequest, Code: "use_dpop_nonce", Description: "需要使用服务器提供的 DPoP nonce", DPoPNonce: d.Nonce()}
	}
	tp, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", errInvalidDPoP("DPoP 公钥无效")
	}
	jkt := base64.RawURLEncoding.EncodeToString(tp)
	key := jkt + "|" + cl.Jti
	if _, seen := d.jtis.Get(key); seen {
		return "", errInvalidDPoP("DPoP 证明已被使用")
	}
	d.jtis.Set(key, struct{}{})
	return jkt, nil
}

func htuMatches(got, want string) bool {
	if i := strings.IndexAny(got, "?#"); i >= 0 {
		got = got[:i]
	}
	return strings.EqualFold(strings.TrimSuffix(got, "/"), strings.TrimSuffix(want, "/"))
}

// validJKT checks the syntax of a dpop_jkt authorization parameter.
func validJKT(s string) bool {
	if s == "" {
		return true
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	return err == nil && len(b) == 32
}

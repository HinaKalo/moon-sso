package moonsso

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// DPoPKey is a P-256 key proving possession of DPoP-bound refresh tokens
// (RFC 9449). Keep it with the tokens in secure storage: a refresh token is
// useless without the key that it is bound to.
type DPoPKey struct {
	priv *ecdsa.PrivateKey
}

// NewDPoPKey generates a fresh key.
func NewDPoPKey() (*DPoPKey, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &DPoPKey{priv: k}, nil
}

// MarshalDPoPKey encodes the private key (PKCS#8, base64) for storage.
func MarshalDPoPKey(k *DPoPKey) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k.priv)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(der), nil
}

// ParseDPoPKey decodes a key produced by MarshalDPoPKey.
func ParseDPoPKey(s string) (*DPoPKey, error) {
	der, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, errors.New("moonsso: DPoP key must be P-256")
	}
	return &DPoPKey{priv: ec}, nil
}

// Thumbprint returns the RFC 7638 JWK thumbprint used as dpop_jkt.
func (k *DPoPKey) Thumbprint() string {
	tp, _ := (&jose.JSONWebKey{Key: k.priv.Public()}).Thumbprint(crypto.SHA256)
	return base64.RawURLEncoding.EncodeToString(tp)
}

type dpopState struct {
	key   *DPoPKey
	mu    sync.Mutex
	nonce string
}

func (d *dpopState) setNonce(n string) {
	if n == "" {
		return
	}
	d.mu.Lock()
	d.nonce = n
	d.mu.Unlock()
}

// proof builds a DPoP proof JWT for method+url using the latest server nonce.
func (d *dpopState) proof(method, u string) (string, error) {
	d.mu.Lock()
	nonce := d.nonce
	d.mu.Unlock()
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", err
	}
	claims := map[string]any{"jti": base64.RawURLEncoding.EncodeToString(jti), "htm": method, "htu": u, "iat": time.Now().Unix()}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	payload, _ := json.Marshal(claims)
	opts := (&jose.SignerOptions{EmbedJWK: true}).WithType("dpop+jwt")
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: d.key.priv}, opts)
	if err != nil {
		return "", err
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}
	return jws.CompactSerialize()
}

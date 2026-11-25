// Package crypto holds the server's cryptographic primitives: master-key
// derived subkeys, authenticated encryption for data at rest, random tokens,
// password hashing and TOTP.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Purpose labels for HKDF. Changing a label invalidates everything derived from it.
const (
	PurposeAtRest      = "moon-sso/at-rest/v1"      // AES-GCM for secrets stored in MySQL
	PurposeTokenHMAC   = "moon-sso/token-hmac/v1"   // HMAC for client secrets, RATs
	PurposePairwise    = "moon-sso/pairwise/v1"     // pairwise subject derivation
	PurposeCSRF        = "moon-sso/csrf/v1"         // CSRF tokens
	PurposeCookieAEAD  = "moon-sso/cookie-aead/v1"  // short-lived encrypted cookies
	PurposeDPoPNonce   = "moon-sso/dpop-nonce/v1"   // stateless DPoP nonces
	PurposeRefreshAEAD = "moon-sso/refresh-aead/v1" // grace-window refresh token copies
)

// Keyring derives purpose-specific keys from a 32-byte master key.
// The key id (first 4 bytes of SHA-256(master)) is stored beside every
// ciphertext so that a future master-key rotation can find the right key.
type Keyring struct {
	id     string
	master []byte
}

// LoadKeyring reads a master key file containing 32 random bytes encoded as
// hex or base64 (with or without padding).
func LoadKeyring(path string) (*Keyring, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("master key: %w", err)
	}
	return ParseKeyring(strings.TrimSpace(string(b)))
}

func ParseKeyring(s string) (*Keyring, error) {
	var key []byte
	if k, err := hex.DecodeString(s); err == nil && len(k) == 32 {
		key = k
	} else if k, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(s, "=")); err == nil && len(k) == 32 {
		key = k
	} else if k, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "=")); err == nil && len(k) == 32 {
		key = k
	} else {
		return nil, errors.New("master key must be 32 bytes encoded as hex or base64")
	}
	sum := sha256.Sum256(key)
	return &Keyring{id: hex.EncodeToString(sum[:4]), master: key}, nil
}

// GenerateMasterKey returns a new hex-encoded master key.
func GenerateMasterKey() string { return hex.EncodeToString(RandomBytes(32)) }

func (k *Keyring) ID() string { return k.id }

// Key derives a 32-byte subkey for purpose.
func (k *Keyring) Key(purpose string) []byte {
	out, err := hkdf.Key(sha256.New, k.master, nil, purpose, 32)
	if err != nil {
		panic(err) // only fails for invalid lengths
	}
	return out
}

// MAC returns HMAC-SHA256(subkey(purpose), data).
func (k *Keyring) MAC(purpose string, data ...[]byte) []byte {
	m := hmac.New(sha256.New, k.Key(purpose))
	for _, d := range data {
		m.Write(d)
	}
	return m.Sum(nil)
}

// Sealer performs AES-256-GCM with a key id prefix: kid(4 bytes) || nonce(12) || ciphertext.
type Sealer struct {
	kid  []byte
	aead cipher.AEAD
}

func (k *Keyring) Sealer(purpose string) *Sealer {
	block, err := aes.NewCipher(k.Key(purpose))
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	kid, _ := hex.DecodeString(k.id)
	return &Sealer{kid: kid, aead: aead}
}

var ErrDecrypt = errors.New("crypto: decryption failed")

func (s *Sealer) Seal(plaintext, aad []byte) []byte {
	out := make([]byte, 0, 4+12+len(plaintext)+16)
	out = append(out, s.kid...)
	nonce := RandomBytes(12)
	out = append(out, nonce...)
	return s.aead.Seal(out, nonce, plaintext, aad)
}

func (s *Sealer) Open(sealed, aad []byte) ([]byte, error) {
	if len(sealed) < 4+12+16 || !hmac.Equal(sealed[:4], s.kid) {
		return nil, ErrDecrypt
	}
	pt, err := s.aead.Open(nil, sealed[4:16], sealed[16:], aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

// RandomBytes returns n cryptographically random bytes.
func RandomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// RandomToken returns a URL-safe random string carrying n bytes of entropy.
func RandomToken(n int) string { return base64.RawURLEncoding.EncodeToString(RandomBytes(n)) }

// SHA256 returns the SHA-256 digest of s.
func SHA256(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

// ConstantTimeEqual compares two byte slices in constant time.
func ConstantTimeEqual(a, b []byte) bool { return hmac.Equal(a, b) }

// B64 encodes bytes as unpadded base64url.
func B64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// UnB64 decodes unpadded base64url.
func UnB64(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

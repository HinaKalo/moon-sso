package crypto

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

// ErrHasherBusy is returned when the hashing queue is saturated. Callers
// should answer 503 with Retry-After instead of queueing indefinitely.
var ErrHasherBusy = errors.New("password hasher busy")

// PasswordParams are argon2id cost parameters.
type PasswordParams struct {
	MemoryKiB   uint32
	Time        uint32
	Parallelism uint8
}

// Hasher hashes passwords with argon2id while bounding concurrency so that a
// login flood cannot exhaust memory or starve the rest of the server.
type Hasher struct {
	params PasswordParams
	sem    chan struct{}
	wait   time.Duration
	dummy  string
}

func NewHasher(p PasswordParams, concurrency int, wait time.Duration) *Hasher {
	h := &Hasher{params: p, sem: make(chan struct{}, concurrency), wait: wait}
	h.dummy = h.encode(RandomBytes(16), h.derive([]byte("dummy-password"), RandomBytes(16), p))
	return h
}

func (h *Hasher) acquire(ctx context.Context) error {
	t := time.NewTimer(h.wait)
	defer t.Stop()
	select {
	case h.sem <- struct{}{}:
		return nil
	case <-t.C:
		return ErrHasherBusy
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (h *Hasher) release() { <-h.sem }

func (h *Hasher) derive(pw, salt []byte, p PasswordParams) []byte {
	return argon2.IDKey(pw, salt, p.Time, p.MemoryKiB, p.Parallelism, 32)
}

func (h *Hasher) encode(salt, key []byte) string {
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version,
		h.params.MemoryKiB, h.params.Time, h.params.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key))
}

// Hash returns a PHC-formatted argon2id hash.
func (h *Hasher) Hash(ctx context.Context, password string) (string, error) {
	if err := h.acquire(ctx); err != nil {
		return "", err
	}
	defer h.release()
	salt := RandomBytes(16)
	return h.encode(salt, h.derive([]byte(password), salt, h.params)), nil
}

type parsedHash struct {
	params PasswordParams
	salt   []byte
	key    []byte
}

func parsePHC(encoded string) (*parsedHash, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return nil, errors.New("unsupported hash format")
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return nil, errors.New("unsupported argon2 version")
	}
	var p PasswordParams
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.MemoryKiB, &p.Time, &p.Parallelism); err != nil {
		return nil, errors.New("bad argon2 parameters")
	}
	if p.MemoryKiB > 256*1024 || p.Time > 16 || p.Parallelism == 0 {
		return nil, errors.New("argon2 parameters out of range")
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, err
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, err
	}
	return &parsedHash{params: p, salt: salt, key: key}, nil
}

// Verify checks password against encoded. needsRehash reports that the stored
// hash uses outdated parameters. An empty encoded value runs a dummy
// verification so that unknown usernames take the same time as known ones.
func (h *Hasher) Verify(ctx context.Context, password, encoded string) (ok, needsRehash bool, err error) {
	if encoded == "" {
		encoded = h.dummy
		defer func() { ok, needsRehash = false, false }()
	}
	ph, err := parsePHC(encoded)
	if err != nil {
		return false, false, err
	}
	if err := h.acquire(ctx); err != nil {
		return false, false, err
	}
	defer h.release()
	got := argon2.IDKey([]byte(password), ph.salt, ph.params.Time, ph.params.MemoryKiB, ph.params.Parallelism, uint32(len(ph.key)))
	ok = subtle.ConstantTimeCompare(got, ph.key) == 1
	needsRehash = ok && ph.params != h.params
	return ok, needsRehash, nil
}

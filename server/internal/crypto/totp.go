package crypto

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const totpPeriod = 30

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret returns a random 160-bit secret encoded in base32.
func NewTOTPSecret() string { return b32.EncodeToString(RandomBytes(20)) }

// TOTPURI builds the otpauth:// URI understood by authenticator apps.
func TOTPURI(issuer, account, secret string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{"secret": {secret}, "issuer": {issuer}, "algorithm": {"SHA1"}, "digits": {"6"}, "period": {"30"}}
	return "otpauth://totp/" + label + "?" + q.Encode()
}

func hotp(key []byte, counter uint64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	code := (binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff) % 1_000_000
	return fmt.Sprintf("%06d", code)
}

// TOTPCode returns the code for time t (used by tests and enrollment checks).
func TOTPCode(secret string, t time.Time) (string, error) {
	key, err := b32.DecodeString(strings.ToUpper(secret))
	if err != nil {
		return "", err
	}
	return hotp(key, uint64(t.Unix()/totpPeriod)), nil
}

// VerifyTOTP checks code within ±1 step and rejects steps at or before
// lastStep (replay protection). It returns the matched step on success.
func VerifyTOTP(secret, code string, now time.Time, lastStep int64) (int64, bool) {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != 6 {
		return 0, false
	}
	key, err := b32.DecodeString(strings.ToUpper(secret))
	if err != nil {
		return 0, false
	}
	cur := now.Unix() / totpPeriod
	for _, d := range []int64{0, -1, 1} {
		step := cur + d
		if step <= lastStep {
			continue
		}
		if hmac.Equal([]byte(hotp(key, uint64(step))), []byte(code)) {
			return step, true
		}
	}
	return 0, false
}

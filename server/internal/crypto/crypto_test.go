package crypto

import (
	"context"
	"encoding/base32"
	"testing"
	"time"
)

// RFC 6238 Appendix B (SHA-1, 8 digits); we compare the last 6 digits.
func TestTOTPRFC6238(t *testing.T) {
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	cases := map[int64]string{59: "287082", 1111111109: "081804", 1234567890: "005924", 2000000000: "279037"}
	for ts, want := range cases {
		got, err := TOTPCode(secret, time.Unix(ts, 0))
		if err != nil || got != want {
			t.Fatalf("t=%d got %s want %s (%v)", ts, got, want, err)
		}
	}
}

func TestTOTPWindowAndReplay(t *testing.T) {
	s := NewTOTPSecret()
	now := time.Unix(1_800_000_000, 0)
	code, _ := TOTPCode(s, now)
	step, ok := VerifyTOTP(s, code, now, 0)
	if !ok {
		t.Fatal("current code rejected")
	}
	if _, ok := VerifyTOTP(s, code, now, step); ok {
		t.Fatal("replayed code accepted")
	}
	old, _ := TOTPCode(s, now.Add(-90*time.Second))
	if _, ok := VerifyTOTP(s, old, now, 0); ok {
		t.Fatal("code three steps old accepted")
	}
}

func TestPasswordHashVerifyAndRehash(t *testing.T) {
	ctx := context.Background()
	h := NewHasher(PasswordParams{MemoryKiB: 1024, Time: 1, Parallelism: 1}, 2, time.Second)
	enc, err := h.Hash(ctx, "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if ok, rehash, _ := h.Verify(ctx, "correct horse", enc); !ok || rehash {
		t.Fatalf("verify ok=%v rehash=%v", ok, rehash)
	}
	if ok, _, _ := h.Verify(ctx, "wrong", enc); ok {
		t.Fatal("wrong password accepted")
	}
	if ok, _, _ := h.Verify(ctx, "anything", ""); ok {
		t.Fatal("dummy verification must fail")
	}
	stronger := NewHasher(PasswordParams{MemoryKiB: 2048, Time: 1, Parallelism: 1}, 2, time.Second)
	if ok, rehash, _ := stronger.Verify(ctx, "correct horse", enc); !ok || !rehash {
		t.Fatal("outdated parameters should request a rehash")
	}
}

func TestHasherBoundsConcurrency(t *testing.T) {
	h := NewHasher(PasswordParams{MemoryKiB: 1024, Time: 1, Parallelism: 1}, 1, 10*time.Millisecond)
	h.sem <- struct{}{} // occupy the only slot
	if _, err := h.Hash(context.Background(), "x"); err != ErrHasherBusy {
		t.Fatalf("expected ErrHasherBusy, got %v", err)
	}
	<-h.sem
}

func TestSealerRoundTripAndAAD(t *testing.T) {
	k, err := ParseKeyring(GenerateMasterKey())
	if err != nil {
		t.Fatal(err)
	}
	s := k.Sealer(PurposeAtRest)
	ct := s.Seal([]byte("secret"), []byte("aad-1"))
	if pt, err := s.Open(ct, []byte("aad-1")); err != nil || string(pt) != "secret" {
		t.Fatalf("open: %v", err)
	}
	if _, err := s.Open(ct, []byte("aad-2")); err == nil {
		t.Fatal("wrong AAD accepted")
	}
	if _, err := k.Sealer(PurposeCookieAEAD).Open(ct, []byte("aad-1")); err == nil {
		t.Fatal("key separation between purposes broken")
	}
	other, _ := ParseKeyring(GenerateMasterKey())
	if _, err := other.Sealer(PurposeAtRest).Open(ct, []byte("aad-1")); err == nil {
		t.Fatal("foreign master key accepted")
	}
}

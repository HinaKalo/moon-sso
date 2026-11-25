package feed

import (
	"encoding/base64"
	"strings"
	"testing"
)

// Standard Webhooks reference vector (also in docs/sdk-spec.md §5.2).
func TestSignStandardWebhooksVector(t *testing.T) {
	secret := "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"
	key, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(secret, "whsec_"))
	if err != nil {
		t.Fatal(err)
	}
	got := Sign(key, "msg_p5jXN8AQM9LWM0D4loKWxJek", 1614265330, []byte(`{"test": 2432232314}`))
	want := "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE="
	if got != want {
		t.Fatalf("got %s want %s", got, want)
	}
}

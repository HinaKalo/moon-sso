package desktop

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	moonsso "sso.moonl.cloud/sdk/go"
)

func TestSecureFileStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	store, err := newPlatformStore("moon-sso-test-" + filepath.Base(dir))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	defer store.Clear(ctx)
	if st, err := store.Load(ctx); err != nil || st != nil {
		t.Fatalf("empty store: %v %v", st, err)
	}
	key, _ := moonsso.NewDPoPKey()
	k, _ := moonsso.MarshalDPoPKey(key)
	want := &moonsso.Stored{Token: moonsso.Token{AccessToken: "at", RefreshToken: "rt-secret", ExpiresAt: time.Now().Add(time.Hour)}, DPoPKey: k}
	if err := store.Save(ctx, want); err != nil {
		t.Fatal(err)
	}
	got, err := store.Load(ctx)
	if err != nil || got == nil || got.Token.RefreshToken != "rt-secret" || got.DPoPKey != k {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	if err := store.Clear(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestFileLockIsExclusive(t *testing.T) {
	l := NewFileLock(filepath.Join(t.TempDir(), "x.lock"))
	ctx := context.Background()
	var mu sync.Mutex
	inside := 0
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Separate lock objects behave like separate processes.
			lk := NewFileLock(l.(*fileLock).path)
			unlock, err := lk.Lock(ctx)
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			inside++
			if inside != 1 {
				t.Error("two holders at once")
			}
			mu.Unlock()
			time.Sleep(20 * time.Millisecond)
			mu.Lock()
			inside--
			mu.Unlock()
			unlock()
		}()
	}
	wg.Wait()
}

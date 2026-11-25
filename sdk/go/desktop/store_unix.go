//go:build !windows

package desktop

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/zalando/go-keyring"

	moonsso "sso.moonl.cloud/sdk/go"
)

// keyringStore keeps the session in the macOS Keychain or the Linux Secret
// Service. The DPoP key and refresh token never touch the filesystem.
type keyringStore struct{ service string }

const keyringUser = "session"

func (k *keyringStore) Load(context.Context) (*moonsso.Stored, error) {
	v, err := keyring.Get(k.service, keyringUser)
	if errors.Is(err, keyring.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var st moonsso.Stored
	if json.Unmarshal([]byte(v), &st) != nil {
		return nil, nil
	}
	return &st, nil
}

func (k *keyringStore) Save(_ context.Context, st *moonsso.Stored) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return keyring.Set(k.service, keyringUser, string(b))
}

func (k *keyringStore) Clear(context.Context) error {
	err := keyring.Delete(k.service, keyringUser)
	if errors.Is(err, keyring.ErrNotFound) {
		return nil
	}
	return err
}

func newPlatformStore(app string) (moonsso.Store, error) {
	ks := &keyringStore{service: "moon-sso:" + app}
	// Probe the keyring; headless Linux often has no Secret Service.
	if err := keyring.Set(ks.service, "probe", "1"); err == nil {
		_ = keyring.Delete(ks.service, "probe")
		return ks, nil
	}
	log.Printf("moon-sso: no OS keyring available; storing the session in a 0600 file under %s", appDir(app))
	return &fileStore{path: filepath.Join(appDir(app), "moon-sso.json")}, nil
}

func replaceFile(from, to string) error { return os.Rename(from, to) }

type fileLock struct{ path string }

// NewFileLock returns a cross-process Locker backed by flock(2).
func NewFileLock(path string) moonsso.Locker { return &fileLock{path: path} }

func (l *fileLock) Lock(ctx context.Context) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(l.path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	for {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}

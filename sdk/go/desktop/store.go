package desktop

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	moonsso "sso.moonl.cloud/sdk/go"
)

// appDir returns the per-user application data directory.
func appDir(app string) string {
	base, err := os.UserConfigDir()
	if err != nil {
		base = os.TempDir()
	}
	return filepath.Join(base, app)
}

// sealer encrypts session blobs with an OS facility.
type sealer interface {
	seal([]byte) ([]byte, error)
	open([]byte) ([]byte, error)
}

// fileStore writes the (sealed) session to a file atomically.
type fileStore struct {
	mu   sync.Mutex
	path string
	s    sealer // nil: plain 0600 file (last-resort fallback)
}

func (f *fileStore) Load(context.Context) (*moonsso.Stored, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, err := os.ReadFile(f.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if f.s != nil {
		if b, err = f.s.open(b); err != nil {
			return nil, fmt.Errorf("desktop: cannot decrypt session: %w", err)
		}
	}
	var st moonsso.Stored
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, nil // corrupt: treat as signed out
	}
	return &st, nil
}

func (f *fileStore) Save(_ context.Context, st *moonsso.Stored) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	if f.s != nil {
		if b, err = f.s.seal(b); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Dir(f.path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(f.path), ".moon-sso-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	tmp.Close()
	if runtime.GOOS != "windows" {
		_ = os.Chmod(tmp.Name(), 0o600)
	}
	return replaceFile(tmp.Name(), f.path)
}

func (f *fileStore) Clear(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	err := os.Remove(f.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// NewSecureStore returns the best secure store for this OS:
// Windows: DPAPI-encrypted file under %AppData%; macOS: Keychain;
// Linux: Secret Service (libsecret), falling back to a 0600 file.
func NewSecureStore(app string) (moonsso.Store, error) {
	return newPlatformStore(app)
}

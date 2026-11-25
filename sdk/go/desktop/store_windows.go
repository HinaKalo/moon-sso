//go:build windows

package desktop

import (
	"context"
	"os"
	"path/filepath"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	moonsso "sso.moonl.cloud/sdk/go"
)

type dpapi struct{ entropy []byte }

func blob(b []byte) *windows.DataBlob {
	if len(b) == 0 {
		return &windows.DataBlob{}
	}
	return &windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
}

func (d dpapi) seal(pt []byte) ([]byte, error) {
	var out windows.DataBlob
	if err := windows.CryptProtectData(blob(pt), nil, blob(d.entropy), 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...), nil
}

func (d dpapi) open(ct []byte) ([]byte, error) {
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(blob(ct), nil, blob(d.entropy), 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...), nil
}

func newPlatformStore(app string) (moonsso.Store, error) {
	return &fileStore{path: filepath.Join(appDir(app), "moon-sso.dat"), s: dpapi{entropy: []byte("moon-sso:" + app)}}, nil
}

func replaceFile(from, to string) error {
	return windows.Rename(from, to)
}

// fileLock uses LockFileEx on a lock file shared by all app instances.
type fileLock struct{ path string }

// NewFileLock returns a cross-process Locker backed by a lock file.
func NewFileLock(path string) moonsso.Locker { return &fileLock{path: path} }

func (l *fileLock) Lock(ctx context.Context) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(l.path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	h := windows.Handle(f.Fd())
	ol := new(windows.Overlapped)
	for {
		err = windows.LockFileEx(h, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, ol)
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
		_ = windows.UnlockFileEx(h, 0, 1, 0, ol)
		f.Close()
	}, nil
}

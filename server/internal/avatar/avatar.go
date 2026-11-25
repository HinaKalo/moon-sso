// Package avatar validates uploaded images and stores normalized,
// content-addressed JPEG renditions (512px and 128px squares).
package avatar

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"image"
	"image/color"
	"image/jpeg"
	"io"
	"os"
	"path/filepath"

	_ "image/gif"
	_ "image/png"

	"golang.org/x/image/draw"
	_ "golang.org/x/image/webp"
)

const (
	MaxBytes     = 5 << 20
	MaxDimension = 6000
	MaxPixels    = 30_000_000
	SizeLarge    = 512
	SizeSmall    = 128
	jpegQuality  = 88
)

var (
	ErrTooLarge    = errors.New("图片不能超过 5 MB")
	ErrUnsupported = errors.New("不支持的图片格式，请上传 PNG、JPEG、GIF 或 WebP")
	ErrDimensions  = errors.New("图片尺寸过大或过小")
)

type Store struct{ Dir string }

// Save decodes r, crops it to a centered square, writes both renditions
// and returns the key ("<hash>.jpg") stored on the user.
func (s *Store) Save(r io.Reader) (string, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxBytes+1))
	if err != nil {
		return "", err
	}
	if len(data) > MaxBytes {
		return "", ErrTooLarge
	}
	cfg, _, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return "", ErrUnsupported
	}
	if cfg.Width < 16 || cfg.Height < 16 || cfg.Width > MaxDimension || cfg.Height > MaxDimension || cfg.Width*cfg.Height > MaxPixels {
		return "", ErrDimensions
	}
	src, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return "", ErrUnsupported
	}
	b := src.Bounds()
	side := min(b.Dx(), b.Dy())
	crop := image.Rect(b.Min.X+(b.Dx()-side)/2, b.Min.Y+(b.Dy()-side)/2, 0, 0)
	crop.Max = crop.Min.Add(image.Pt(side, side))

	large, err := render(src, crop, min(SizeLarge, side))
	if err != nil {
		return "", err
	}
	small, err := render(src, crop, min(SizeSmall, side))
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(large)
	key := hex.EncodeToString(sum[:16])
	if err := os.MkdirAll(s.Dir, 0o755); err != nil {
		return "", err
	}
	if err := writeAtomic(filepath.Join(s.Dir, key+"_128.jpg"), small); err != nil {
		return "", err
	}
	if err := writeAtomic(filepath.Join(s.Dir, key+".jpg"), large); err != nil {
		return "", err
	}
	return key + ".jpg", nil
}

// render scales the crop to size×size over a white background (JPEG has no
// alpha) and re-encodes it, which also strips EXIF and other metadata.
func render(src image.Image, crop image.Rectangle, size int) ([]byte, error) {
	dst := image.NewRGBA(image.Rect(0, 0, size, size))
	draw.Draw(dst, dst.Bounds(), &image.Uniform{C: color.White}, image.Point{}, draw.Src)
	draw.CatmullRom.Scale(dst, dst.Bounds(), src, crop, draw.Over, nil)
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, dst, &jpeg.Options{Quality: jpegQuality}); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeAtomic(path string, data []byte) error {
	if _, err := os.Stat(path); err == nil {
		return nil // content-addressed: identical file already present
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".avatar-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Open serves an avatar file (used when no reverse proxy serves the directory).
func (s *Store) Open(key string) (*os.File, error) {
	if len(key) < 36 || len(key) > 44 || filepath.Base(key) != key {
		return nil, os.ErrNotExist
	}
	for _, r := range key {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r == '.' || r == '_' || r == 'j' || r == 'p' || r == 'g' || r == '1' || r == '2' || r == '8') {
			return nil, os.ErrNotExist
		}
	}
	return os.Open(filepath.Join(s.Dir, key))
}

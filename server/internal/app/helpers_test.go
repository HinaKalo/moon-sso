package app_test

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"io"
	"net/http"
	"strings"

	"moon-sso/server/internal/feed"
)

func feedSign(key []byte, id string, ts int64, body []byte) string {
	return feed.Sign(key, id, ts, body)
}

// testPNG returns a small valid PNG.
func testPNG() []byte {
	img := image.NewRGBA(image.Rect(0, 0, 64, 48))
	for x := 0; x < 64; x++ {
		for y := 0; y < 48; y++ {
			img.Set(x, y, color.RGBA{uint8(x * 4), uint8(y * 5), 120, 255})
		}
	}
	var b bytes.Buffer
	_ = png.Encode(&b, img)
	return b.Bytes()
}

func bufCopy(w *strings.Builder, resp *http.Response) (int64, error) {
	defer resp.Body.Close()
	return io.Copy(w, resp.Body)
}

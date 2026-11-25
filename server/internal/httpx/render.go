package httpx

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/labstack/echo/v5"
)

// Renderer renders page templates. A page "x" is pages/x.html parsed together
// with the layouts and partials; "x#block" renders a single block (HTMX swaps).
type Renderer struct {
	pages map[string]*template.Template
	pool  sync.Pool
}

type Assets struct {
	files map[string][]byte
	hash  map[string]string
}

// LoadAssets reads static files and computes short content hashes for cache busting.
func LoadAssets(static fs.FS) (*Assets, error) {
	a := &Assets{files: map[string][]byte{}, hash: map[string]string{}}
	err := fs.WalkDir(static, "static", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := fs.ReadFile(static, p)
		if err != nil {
			return err
		}
		name := strings.TrimPrefix(p, "static/")
		sum := sha256.Sum256(b)
		a.files[name] = b
		a.hash[name] = hex.EncodeToString(sum[:5])
		return nil
	})
	return a, err
}

// URL returns the cache-busted path for a static file.
func (a *Assets) URL(name string) string {
	h, ok := a.hash[name]
	if !ok {
		panic("unknown asset " + name)
	}
	return "/static/" + h + "/" + name
}

// Handler serves /static/:hash/*. Any hash serves the current file so pages
// rendered by a previous release keep working during a deploy; only a
// matching hash is cached as immutable.
func (a *Assets) Handler() echo.HandlerFunc {
	return func(c *echo.Context) error {
		name := c.Param("*")
		b, ok := a.files[name]
		if !ok {
			return echo.ErrNotFound
		}
		ct := mime.TypeByExtension(path.Ext(name))
		if ct == "" {
			ct = "application/octet-stream"
		}
		h := c.Response().Header()
		if c.Param("hash") == a.hash[name] {
			h.Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			h.Set("Cache-Control", "public, max-age=300")
		}
		h.Set("X-Content-Type-Options", "nosniff")
		return c.Blob(http.StatusOK, ct, b)
	}
}

func NewRenderer(tfs fs.FS, funcs template.FuncMap) (*Renderer, error) {
	base := template.New("").Funcs(funcs)
	for _, pattern := range []string{"templates/layouts/*.html", "templates/partials/*.html"} {
		matches, err := fs.Glob(tfs, pattern)
		if err != nil {
			return nil, err
		}
		if len(matches) == 0 {
			continue
		}
		if base, err = base.ParseFS(tfs, pattern); err != nil {
			return nil, err
		}
	}
	r := &Renderer{pages: map[string]*template.Template{}}
	r.pool.New = func() any { return new(bytes.Buffer) }
	err := fs.WalkDir(tfs, "templates/pages", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".html") {
			return err
		}
		t, err := base.Clone()
		if err != nil {
			return err
		}
		if t, err = t.ParseFS(tfs, p); err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		name := strings.TrimSuffix(strings.TrimPrefix(p, "templates/pages/"), ".html")
		r.pages[name] = t
		return nil
	})
	return r, err
}

// Render implements echo.Renderer. Output is buffered so a template error
// produces a clean 500 instead of a half-written page.
func (r *Renderer) Render(c *echo.Context, w io.Writer, name string, data any) error {
	page, block, _ := strings.Cut(name, "#")
	t, ok := r.pages[page]
	if !ok {
		return fmt.Errorf("template %q not found", page)
	}
	if block == "" {
		block = "layout"
		if strings.HasPrefix(page, "admin/") {
			block = "admin_layout"
		}
	}
	buf := r.pool.Get().(*bytes.Buffer)
	buf.Reset()
	defer r.pool.Put(buf)
	if err := t.ExecuteTemplate(buf, block, data); err != nil {
		return err
	}
	_, err := w.Write(buf.Bytes())
	return err
}

// Funcs returns the template helpers shared by public and admin pages.
func Funcs(assets *Assets, publicURL string) template.FuncMap {
	cst := time.FixedZone("CST", 8*3600)
	return template.FuncMap{
		"asset": assets.URL,
		"avatar": func(key string) string {
			if key == "" {
				return ""
			}
			return publicURL + "/avatars/" + key
		},
		"fmtTime": func(t any) string {
			switch v := t.(type) {
			case time.Time:
				if v.IsZero() {
					return "—"
				}
				return v.In(cst).Format("2006-01-02 15:04")
			case *time.Time:
				if v == nil {
					return "—"
				}
				return v.In(cst).Format("2006-01-02 15:04")
			}
			return ""
		},
		"ago": func(t time.Time) string { return humanAgo(time.Since(t)) },
		"initial": func(s string) string {
			for _, r := range s {
				return strings.ToUpper(string(r))
			}
			return "?"
		},
		"join":     strings.Join,
		"contains": strings.Contains,
		"split":    strings.Fields,
		"dict": func(kv ...any) map[string]any {
			m := map[string]any{}
			for i := 0; i+1 < len(kv); i += 2 {
				m[fmt.Sprint(kv[i])] = kv[i+1]
			}
			return m
		},
		"add": func(a, b int) int { return a + b },
		"has": func(list []string, s string) bool {
			for _, v := range list {
				if v == s {
					return true
				}
			}
			return false
		},
	}
}

func humanAgo(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "刚刚"
	case d < time.Hour:
		return fmt.Sprintf("%d 分钟前", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%d 小时前", int(d.Hours()))
	case d < 30*24*time.Hour:
		return fmt.Sprintf("%d 天前", int(d.Hours()/24))
	default:
		return fmt.Sprintf("%d 个月前", int(d.Hours()/24/30))
	}
}

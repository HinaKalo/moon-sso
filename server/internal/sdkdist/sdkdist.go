// Package sdkdist serves SDK artifacts from the data directory:
//
//	/sdk/go…?go-get=1        go-import meta (module served by the proxy below)
//	/goproxy/…               Go module proxy protocol (static files)
//	/sdk/maven/…             Maven repository (Kotlin, Android, Spring)
//	/sdk/npm/…               npm tarballs
//	/sdk/pypi/…              wheels and sdists
//	/sdk/nuget/…             nupkg files
//
// Artifacts are produced by cmd/sdkpack and uploaded by deploy.ps1 -WithSDK.
package sdkdist

import (
	"io/fs"
	"mime"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/labstack/echo/v5"
)

const GoModule = "sso.moonl.cloud/sdk/go"

type Handler struct {
	Dir       string // e.g. /var/lib/moon-sso/sdk
	PublicURL string
}

var contentTypes = map[string]string{
	".tgz": "application/gzip", ".gz": "application/gzip", ".whl": "application/zip", ".zip": "application/zip",
	".nupkg": "application/zip", ".jar": "application/java-archive", ".aar": "application/zip", ".pom": "application/xml",
	".xml": "application/xml", ".module": "application/json", ".info": "application/json", ".mod": "text/plain; charset=utf-8",
	".sha1": "text/plain", ".sha256": "text/plain", ".sha512": "text/plain", ".md5": "text/plain", ".asc": "text/plain",
}

// GoImport answers ?go-get=1 discovery for the module and its packages.
func (h *Handler) GoImport(c *echo.Context) error {
	if c.QueryParam("go-get") != "1" {
		return c.Redirect(http.StatusFound, "/sdk")
	}
	body := `<!doctype html><html><head><meta name="go-import" content="` + GoModule + ` mod ` + h.PublicURL + `/goproxy"></head><body>go get ` + GoModule + `</body></html>`
	return c.HTML(http.StatusOK, body)
}

// File serves one artifact below prefix (a directory under Dir).
func (h *Handler) File(prefix string) echo.HandlerFunc {
	return func(c *echo.Context) error {
		rel := path.Clean("/" + c.Param("*"))
		if strings.Contains(rel, "..") {
			return echo.ErrNotFound
		}
		full := filepath.Join(h.Dir, prefix, filepath.FromSlash(rel))
		st, err := os.Stat(full)
		if err != nil || st.IsDir() {
			return echo.ErrNotFound
		}
		ct := contentTypes[strings.ToLower(filepath.Ext(full))]
		if ct == "" {
			if ct = mime.TypeByExtension(filepath.Ext(full)); ct == "" {
				ct = "application/octet-stream"
			}
		}
		if strings.HasSuffix(full, "list") && prefix == "goproxy" {
			ct = "text/plain; charset=utf-8"
		}
		f, err := os.Open(full)
		if err != nil {
			return echo.ErrNotFound
		}
		defer f.Close()
		hdr := c.Response().Header()
		hdr.Set("Content-Type", ct)
		hdr.Set("X-Content-Type-Options", "nosniff")
		// Versioned artifacts never change; listings and metadata may.
		if strings.HasSuffix(full, "list") || strings.HasSuffix(full, "maven-metadata.xml") || strings.Contains(full, "@latest") {
			hdr.Set("Cache-Control", "public, max-age=300")
		} else {
			hdr.Set("Cache-Control", "public, max-age=86400")
		}
		http.ServeContent(c.Response(), c.Request(), st.Name(), st.ModTime(), f)
		return nil
	}
}

// Artifact is one downloadable file shown on the index page.
type Artifact struct {
	Kind     string
	Name     string
	URL      string
	Size     int64
	Modified time.Time
}

// List enumerates published artifacts for the /sdk page.
func (h *Handler) List() []Artifact {
	var out []Artifact
	add := func(kind, dir string, keep func(string) bool) {
		root := filepath.Join(h.Dir, dir)
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !keep(d.Name()) {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return nil
			}
			rel, _ := filepath.Rel(root, p)
			out = append(out, Artifact{Kind: kind, Name: d.Name(), URL: "/sdk/" + dir + "/" + filepath.ToSlash(rel), Size: info.Size(), Modified: info.ModTime()})
			return nil
		})
	}
	add("npm", "npm", func(n string) bool { return strings.HasSuffix(n, ".tgz") })
	add("pypi", "pypi", func(n string) bool { return strings.HasSuffix(n, ".whl") || strings.HasSuffix(n, ".tar.gz") })
	add("nuget", "nuget", func(n string) bool { return strings.HasSuffix(n, ".nupkg") })
	add("maven", "maven", func(n string) bool {
		return (strings.HasSuffix(n, ".jar") || strings.HasSuffix(n, ".aar")) && !strings.HasSuffix(n, "-sources.jar") && !strings.HasSuffix(n, "-javadoc.jar")
	})
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// CLIFile is one prebuilt moonsso binary.
type CLIFile struct {
	Name, URL, OS, Arch string
	Size                int64
}

// CLI lists the prebuilt moonsso binaries (newest version first by name).
func (h *Handler) CLI() []CLIFile {
	entries, err := os.ReadDir(filepath.Join(h.Dir, "cli"))
	if err != nil {
		return nil
	}
	var out []CLIFile
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, "moonsso-") {
			continue
		}
		parts := strings.Split(strings.TrimSuffix(name, ".exe"), "-")
		if len(parts) < 4 {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, CLIFile{Name: name, URL: "/sdk/cli/" + name, OS: parts[len(parts)-2], Arch: parts[len(parts)-1], Size: info.Size()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name > out[j].Name })
	return out
}

// GoVersions lists published Go SDK versions.
func (h *Handler) GoVersions() []string {
	b, err := os.ReadFile(filepath.Join(h.Dir, "goproxy", GoModule, "@v", "list"))
	if err != nil {
		return nil
	}
	return strings.Fields(string(b))
}

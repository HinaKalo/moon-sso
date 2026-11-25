// Command sdkpack assembles every SDK artifact into one directory tree that
// the server publishes under /sdk and /goproxy:
//
//	go run ./cmd/sdkpack -repo .. -out ../dist/sdk -go-version v1.1.1
//
// Go module versions already published in -out are kept: a published version
// is immutable (proxy.golang.org and sum.golang.org remember its hash), so a
// changed module must get a new version. The moonsso CLI is cross-compiled
// into cli/ with a SHA256SUMS file.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"golang.org/x/mod/module"
	modzip "golang.org/x/mod/zip"
)

const goModule = "sso.moonl.cloud/sdk/go"

func main() {
	repo := flag.String("repo", "..", "repository root")
	out := flag.String("out", "../dist/sdk", "output directory")
	goVersion := flag.String("go-version", "v1.1.1", "Go SDK version tag")
	flag.Parse()
	proxy := filepath.Join(*out, "goproxy")
	kept, err := keepGoVersions(proxy, *goVersion)
	if err != nil {
		fail(err)
	}
	defer os.RemoveAll(kept)
	if err := os.RemoveAll(*out); err != nil {
		fail(err)
	}
	if err := packGo(filepath.Join(*repo, "sdk", "go"), proxy, *goVersion, kept); err != nil {
		fail(fmt.Errorf("go: %w", err))
	}
	if err := buildCLI(filepath.Join(*repo, "sdk", "go"), filepath.Join(*out, "cli"), *goVersion); err != nil {
		fail(fmt.Errorf("cli: %w", err))
	}
	copies := []struct{ from, to, glob string }{
		{"sdk/typescript/dist-pkg", "npm", "*.tgz"},
		{"sdk/python/dist", "pypi", "*"},
		{"sdk/dotnet/artifacts", "nuget", "*.nupkg"},
	}
	for _, c := range copies {
		n, err := copyGlob(filepath.Join(*repo, c.from), filepath.Join(*out, c.to), c.glob)
		if err != nil {
			fail(err)
		}
		fmt.Printf("%-6s %d files\n", c.to, n)
	}
	for _, repoDir := range []string{"sdk/kotlin/build/repo", "sdk/java-spring/build/repo"} {
		n, err := copyTree(filepath.Join(*repo, repoDir), filepath.Join(*out, "maven"))
		if err != nil {
			fail(err)
		}
		fmt.Printf("maven  %d files from %s\n", n, repoDir)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "sdkpack:", err)
	os.Exit(1)
}

// keepGoVersions copies previously published versions (other than version)
// to a temporary directory so they survive the rebuild of -out.
func keepGoVersions(proxy, version string) (string, error) {
	tmp, err := os.MkdirTemp("", "sdkpack-go")
	if err != nil {
		return "", err
	}
	src := filepath.Join(proxy, filepath.FromSlash(goModule), "@v")
	entries, err := os.ReadDir(src)
	if os.IsNotExist(err) {
		return tmp, nil
	}
	if err != nil {
		return "", err
	}
	for _, e := range entries {
		name := e.Name()
		ext := filepath.Ext(name)
		if e.IsDir() || (ext != ".zip" && ext != ".mod" && ext != ".info") || strings.TrimSuffix(name, ext) == version {
			continue
		}
		if err := copyFile(filepath.Join(src, name), filepath.Join(tmp, name)); err != nil {
			return "", err
		}
	}
	return tmp, nil
}

func packGo(src, proxy, version, kept string) error {
	dir := filepath.Join(proxy, filepath.FromSlash(goModule), "@v")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	versions := []string{version}
	keptFiles, _ := os.ReadDir(kept)
	for _, e := range keptFiles {
		if err := copyFile(filepath.Join(kept, e.Name()), filepath.Join(dir, e.Name())); err != nil {
			return err
		}
		if v, ok := strings.CutSuffix(e.Name(), ".zip"); ok {
			versions = append(versions, v)
			fmt.Printf("go     %s %s (kept)\n", goModule, v)
		}
	}
	slices.SortFunc(versions, semverCompare)
	mv := module.Version{Path: goModule, Version: version}
	zf, err := os.Create(filepath.Join(dir, version+".zip"))
	if err != nil {
		return err
	}
	if err := modzip.CreateFromDir(zf, mv, src); err != nil {
		zf.Close()
		return err
	}
	if err := zf.Close(); err != nil {
		return err
	}
	mod, err := os.ReadFile(filepath.Join(src, "go.mod"))
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, version+".mod"), mod, 0o644); err != nil {
		return err
	}
	info, _ := json.Marshal(map[string]any{"Version": version, "Time": time.Now().UTC().Format(time.RFC3339)})
	if err := os.WriteFile(filepath.Join(dir, version+".info"), info, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "list"), []byte(strings.Join(versions, "\n")+"\n"), 0o644); err != nil {
		return err
	}
	latest := filepath.Join(proxy, filepath.FromSlash(goModule), "@latest")
	if err := os.WriteFile(latest, info, 0o644); err != nil {
		return err
	}
	fmt.Printf("go     %s %s\n", goModule, version)
	return nil
}

// semverCompare orders vMAJOR.MINOR.PATCH tags numerically.
func semverCompare(a, b string) int {
	pa, pb := strings.Split(strings.TrimPrefix(a, "v"), "."), strings.Split(strings.TrimPrefix(b, "v"), ".")
	for i := 0; i < 3; i++ {
		var x, y int
		if i < len(pa) {
			fmt.Sscan(pa[i], &x)
		}
		if i < len(pb) {
			fmt.Sscan(pb[i], &y)
		}
		if x != y {
			return x - y
		}
	}
	return 0
}

// buildCLI cross-compiles cmd/moonsso for the supported platforms.
func buildCLI(module, out, version string) error {
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	targets := [][2]string{{"linux", "amd64"}, {"linux", "arm64"}, {"darwin", "amd64"}, {"darwin", "arm64"}, {"windows", "amd64"}, {"windows", "arm64"}}
	var sums []string
	for _, t := range targets {
		name := "moonsso-" + strings.TrimPrefix(version, "v") + "-" + t[0] + "-" + t[1]
		if t[0] == "windows" {
			name += ".exe"
		}
		dst, err := filepath.Abs(filepath.Join(out, name))
		if err != nil {
			return err
		}
		cmd := exec.Command("go", "build", "-trimpath", "-ldflags", "-s -w -X main.version="+version, "-o", dst, "./cmd/moonsso")
		cmd.Dir = module
		cmd.Env = append(os.Environ(), "GOOS="+t[0], "GOARCH="+t[1], "CGO_ENABLED=0")
		cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("%s/%s: %w", t[0], t[1], err)
		}
		b, err := os.ReadFile(dst)
		if err != nil {
			return err
		}
		h := sha256.Sum256(b)
		sums = append(sums, hex.EncodeToString(h[:])+"  "+name)
		fmt.Printf("cli    %s (%d KiB)\n", name, len(b)/1024)
	}
	return os.WriteFile(filepath.Join(out, "SHA256SUMS"), []byte(strings.Join(sums, "\n")+"\n"), 0o644)
}

func copyGlob(from, to, glob string) (int, error) {
	matches, _ := filepath.Glob(filepath.Join(from, glob))
	n := 0
	for _, m := range matches {
		st, err := os.Stat(m)
		if err != nil || st.IsDir() {
			continue
		}
		if err := copyFile(m, filepath.Join(to, filepath.Base(m))); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

func copyTree(from, to string) (int, error) {
	n := 0
	if _, err := os.Stat(from); err != nil {
		return 0, nil
	}
	err := filepath.WalkDir(from, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(from, p)
		if strings.HasPrefix(d.Name(), ".") {
			return nil
		}
		n++
		return copyFile(p, filepath.Join(to, rel))
	})
	return n, err
}

func copyFile(from, to string) error {
	if err := os.MkdirAll(filepath.Dir(to), 0o755); err != nil {
		return err
	}
	in, err := os.Open(from)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(to)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

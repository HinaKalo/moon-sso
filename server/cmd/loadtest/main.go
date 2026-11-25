// Command loadtest measures throughput and latency of the hot paths against a
// testbed instance (it uses the testbed fixtures: client test-native, user alice).
//
//	loadtest -base http://127.0.0.1:18601 -c 64 -d 20s -scenario all
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type result struct {
	name    string
	n, errs int64
	lat     []time.Duration
	elapsed time.Duration
}

func (r *result) print() {
	sort.Slice(r.lat, func(i, j int) bool { return r.lat[i] < r.lat[j] })
	pct := func(p float64) time.Duration {
		if len(r.lat) == 0 {
			return 0
		}
		return r.lat[min(len(r.lat)-1, int(float64(len(r.lat))*p))]
	}
	fmt.Printf("%-10s %8.0f req/s  n=%-7d err=%-5d p50=%-9s p95=%-9s p99=%-9s max=%s\n", r.name,
		float64(r.n)/r.elapsed.Seconds(), r.n, r.errs, pct(.50).Round(10*time.Microsecond), pct(.95).Round(10*time.Microsecond),
		pct(.99).Round(10*time.Microsecond), pct(1).Round(10*time.Microsecond))
}

var hc = &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{MaxIdleConns: 1024, MaxIdleConnsPerHost: 1024, IdleConnTimeout: time.Minute}}

func run(name string, conc int, dur time.Duration, setup func(worker int) any, op func(state any) (any, error)) *result {
	var n, errs atomic.Int64
	lats := make([][]time.Duration, conc)
	states := make([]any, conc)
	for i := range states {
		states[i] = setup(i)
	}
	deadline := time.Now().Add(dur)
	start := time.Now()
	var wg sync.WaitGroup
	for w := 0; w < conc; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			st := states[w]
			for time.Now().Before(deadline) {
				t0 := time.Now()
				next, err := op(st)
				lats[w] = append(lats[w], time.Since(t0))
				if err != nil {
					errs.Add(1)
					if errs.Load() < 4 {
						fmt.Fprintln(os.Stderr, name, "error:", err)
					}
					continue
				}
				if next != nil {
					st = next
				}
				n.Add(1)
			}
		}(w)
	}
	wg.Wait()
	r := &result{name: name, n: n.Load(), errs: errs.Load(), elapsed: time.Since(start)}
	for _, l := range lats {
		r.lat = append(r.lat, l...)
	}
	return r
}

func get(u, bearer string) error {
	req, _ := http.NewRequest(http.MethodGet, u, nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}

type tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	Code         string `json:"authorization_code"`
	Error        string `json:"error"`
}

func postForm(u string, form url.Values) (*tokens, error) {
	resp, err := hc.PostForm(u, form)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var t tokens
	if err := json.NewDecoder(resp.Body).Decode(&t); err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("status %d %s", resp.StatusCode, t.Error)
	}
	return &t, nil
}

func login(base string) (*tokens, error) {
	v := strings.Repeat("v", 20) + fmt.Sprint(time.Now().UnixNano())
	v = (v + strings.Repeat("x", 64))[:64]
	sum := sha256.Sum256([]byte(v))
	ch := base64.RawURLEncoding.EncodeToString(sum[:])
	c, err := postForm(base+"/oauth/authorize-challenge", url.Values{"client_id": {"test-native"}, "username": {"alice"},
		"password": {"Wonderland-Pass-1"}, "scope": {"openid profile offline_access"}, "code_challenge": {ch}, "code_challenge_method": {"S256"}})
	if err != nil {
		return nil, err
	}
	return postForm(base+"/oauth/token", url.Values{"client_id": {"test-native"}, "grant_type": {"authorization_code"}, "code": {c.Code}, "code_verifier": {v}})
}

func main() {
	base := flag.String("base", "http://127.0.0.1:18601", "testbed base URL")
	conc := flag.Int("c", 64, "concurrent workers")
	dur := flag.Duration("d", 20*time.Second, "duration per scenario")
	scenario := flag.String("scenario", "all", "jwks|discovery|me|refresh|login|all")
	flag.Parse()
	want := func(s string) bool { return *scenario == "all" || *scenario == s }
	if want("jwks") {
		run("jwks", *conc, *dur, func(int) any { return nil }, func(any) (any, error) { return nil, get(*base+"/.well-known/jwks.json", "") }).print()
	}
	if want("discovery") {
		run("discovery", *conc, *dur, func(int) any { return nil }, func(any) (any, error) {
			return nil, get(*base+"/.well-known/openid-configuration", "")
		}).print()
	}
	if want("me") || want("refresh") {
		fmt.Fprintf(os.Stderr, "signing in %d sessions…\n", *conc)
		sessions := make([]*tokens, *conc)
		for i := range sessions {
			t, err := login(*base)
			if err != nil {
				fmt.Fprintln(os.Stderr, "login failed:", err)
				os.Exit(1)
			}
			sessions[i] = t
		}
		if want("me") {
			run("me", *conc, *dur, func(w int) any { return sessions[w] }, func(st any) (any, error) {
				return nil, get(*base+"/api/v1/me", st.(*tokens).AccessToken)
			}).print()
		}
		if want("refresh") {
			run("refresh", *conc, *dur, func(w int) any { return sessions[w] }, func(st any) (any, error) {
				t, err := postForm(*base+"/oauth/token", url.Values{"client_id": {"test-native"}, "grant_type": {"refresh_token"},
					"refresh_token": {st.(*tokens).RefreshToken}})
				if err != nil {
					return nil, err
				}
				return t, nil
			}).print()
		}
	}
	if want("login") {
		run("login", *conc, *dur, func(int) any { return nil }, func(any) (any, error) { _, err := login(*base); return nil, err }).print()
	}
}

package httpx

import (
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// A tiny Prometheus text-format registry. It avoids the client_golang
// dependency while giving the admin dashboard and scrapers the numbers they need.

var latencyBuckets = []float64{0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5}

type routeStats struct {
	count   [6]atomic.Uint64 // by status class 0..5
	buckets []atomic.Uint64
	sumNs   atomic.Uint64
}

type registry struct {
	mu       sync.RWMutex
	routes   map[string]*routeStats
	counters sync.Map // name -> *atomic.Uint64
	gauges   sync.Map // name -> func() float64
	start    time.Time
}

var Metrics = &registry{routes: map[string]*routeStats{}, start: time.Now()}

func (r *registry) Observe(route string, status int, d time.Duration) {
	if route == "" {
		route = "unmatched"
	}
	r.mu.RLock()
	s, ok := r.routes[route]
	r.mu.RUnlock()
	if !ok {
		r.mu.Lock()
		if s, ok = r.routes[route]; !ok {
			s = &routeStats{buckets: make([]atomic.Uint64, len(latencyBuckets))}
			r.routes[route] = s
		}
		r.mu.Unlock()
	}
	class := status / 100
	if class < 0 || class > 5 {
		class = 0
	}
	s.count[class].Add(1)
	sec := d.Seconds()
	for i, b := range latencyBuckets {
		if sec <= b {
			s.buckets[i].Add(1)
		}
	}
	s.sumNs.Add(uint64(d.Nanoseconds()))
}

// Inc increments a named counter, e.g. "tokens_issued_total{grant=\"refresh_token\"}".
func (r *registry) Inc(name string) {
	v, _ := r.counters.LoadOrStore(name, new(atomic.Uint64))
	v.(*atomic.Uint64).Add(1)
}

func (r *registry) Counter(name string) uint64 {
	if v, ok := r.counters.Load(name); ok {
		return v.(*atomic.Uint64).Load()
	}
	return 0
}

// Gauge registers a callback evaluated at scrape time.
func (r *registry) Gauge(name string, f func() float64) { r.gauges.Store(name, f) }

func (r *registry) Write(w io.Writer) {
	fmt.Fprintf(w, "moon_sso_uptime_seconds %d\n", int64(time.Since(r.start).Seconds()))
	r.mu.RLock()
	names := make([]string, 0, len(r.routes))
	for k := range r.routes {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, route := range names {
		s := r.routes[route]
		lbl := strings.ReplaceAll(route, `"`, `'`)
		var total uint64
		for class := 1; class <= 5; class++ {
			n := s.count[class].Load()
			total += n
			if n > 0 {
				fmt.Fprintf(w, "moon_sso_http_requests_total{route=%q,class=\"%dxx\"} %d\n", lbl, class, n)
			}
		}
		for i, b := range latencyBuckets {
			fmt.Fprintf(w, "moon_sso_http_duration_seconds_bucket{route=%q,le=\"%g\"} %d\n", lbl, b, s.buckets[i].Load())
		}
		fmt.Fprintf(w, "moon_sso_http_duration_seconds_bucket{route=%q,le=\"+Inf\"} %d\n", lbl, total)
		fmt.Fprintf(w, "moon_sso_http_duration_seconds_sum{route=%q} %g\n", lbl, float64(s.sumNs.Load())/1e9)
		fmt.Fprintf(w, "moon_sso_http_duration_seconds_count{route=%q} %d\n", lbl, total)
	}
	r.mu.RUnlock()
	var lines []string
	r.counters.Range(func(k, v any) bool {
		lines = append(lines, fmt.Sprintf("moon_sso_%s %d", k, v.(*atomic.Uint64).Load()))
		return true
	})
	r.gauges.Range(func(k, v any) bool {
		val := v.(func() float64)()
		if !math.IsNaN(val) {
			lines = append(lines, fmt.Sprintf("moon_sso_%s %g", k, val))
		}
		return true
	})
	sort.Strings(lines)
	for _, l := range lines {
		fmt.Fprintln(w, l)
	}
}

package auth

import (
	"hash/maphash"
	"math"
	"sync"
	"time"
)

// Limiter is an in-process token bucket keyed by string. Buckets idle long
// enough to be full again are garbage collected.
type Limiter struct {
	rate   float64 // tokens per second
	burst  float64
	seed   maphash.Seed
	shards [16]limShard
	now    func() time.Time
}

type limShard struct {
	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

// NewLimiter allows burst events immediately and then `perMinute` per minute.
func NewLimiter(perMinute float64, burst int) *Limiter {
	l := &Limiter{rate: perMinute / 60, burst: float64(burst), seed: maphash.MakeSeed(), now: time.Now}
	for i := range l.shards {
		l.shards[i].buckets = map[string]*bucket{}
	}
	return l
}

func (l *Limiter) shard(key string) *limShard {
	return &l.shards[maphash.String(l.seed, key)%uint64(len(l.shards))]
}

// Allow consumes one token. When denied it returns how long until one is available.
func (l *Limiter) Allow(key string) (bool, time.Duration) {
	s := l.shard(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	now := l.now()
	b, ok := s.buckets[key]
	if !ok {
		b = &bucket{tokens: l.burst, last: now}
		s.buckets[key] = b
	}
	b.tokens = math.Min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.rate)
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	wait := time.Duration((1 - b.tokens) / l.rate * float64(time.Second))
	return false, wait
}

// Peek reports whether a token is available without consuming it.
func (l *Limiter) Peek(key string) bool {
	s := l.shard(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.buckets[key]
	if !ok {
		return true
	}
	return math.Min(l.burst, b.tokens+l.now().Sub(b.last).Seconds()*l.rate) >= 1
}

// Reset forgets a key (e.g. after a successful login).
func (l *Limiter) Reset(key string) {
	s := l.shard(key)
	s.mu.Lock()
	delete(s.buckets, key)
	s.mu.Unlock()
}

// GC removes buckets that have refilled completely.
func (l *Limiter) GC() {
	full := time.Duration(l.burst / l.rate * float64(time.Second))
	cutoff := l.now().Add(-full)
	for i := range l.shards {
		s := &l.shards[i]
		s.mu.Lock()
		for k, b := range s.buckets {
			if b.last.Before(cutoff) {
				delete(s.buckets, k)
			}
		}
		s.mu.Unlock()
	}
}

// Throttle tracks login failures and imposes a progressive delay instead of a
// hard lockout, so attackers cannot lock real users out of their accounts.
type Throttle struct {
	mu       sync.Mutex
	failures map[string]*failRec
	now      func() time.Time
}

type failRec struct {
	n    int
	last time.Time
}

func NewThrottle() *Throttle { return &Throttle{failures: map[string]*failRec{}, now: time.Now} }

// Delay returns the wait required before the next attempt for key.
func (t *Throttle) Delay(key string) time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	r, ok := t.failures[key]
	if !ok || r.n < 3 {
		return 0
	}
	// 3 failures → 1s, then doubling up to 5 minutes.
	d := time.Second << min(r.n-3, 9)
	if d > 5*time.Minute {
		d = 5 * time.Minute
	}
	until := r.last.Add(d)
	if now := t.now(); now.Before(until) {
		return until.Sub(now)
	}
	return 0
}

func (t *Throttle) Fail(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	r, ok := t.failures[key]
	now := t.now()
	if !ok || now.Sub(r.last) > time.Hour {
		r = &failRec{}
		t.failures[key] = r
	}
	r.n++
	r.last = now
}

func (t *Throttle) Success(key string) {
	t.mu.Lock()
	delete(t.failures, key)
	t.mu.Unlock()
}

func (t *Throttle) GC() {
	t.mu.Lock()
	defer t.mu.Unlock()
	cutoff := t.now().Add(-time.Hour)
	for k, r := range t.failures {
		if r.last.Before(cutoff) {
			delete(t.failures, k)
		}
	}
}

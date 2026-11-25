// Package cache provides a sharded, size-bounded TTL cache for hot lookups
// (sessions, clients, settings). It is safe for concurrent use.
package cache

import (
	"container/list"
	"hash/maphash"
	"sync"
	"time"
)

const shards = 32

type entry[K comparable, V any] struct {
	key K
	val V
	exp time.Time
}

type shard[K comparable, V any] struct {
	mu    sync.Mutex
	items map[K]*list.Element
	order *list.List
	max   int
}

// Cache is an LRU with per-entry expiry.
type Cache[K comparable, V any] struct {
	seed   maphash.Seed
	shards [shards]*shard[K, V]
	ttl    time.Duration
	now    func() time.Time
}

func New[K comparable, V any](maxEntries int, ttl time.Duration) *Cache[K, V] {
	c := &Cache[K, V]{seed: maphash.MakeSeed(), ttl: ttl, now: time.Now}
	per := maxEntries / shards
	if per < 8 {
		per = 8
	}
	for i := range c.shards {
		c.shards[i] = &shard[K, V]{items: map[K]*list.Element{}, order: list.New(), max: per}
	}
	return c
}

func (c *Cache[K, V]) shard(k K) *shard[K, V] {
	return c.shards[maphash.Comparable(c.seed, k)%shards]
}

func (c *Cache[K, V]) Get(k K) (V, bool) {
	s := c.shard(k)
	s.mu.Lock()
	defer s.mu.Unlock()
	el, ok := s.items[k]
	if !ok {
		var zero V
		return zero, false
	}
	e := el.Value.(*entry[K, V])
	if c.now().After(e.exp) {
		s.order.Remove(el)
		delete(s.items, k)
		var zero V
		return zero, false
	}
	s.order.MoveToFront(el)
	return e.val, true
}

func (c *Cache[K, V]) Set(k K, v V) { c.SetTTL(k, v, c.ttl) }

func (c *Cache[K, V]) SetTTL(k K, v V, ttl time.Duration) {
	s := c.shard(k)
	s.mu.Lock()
	defer s.mu.Unlock()
	exp := c.now().Add(ttl)
	if el, ok := s.items[k]; ok {
		e := el.Value.(*entry[K, V])
		e.val, e.exp = v, exp
		s.order.MoveToFront(el)
		return
	}
	s.items[k] = s.order.PushFront(&entry[K, V]{key: k, val: v, exp: exp})
	for s.order.Len() > s.max {
		last := s.order.Back()
		s.order.Remove(last)
		delete(s.items, last.Value.(*entry[K, V]).key)
	}
}

func (c *Cache[K, V]) Delete(k K) {
	s := c.shard(k)
	s.mu.Lock()
	defer s.mu.Unlock()
	if el, ok := s.items[k]; ok {
		s.order.Remove(el)
		delete(s.items, k)
	}
}

// DeleteFunc removes all entries whose value matches pred.
func (c *Cache[K, V]) DeleteFunc(pred func(K, V) bool) {
	for _, s := range c.shards {
		s.mu.Lock()
		for k, el := range s.items {
			if pred(k, el.Value.(*entry[K, V]).val) {
				s.order.Remove(el)
				delete(s.items, k)
			}
		}
		s.mu.Unlock()
	}
}

func (c *Cache[K, V]) Len() int {
	n := 0
	for _, s := range c.shards {
		s.mu.Lock()
		n += s.order.Len()
		s.mu.Unlock()
	}
	return n
}

package cache

import (
	"container/heap"
	"fmt"
	"math/rand"
	"reflect"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/zhouchenh/secDNS/pkg/upstream/resolver"
)

// TestDescriptorDefaultMaxEntries pins the documented default: a cache config that
// omits maxEntries is bounded at DefaultMaxEntries, and an explicit value (including
// 0 = unlimited) is kept as configured.
func TestDescriptorDefaultMaxEntries(t *testing.T) {
	describe := func(cfg map[string]interface{}) *Cache {
		t.Helper()
		d, ok := resolver.GetResolverDescriptorByTypeName("cache")
		if !ok {
			t.Fatal("cache descriptor not registered")
		}
		obj, s, f := d.Describe(cfg)
		c, ok := obj.(*Cache)
		// The upstream resolver is omitted (it needs the config loader); only the
		// numeric fields are under test here.
		if !ok || s < 1 {
			t.Fatalf("describe failed: %T successes=%d failures=%d", obj, s, f)
		}
		return c
	}
	if got := describe(map[string]interface{}{}).MaxEntries; got != DefaultMaxEntries {
		t.Fatalf("default MaxEntries = %d, want %d", got, DefaultMaxEntries)
	}
	if DefaultMaxEntries <= 0 || DefaultMaxEntries > 100000 {
		t.Fatalf("DefaultMaxEntries = %d, want a bounded value <= 100000", DefaultMaxEntries)
	}
	if got := describe(map[string]interface{}{"maxEntries": float64(250000)}).MaxEntries; got != 250000 {
		t.Fatalf("explicit MaxEntries = %d, want 250000", got)
	}
	if got := describe(map[string]interface{}{"maxEntries": float64(0)}).MaxEntries; got != 0 {
		t.Fatalf("explicit MaxEntries 0 = %d, want 0 (unlimited)", got)
	}
}

// TestExpirationHeapPopZeroesSlot verifies that Pop clears the vacated backing-array
// slot, so the popped key string is not kept reachable by the heap's spare capacity.
func TestExpirationHeapPopZeroesSlot(t *testing.T) {
	h := &expirationHeap{}
	base := time.Now()
	for i := 0; i < 8; i++ {
		heap.Push(h, expirationItem{key: fmt.Sprintf("k%d", i), expiresAt: base.Add(time.Duration(i) * time.Second)})
	}
	for i := 0; i < 8; i++ {
		heap.Pop(h)
		full := (*h)[:cap(*h)]
		for j := len(*h); j < len(full); j++ {
			if full[j].key != "" || !full[j].expiresAt.IsZero() {
				t.Fatalf("after pop %d: vacated slot %d still holds %+v", i, j, full[j])
			}
		}
	}
}

// TestCleanupShrinksAfterBurst verifies that once a burst of entries has expired and been
// swept, the expiration heap's backing array and the entry map are rebuilt at the live
// size instead of keeping their peak allocation.
func TestCleanupShrinksAfterBurst(t *testing.T) {
	mock := &mockResolver{response: aResponse("x.example.")}
	c := &Cache{Resolver: mock, CleanupInterval: time.Hour, TTLJitterPercent: -1}
	c.initOnce.Do(c.init)
	defer c.Stop()

	const burst = 20000
	short := aResponse("burst.example.")
	short.Answer[0].Header().Ttl = 1
	for i := 0; i < burst; i++ {
		c.set(fmt.Sprintf("burst-%d.example.:1:1", i), short)
	}
	// A few long-lived survivors.
	long := aResponse("keep.example.")
	long.Answer[0].Header().Ttl = 3600
	for i := 0; i < 10; i++ {
		c.set(fmt.Sprintf("keep-%d.example.:1:1", i), long)
	}

	c.mutex.RLock()
	peakCap := cap(c.queue)
	mapBefore := reflect.ValueOf(c.entries).Pointer()
	c.mutex.RUnlock()
	if peakCap < burst {
		t.Fatalf("setup: heap cap %d, want >= %d", peakCap, burst)
	}

	// Move the burst's expiry into the past instead of sleeping.
	c.mutex.Lock()
	past := time.Now().Add(-time.Minute)
	for _, e := range c.entries {
		if e.OriginalTTL == 1 {
			e.ExpiresAt = past
		}
	}
	c.rebuildExpirationQueueLocked()
	c.mutex.Unlock()

	c.cleanupExpired()

	c.mutex.RLock()
	defer c.mutex.RUnlock()
	if len(c.entries) != 10 {
		t.Fatalf("entries after sweep = %d, want 10", len(c.entries))
	}
	if got := cap(c.queue); got > 4*len(c.queue)+compactMinSlack {
		t.Fatalf("heap cap after drain = %d (len %d, peak %d): backing array not shrunk", got, len(c.queue), peakCap)
	}
	if reflect.ValueOf(c.entries).Pointer() == mapBefore {
		t.Fatalf("entry map was not rebuilt after draining from %d to %d entries", burst+10, len(c.entries))
	}
	for i := 0; i < 10; i++ {
		if _, ok := c.entries[fmt.Sprintf("keep-%d.example.:1:1", i)]; !ok {
			t.Fatalf("survivor keep-%d lost during compaction", i)
		}
	}
	if c.lru.Size() != len(c.entries) {
		t.Fatalf("lru len %d != entries %d", c.lru.Size(), len(c.entries))
	}
}

// TestMaxTTLIsUpperBoundWithJitter verifies that TTL jitter cannot push an entry's TTL
// above MaxTTL, for both new entries and updates of an existing entry.
func TestMaxTTLIsUpperBoundWithJitter(t *testing.T) {
	mock := &mockResolver{response: aResponse("x.example.")}
	c := &Cache{Resolver: mock, CleanupInterval: time.Hour, MaxTTL: 7200 * time.Second, TTLJitterPercent: 0.05,
		DefaultPositiveTTL: 48 * time.Hour}
	c.rng = rand.New(rand.NewSource(1))
	c.initOnce.Do(c.init)
	defer c.Stop()

	resp := aResponse("long.example.")
	resp.Answer[0].Header().Ttl = 86400
	for i := 0; i < 500; i++ {
		key := fmt.Sprintf("n%d.example.:%d:1", i, dns.TypeA)
		c.set(key, resp) // new entry
		c.set(key, resp) // update path
		c.mutex.RLock()
		e := c.entries[key]
		ttl, lifetime := e.OriginalTTL, e.ExpiresAt.Sub(e.CachedAt)
		c.mutex.RUnlock()
		if ttl > 7200 || lifetime > 7200*time.Second {
			t.Fatalf("entry %d: TTL %d s (lifetime %s) exceeds MaxTTL 7200 s", i, ttl, lifetime)
		}
	}
}

// TestStopOnUnusedCache verifies Stop does not panic on a cache that never served a
// query, that a second Stop is harmless, and that the cache still answers afterwards.
func TestStopOnUnusedCache(t *testing.T) {
	mock := &mockResolver{response: aResponse("example.com.")}
	c := &Cache{Resolver: mock}
	c.Stop()
	c.Stop()

	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	if _, err := c.Resolve(q, 4); err != nil {
		t.Fatalf("Resolve after Stop: %v", err)
	}
}

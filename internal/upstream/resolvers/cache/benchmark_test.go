package cache

import (
	"fmt"
	"github.com/miekg/dns"
	"sync"
	"testing"
	"time"
)

func BenchmarkCacheLookup_Hit(b *testing.B) {
	response := new(dns.Msg)
	response.SetQuestion("example.com.", dns.TypeA)
	response.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{
				Name:   "example.com.",
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			A: []byte{93, 184, 216, 34},
		},
	}

	mock := &mockResolver{response: response}
	cache := &Cache{
		Resolver:   mock,
		MaxEntries: 10000,
	}

	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)

	// Prime the cache
	if _, err := cache.Resolve(query, 10); err != nil {
		b.Fatalf("failed to prime cache: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		if _, err := cache.Resolve(query, 10); err != nil {
			b.Fatalf("resolve failed: %v", err)
		}
	}
}

func BenchmarkCacheLookup_Miss(b *testing.B) {
	response := new(dns.Msg)
	response.SetQuestion("example.com.", dns.TypeA)
	response.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{
				Name:   "example.com.",
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			A: []byte{93, 184, 216, 34},
		},
	}

	mock := &mockResolver{response: response}
	cache := &Cache{
		Resolver:   mock,
		MaxEntries: 10000,
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		query := new(dns.Msg)
		query.SetQuestion(fmt.Sprintf("example%d.com.", i), dns.TypeA)
		if _, err := cache.Resolve(query, 10); err != nil {
			b.Fatalf("resolve failed: %v", err)
		}
	}
}

func BenchmarkCacheInsert(b *testing.B) {
	response := new(dns.Msg)
	response.SetQuestion("example.com.", dns.TypeA)
	response.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{
				Name:   "example.com.",
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			A: []byte{93, 184, 216, 34},
		},
	}

	cache := &Cache{
		MaxEntries: 100000,
	}
	// Manually initialize for benchmarking set() directly
	cache.entries = make(map[string]*Entry)
	cache.lru = NewLRUList()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		key := fmt.Sprintf("example%d.com.:1:1", i)
		cache.set(key, response)
	}
}

func BenchmarkCacheConcurrent(b *testing.B) {
	response := new(dns.Msg)
	response.SetQuestion("example.com.", dns.TypeA)
	response.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{
				Name:   "example.com.",
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			A: []byte{93, 184, 216, 34},
		},
	}

	mock := &mockResolver{response: response}
	cache := &Cache{
		Resolver:   mock,
		MaxEntries: 10000,
	}

	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)

	// Prime the cache
	if _, err := cache.Resolve(query, 10); err != nil {
		b.Fatalf("failed to prime cache: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := cache.Resolve(query, 10); err != nil {
				b.Fatalf("resolve failed: %v", err)
			}
		}
	})
}

func BenchmarkLRU_AddToFront(b *testing.B) {
	// Bounded: cap the list at a fixed size by trimming the tail, so memory stays O(1)
	// in b.N regardless of -benchtime (an earlier unbounded version grew by b.N).
	const cap = 4096
	lru := NewLRUList()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		lru.AddToFront("key")
		if lru.Size() > cap {
			lru.RemoveTail()
		}
	}
}

func BenchmarkLRU_MoveToFront(b *testing.B) {
	lru := NewLRUList()
	nodes := make([]*LRUNode, 1000)

	for i := 0; i < 1000; i++ {
		nodes[i] = lru.AddToFront(fmt.Sprintf("key%d", i))
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		lru.MoveToFront(nodes[i%1000])
	}
}

func BenchmarkLRU_Remove(b *testing.B) {
	// Bounded: a fixed-size fixture is churned (remove one node, add a replacement) so
	// memory stays O(fixtureSize), not O(b.N). The previous version pre-allocated
	// make([]*LRUNode, b.N) plus b.N list nodes, which OOM'd the host under a
	// time-based -benchtime. This measures the realistic remove+insert eviction churn.
	const fixtureSize = 4096
	lru := NewLRUList()
	nodes := make([]*LRUNode, fixtureSize)
	for i := 0; i < fixtureSize; i++ {
		nodes[i] = lru.AddToFront("key")
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		idx := i % fixtureSize
		lru.Remove(nodes[idx])
		nodes[idx] = lru.AddToFront("key")
	}
}

func BenchmarkCacheKeyGeneration(b *testing.B) {
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = makeCacheKey(query)
	}
}

func BenchmarkCacheTTLCalculation(b *testing.B) {
	cache := &Cache{}
	entry := &Entry{
		OriginalTTL: 300,
		CachedAt:    time.Now().Add(-10 * time.Second),
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = cache.calculateRemainingTTL(entry)
	}
}

func BenchmarkCacheWithEviction(b *testing.B) {
	response := new(dns.Msg)
	response.SetQuestion("example.com.", dns.TypeA)
	response.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{
				Name:   "example.com.",
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			A: []byte{93, 184, 216, 34},
		},
	}

	mock := &mockResolver{response: response}
	cache := &Cache{
		Resolver:   mock,
		MaxEntries: 1000, // Small cache to trigger evictions
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		query := new(dns.Msg)
		query.SetQuestion(fmt.Sprintf("example%d.com.", i), dns.TypeA)
		if _, err := cache.Resolve(query, 10); err != nil {
			b.Fatalf("resolve failed: %v", err)
		}
	}
}

// BenchmarkCacheGetHit_Parallel measures concurrent cache-hit throughput across a fixed
// set of distinct primed keys. Each parallel hitter touches a different entry, so the
// headline cost is contention on the cache's lock(s) on the get() path — this is the
// benchmark that the CLOCK change (no writer lock per hit) is meant to improve. Bounded:
// the working set is a fixed `keys` entries regardless of b.N.
func BenchmarkCacheGetHit_Parallel(b *testing.B) {
	const keys = 1024
	response := new(dns.Msg)
	response.SetQuestion("example.com.", dns.TypeA)
	response.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   []byte{93, 184, 216, 34},
		},
	}
	mock := &mockResolver{response: response}
	cache := &Cache{Resolver: mock, MaxEntries: keys * 2}

	queries := make([]*dns.Msg, keys)
	for i := 0; i < keys; i++ {
		q := new(dns.Msg)
		q.SetQuestion(fmt.Sprintf("h%d.example.", i), dns.TypeA)
		queries[i] = q
		if _, err := cache.Resolve(q, 10); err != nil {
			b.Fatalf("prime failed: %v", err)
		}
	}

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			if _, err := cache.Resolve(queries[i%keys], 10); err != nil {
				b.Fatalf("resolve failed: %v", err)
			}
			i++
		}
	})
}

func BenchmarkCacheConcurrent_ReadWrite(b *testing.B) {
	response := new(dns.Msg)
	response.SetQuestion("example.com.", dns.TypeA)
	response.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{
				Name:   "example.com.",
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			A: []byte{93, 184, 216, 34},
		},
	}

	mock := &mockResolver{response: response}
	cache := &Cache{
		Resolver:   mock,
		MaxEntries: 10000,
	}

	// Pre-populate with some entries
	for i := 0; i < 100; i++ {
		query := new(dns.Msg)
		query.SetQuestion(fmt.Sprintf("example%d.com.", i), dns.TypeA)
		if _, err := cache.Resolve(query, 10); err != nil {
			b.Fatalf("failed to pre-populate cache: %v", err)
		}
	}

	b.ResetTimer()
	b.ReportAllocs()

	var (
		wg       sync.WaitGroup
		errMu    sync.Mutex
		firstErr error
	)
	recordErr := func(err error) bool {
		if err == nil {
			return false
		}
		errMu.Lock()
		if firstErr == nil {
			firstErr = err
		}
		errMu.Unlock()
		return true
	}
	writers := 4
	readers := 12

	// Writers (25%)
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < b.N/writers; j++ {
				query := new(dns.Msg)
				query.SetQuestion(fmt.Sprintf("new%d-%d.com.", id, j), dns.TypeA)
				if _, err := cache.Resolve(query, 10); recordErr(err) {
					return
				}
			}
		}(i)
	}

	// Readers (75%)
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < b.N/readers; j++ {
				query := new(dns.Msg)
				query.SetQuestion(fmt.Sprintf("example%d.com.", j%100), dns.TypeA)
				if _, err := cache.Resolve(query, 10); recordErr(err) {
					return
				}
			}
		}(i)
	}

	wg.Wait()
	if firstErr != nil {
		b.Fatalf("resolve failed: %v", firstErr)
	}
}

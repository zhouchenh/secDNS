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
	cache.Resolve(query, 10)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		cache.Resolve(query, 10)
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
		cache.Resolve(query, 10)
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
	cache.entries = make(map[string]*CacheEntry)
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
	cache.Resolve(query, 10)

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			cache.Resolve(query, 10)
		}
	})
}

func BenchmarkLRU_AddToFront(b *testing.B) {
	lru := NewLRUList()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		lru.AddToFront(fmt.Sprintf("key%d", i))
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
	lru := NewLRUList()
	nodes := make([]*LRUNode, b.N)

	for i := 0; i < b.N; i++ {
		nodes[i] = lru.AddToFront(fmt.Sprintf("key%d", i))
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		lru.Remove(nodes[i])
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
	entry := &CacheEntry{
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
		cache.Resolve(query, 10)
	}
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
		cache.Resolve(query, 10)
	}

	b.ResetTimer()
	b.ReportAllocs()

	var wg sync.WaitGroup
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
				cache.Resolve(query, 10)
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
				cache.Resolve(query, 10)
			}
		}(i)
	}

	wg.Wait()
}

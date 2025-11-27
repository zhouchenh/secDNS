package cache

import (
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"github.com/zhouchenh/secDNS/pkg/upstream/resolver"
	"net"
	"sync"
	"testing"
	"time"
)

func newTestCache(res resolver.Resolver) *Cache {
	return &Cache{
		Resolver:          res,
		MaxEntries:        100,
		ServeStale:        false,
		TTLJitterPercent:  0,
		PrefetchThreshold: 0,
		PrefetchPercent:   1,
	}
}

func TestCacheKey(t *testing.T) {
	tests := []struct {
		name     string
		qname    string
		qtype    uint16
		qclass   uint16
		expected string
		mutate   func(msg *dns.Msg)
	}{
		{"A record", "example.com.", dns.TypeA, dns.ClassINET, "example.com.:1:1", nil},
		{"AAAA record", "example.com.", dns.TypeAAAA, dns.ClassINET, "example.com.:28:1", nil},
		{"Case insensitive", "Example.Com.", dns.TypeA, dns.ClassINET, "example.com.:1:1", nil},
		{"Different type", "test.org.", dns.TypeMX, dns.ClassINET, "test.org.:15:1", nil},
		{
			name:     "ECS IPv4 subnet",
			qname:    "ecs.example.com.",
			qtype:    dns.TypeA,
			qclass:   dns.ClassINET,
			expected: "ecs.example.com.:1:1:ecs:1:24:203.0.113.0",
			mutate: func(msg *dns.Msg) {
				msg.SetEdns0(4096, false)
				opt := msg.IsEdns0()
				opt.Option = append(opt.Option, &dns.EDNS0_SUBNET{
					Code:          dns.EDNS0SUBNET,
					Family:        1,
					SourceNetmask: 24,
					Address:       net.ParseIP("203.0.113.45"),
				})
			},
		},
		{
			name:     "ECS IPv6 subnet",
			qname:    "ipv6.example.com.",
			qtype:    dns.TypeAAAA,
			qclass:   dns.ClassINET,
			expected: "ipv6.example.com.:28:1:ecs:2:48:2001:db8:abcd::",
			mutate: func(msg *dns.Msg) {
				msg.SetEdns0(4096, false)
				opt := msg.IsEdns0()
				opt.Option = append(opt.Option, &dns.EDNS0_SUBNET{
					Code:          dns.EDNS0SUBNET,
					Family:        2,
					SourceNetmask: 48,
					Address:       net.ParseIP("2001:db8:abcd:1234::1"),
				})
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			query := new(dns.Msg)
			query.SetQuestion(tt.qname, tt.qtype)
			query.Question[0].Qclass = tt.qclass
			if tt.mutate != nil {
				tt.mutate(query)
			}

			key := makeCacheKey(query)
			if key != tt.expected {
				t.Errorf("makeCacheKey() = %q, expected %q", key, tt.expected)
			}
		})
	}
}

func TestCacheHitMiss(t *testing.T) {
	// Create a response
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
	cache := newTestCache(mock)

	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)

	// First query - should miss and call upstream
	resp1, err := cache.Resolve(query, 10)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if resp1 == nil {
		t.Fatal("Resolve() returned nil response")
	}
	if mock.calls != 1 {
		t.Errorf("Expected 1 upstream call, got %d", mock.calls)
	}

	stats := cache.Stats()
	if stats.Misses != 1 {
		t.Errorf("Expected 1 miss, got %d", stats.Misses)
	}

	// Second query - should hit cache and not call upstream
	resp2, err := cache.Resolve(query, 10)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if resp2 == nil {
		t.Fatal("Resolve() returned nil response")
	}
	if mock.calls != 1 {
		t.Errorf("Expected 1 upstream call (cached), got %d", mock.calls)
	}

	stats = cache.Stats()
	if stats.Hits != 1 {
		t.Errorf("Expected 1 hit, got %d", stats.Hits)
	}
	if stats.HitRate != 0.5 { // 1 hit / 2 total
		t.Errorf("Expected hit rate 0.5, got %f", stats.HitRate)
	}
}

func TestCacheTTLAdjustment(t *testing.T) {
	response := new(dns.Msg)
	response.SetQuestion("example.com.", dns.TypeA)
	response.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{
				Name:   "example.com.",
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    10, // 10 second TTL
			},
			A: []byte{93, 184, 216, 34},
		},
	}

	mock := &mockResolver{response: response}
	cache := newTestCache(mock)

	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)

	// First query - cache it
	resp1, _ := cache.Resolve(query, 10)
	initialTTL := resp1.Answer[0].Header().Ttl

	// Wait 2 seconds
	time.Sleep(2 * time.Second)

	// Second query - TTL should be reduced
	resp2, _ := cache.Resolve(query, 10)
	adjustedTTL := resp2.Answer[0].Header().Ttl

	if adjustedTTL >= initialTTL {
		t.Errorf("TTL not adjusted: initial=%d, after 2s=%d", initialTTL, adjustedTTL)
	}

	// TTL should be roughly 2 seconds less (allow 1s tolerance)
	expectedTTL := initialTTL - 2
	if adjustedTTL < expectedTTL-1 || adjustedTTL > expectedTTL+1 {
		t.Errorf("TTL adjustment incorrect: expected ~%d, got %d", expectedTTL, adjustedTTL)
	}
}

func TestCacheExpiration(t *testing.T) {
	response := new(dns.Msg)
	response.SetQuestion("example.com.", dns.TypeA)
	response.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{
				Name:   "example.com.",
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    2, // 2 second TTL
			},
			A: []byte{93, 184, 216, 34},
		},
	}

	mock := &mockResolver{response: response}
	cache := newTestCache(mock)

	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)

	// First query - cache it
	cache.Resolve(query, 10)
	if mock.calls != 1 {
		t.Fatalf("Expected 1 call, got %d", mock.calls)
	}

	// Immediate second query - should hit cache
	cache.Resolve(query, 10)
	if mock.calls != 1 {
		t.Errorf("Expected 1 call (cached), got %d", mock.calls)
	}

	// Wait for expiration
	time.Sleep(3 * time.Second)

	// Third query - should miss (expired) and call upstream again
	cache.Resolve(query, 10)
	if mock.calls != 2 {
		t.Errorf("Expected 2 calls (expired), got %d", mock.calls)
	}
}

func TestCacheLRUEviction(t *testing.T) {
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
	cache := newTestCache(mock)
	cache.MaxEntries = 3

	// Cache 4 different entries to trigger eviction
	for i := 1; i <= 4; i++ {
		query := new(dns.Msg)
		query.SetQuestion(fmt.Sprintf("example%d.com.", i), dns.TypeA)
		cache.Resolve(query, 10)
	}

	stats := cache.Stats()
	if stats.Size != 3 {
		t.Errorf("Expected cache size 3, got %d", stats.Size)
	}
	if stats.Evictions != 1 {
		t.Errorf("Expected 1 eviction, got %d", stats.Evictions)
	}

	// Verify LRU behavior: example1 should be evicted, example2-4 should be cached
	// IMPORTANT: Check the entries that should be cached FIRST, then check the evicted one LAST
	// to avoid re-caching interfering with verification
	testCases := []struct {
		qname       string
		shouldHit   bool
		description string
	}{
		{"example2.com.", true, "second entry should still be cached"},
		{"example3.com.", true, "third entry should still be cached"},
		{"example4.com.", true, "fourth entry should be cached"},
		{"example1.com.", false, "first entry (LRU) should be evicted"},
	}

	for _, tc := range testCases {
		query := new(dns.Msg)
		query.SetQuestion(tc.qname, dns.TypeA)
		mock.calls = 0
		cache.Resolve(query, 10)

		if tc.shouldHit && mock.calls != 0 {
			t.Errorf("%s: expected cache hit, but got %d upstream calls", tc.description, mock.calls)
		}
		if !tc.shouldHit && mock.calls != 1 {
			t.Errorf("%s: expected cache miss, but got %d upstream calls", tc.description, mock.calls)
		}
	}
}

func TestCacheNegativeNXDOMAIN(t *testing.T) {
	// NXDOMAIN response
	response := new(dns.Msg)
	response.SetQuestion("notexist.example.com.", dns.TypeA)
	response.Rcode = dns.RcodeNameError
	response.Ns = []dns.RR{
		&dns.SOA{
			Hdr: dns.RR_Header{
				Name:   "example.com.",
				Rrtype: dns.TypeSOA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			Minttl: 600,
		},
	}

	mock := &mockResolver{response: response}
	cache := newTestCache(mock)
	cache.NegativeTTL = 5 * time.Minute

	query := new(dns.Msg)
	query.SetQuestion("notexist.example.com.", dns.TypeA)

	// First query - should cache NXDOMAIN
	resp1, _ := cache.Resolve(query, 10)
	if resp1.Rcode != dns.RcodeNameError {
		t.Errorf("Expected NXDOMAIN, got rcode %d", resp1.Rcode)
	}
	if mock.calls != 1 {
		t.Fatalf("Expected 1 call, got %d", mock.calls)
	}

	// Second query - should hit cache
	resp2, _ := cache.Resolve(query, 10)
	if resp2.Rcode != dns.RcodeNameError {
		t.Errorf("Expected cached NXDOMAIN, got rcode %d", resp2.Rcode)
	}
	if mock.calls != 1 {
		t.Errorf("Expected 1 call (cached NXDOMAIN), got %d", mock.calls)
	}

	stats := cache.Stats()
	if stats.Hits != 1 {
		t.Errorf("Expected 1 hit for negative cache, got %d", stats.Hits)
	}
}

func TestCacheNegativeNODATA(t *testing.T) {
	// NODATA response (NOERROR with no answers)
	response := new(dns.Msg)
	response.SetQuestion("example.com.", dns.TypeAAAA)
	response.Rcode = dns.RcodeSuccess
	// No answer section

	mock := &mockResolver{response: response}
	cache := newTestCache(mock)
	cache.NegativeTTL = 5 * time.Minute

	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeAAAA)

	// First query - should cache NODATA
	resp1, _ := cache.Resolve(query, 10)
	if len(resp1.Answer) != 0 {
		t.Errorf("Expected NODATA (no answers), got %d answers", len(resp1.Answer))
	}
	if mock.calls != 1 {
		t.Fatalf("Expected 1 call, got %d", mock.calls)
	}

	// Second query - should hit cache
	cache.Resolve(query, 10)
	if mock.calls != 1 {
		t.Errorf("Expected 1 call (cached NODATA), got %d", mock.calls)
	}
}

func TestCacheConcurrency(t *testing.T) {
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
	cache := newTestCache(mock)
	cache.MaxEntries = 1000

	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)

	// Run 100 concurrent queries
	var wg sync.WaitGroup
	errCh := make(chan error, 100)

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := cache.Resolve(query, 10); err != nil {
				errCh <- err
			}
		}()
	}

	wg.Wait()
	close(errCh)

	// Check for errors
	for err := range errCh {
		t.Errorf("Concurrent query error: %v", err)
	}

	// Should have total 100 requests
	stats := cache.Stats()
	total := stats.Hits + stats.Misses
	if total != 100 {
		t.Errorf("Expected 100 total requests, got %d", total)
	}
}

func TestCacheMinMaxTTL(t *testing.T) {
	response := new(dns.Msg)
	response.SetQuestion("example.com.", dns.TypeA)
	response.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{
				Name:   "example.com.",
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    10, // Very short TTL
			},
			A: []byte{93, 184, 216, 34},
		},
	}

	mock := &mockResolver{response: response}
	cache := newTestCache(mock)
	cache.MinTTL = 1 * time.Minute
	cache.MaxTTL = 1 * time.Hour

	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)

	// Cache the response
	resp, _ := cache.Resolve(query, 10)

	// Check that TTL was overridden to minimum
	ttl := resp.Answer[0].Header().Ttl
	if ttl < 60 {
		t.Errorf("Expected TTL >= 60 (minTTL), got %d", ttl)
	}
}

func TestCacheDepthCheck(t *testing.T) {
	mock := &mockResolver{}
	cache := newTestCache(mock)

	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)

	// Query with negative depth should fail
	_, err := cache.Resolve(query, -1)
	if !errors.Is(err, resolver.ErrLoopDetected) {
		t.Errorf("Expected ErrLoopDetected, got %v", err)
	}
}

func TestCacheClear(t *testing.T) {
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
	cache := newTestCache(mock)

	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)

	// Cache a response
	cache.Resolve(query, 10)
	if cache.Stats().Size != 1 {
		t.Fatalf("Expected cache size 1, got %d", cache.Stats().Size)
	}

	// Clear the cache
	cache.Clear()

	if cache.Stats().Size != 0 {
		t.Errorf("Expected cache size 0 after clear, got %d", cache.Stats().Size)
	}

	// Next query should miss
	mock.calls = 0
	cache.Resolve(query, 10)
	if mock.calls != 1 {
		t.Errorf("Expected cache miss after clear, got %d upstream calls", mock.calls)
	}
}

func TestCacheCleanup(t *testing.T) {
	response := new(dns.Msg)
	response.SetQuestion("example.com.", dns.TypeA)
	response.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{
				Name:   "example.com.",
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    2, // 2 second TTL
			},
			A: []byte{93, 184, 216, 34},
		},
	}

	mock := &mockResolver{response: response}
	cache := newTestCache(mock)
	cache.CleanupInterval = 1 * time.Second
	defer cache.Stop()

	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)

	// Cache the response
	cache.Resolve(query, 10)
	if cache.Stats().Size != 1 {
		t.Fatalf("Expected cache size 1, got %d", cache.Stats().Size)
	}

	// Wait for expiration + cleanup
	time.Sleep(4 * time.Second)

	// Cache should be cleaned up
	if cache.Stats().Size != 0 {
		t.Errorf("Expected cache size 0 after cleanup, got %d", cache.Stats().Size)
	}
}

func TestCacheControlNoCache(t *testing.T) {
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
			A: []byte{1, 1, 1, 1},
		},
	}
	response.SetEdns0(4096, false)
	opt := response.IsEdns0()
	opt.Option = append(opt.Option, &dns.EDNS0_LOCAL{
		Code: cacheControlOptionCode,
		Data: []byte("nocache"),
	})

	mock := &mockResolver{response: response}
	cache := newTestCache(mock)
	cache.CacheControlEnabled = true

	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)

	cache.Resolve(query, 10)
	if cache.Stats().Size != 0 {
		t.Fatalf("expected no cache entries for nocache directive")
	}
	cache.Resolve(query, 10)
	if mock.calls != 2 {
		t.Fatalf("expected both queries to hit upstream, got %d calls", mock.calls)
	}
}

func TestCacheWarmupQueries(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("warm.example.com.", dns.TypeA)
	mock := &mockResolver{response: msg}
	cache := newTestCache(mock)
	cache.WarmupQueries = []WarmupQuery{
		{Name: "warm.example.com.", Type: dns.TypeA},
	}
	cache.initOnce.Do(func() { cache.init() })

	time.Sleep(200 * time.Millisecond)
	if mock.calls == 0 {
		t.Fatalf("expected warmup to trigger resolver call")
	}
}

func TestCacheDomainStats(t *testing.T) {
	response := new(dns.Msg)
	response.SetQuestion("example.com.", dns.TypeA)
	response.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{
				Name:   "example.com.",
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    5,
			},
			A: []byte{1, 1, 1, 1},
		},
	}
	mock := &mockResolver{response: response}
	cache := newTestCache(mock)

	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)

	cache.Resolve(query, 10) // miss
	cache.Resolve(query, 10) // hit

	stats := cache.DomainStatsFor("example.com.")
	if stats.Hits != 1 || stats.Misses != 1 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
}

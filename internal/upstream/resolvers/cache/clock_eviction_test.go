package cache

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func aResponse(name string) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetQuestion(dns.Fqdn(name), dns.TypeA)
	resp.Rcode = dns.RcodeSuccess
	resp.Answer = append(resp.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.IP{1, 2, 3, 4},
	})
	return resp
}

// TestCacheClockSecondChance verifies the CLOCK / second-chance evictor: an entry whose
// referenced bit was set by a recent hit is spared on the next eviction (its bit is
// cleared and it is promoted), and the next unreferenced entry is evicted instead.
func TestCacheClockSecondChance(t *testing.T) {
	mock := &mockResolver{response: aResponse("example.com.")}
	c := &Cache{Resolver: mock, MaxEntries: 3, CleanupInterval: time.Hour}
	c.initOnce.Do(c.init)
	defer c.Stop()

	mk := func(name string) (*dns.Msg, string) {
		q := new(dns.Msg)
		q.SetQuestion(dns.Fqdn(name), dns.TypeA)
		return q, makeCacheKey(q)
	}
	qa, ka := mk("a.example.")
	qb, kb := mk("b.example.")
	qc, kc := mk("c.example.")
	qd, kd := mk("d.example.")

	// Fill the cache: insertion order a, b, c -> tail (LRU) is a.
	for _, q := range []*dns.Msg{qa, qb, qc} {
		if _, err := c.Resolve(q, 10); err != nil {
			t.Fatalf("prime failed: %v", err)
		}
	}
	// Touch a -> sets its referenced bit (no list promotion under CLOCK), so a is still
	// positionally the tail but now referenced.
	if _, err := c.Resolve(qa, 10); err != nil {
		t.Fatalf("hit failed: %v", err)
	}
	// Insert d at capacity: the evictor scans from the tail, gives a its second chance
	// (clears the bit, promotes it), then evicts the next unreferenced entry, b.
	if _, err := c.Resolve(qd, 10); err != nil {
		t.Fatalf("insert d failed: %v", err)
	}

	c.mutex.RLock()
	_, hasA := c.entries[ka]
	_, hasB := c.entries[kb]
	_, hasC := c.entries[kc]
	_, hasD := c.entries[kd]
	n := len(c.entries)
	c.mutex.RUnlock()

	if n != 3 {
		t.Fatalf("expected 3 entries after eviction, got %d", n)
	}
	if !hasA {
		t.Fatalf("recently-referenced entry 'a' should have survived (second chance)")
	}
	if hasB {
		t.Fatalf("unreferenced entry 'b' should have been evicted")
	}
	if !hasC || !hasD {
		t.Fatalf("entries c and d should be present (c=%v d=%v)", hasC, hasD)
	}
}

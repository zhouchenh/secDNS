package cache

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

func ttlTestA(name string, ttl uint32) dns.RR {
	return &dns.A{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
		A:   []byte{192, 0, 2, 1},
	}
}

func ttlTestPositive(answer ...dns.RR) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	m.Rcode = dns.RcodeSuccess
	m.Answer = answer
	return m
}

func TestExtractTTLPositive(t *testing.T) {
	cname := &dns.CNAME{
		Hdr:    dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 3600},
		Target: "target.example.com.",
	}
	ns := &dns.NS{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 86400},
		Ns:  "ns1.example.com.",
	}

	mixedSections := ttlTestPositive(ttlTestA("example.com.", 7200))
	mixedSections.Ns = []dns.RR{ns}
	mixedSections.Extra = []dns.RR{ttlTestA("ns1.example.com.", 1800)}

	withOPT := ttlTestPositive(ttlTestA("example.com.", 7200))
	withOPT.SetEdns0(4096, true) // DO bit set: OPT header TTL field is non-zero
	if opt := withOPT.IsEdns0(); opt == nil || opt.Hdr.Ttl == 0 {
		t.Fatalf("test setup: expected OPT with non-zero TTL field")
	}

	tests := []struct {
		name  string
		cache *Cache
		msg   *dns.Msg
		want  uint32
	}{
		{"1: TTL 7200, no overrides", &Cache{}, ttlTestPositive(ttlTestA("example.com.", 7200)), 7200},
		{"3: TTL 3600 boundary", &Cache{}, ttlTestPositive(ttlTestA("example.com.", 3600)), 3600},
		{"4: TTL 3599", &Cache{}, ttlTestPositive(ttlTestA("example.com.", 3599)), 3599},
		{"5: TTL 86400, MaxTTL 0", &Cache{}, ttlTestPositive(ttlTestA("example.com.", 86400)), 86400},
		{"6: CNAME 3600 + A 7200", &Cache{}, ttlTestPositive(cname, ttlTestA("target.example.com.", 7200)), 3600},
		{"7: A 7200 + A 60", &Cache{}, ttlTestPositive(ttlTestA("example.com.", 7200), ttlTestA("example.com.", 60)), 60},
		{"8: Answer 7200 + Ns 86400 + Extra 1800", &Cache{}, mixedSections, 1800},
		{"9: A 7200 + OPT ignored", &Cache{}, withOPT, 7200},
		{"10: TTL 0", &Cache{}, ttlTestPositive(ttlTestA("example.com.", 0)), 0},
		{"11: TTL 0x80000000 clamps to 0", &Cache{}, ttlTestPositive(ttlTestA("example.com.", 0x80000000)), 0},
		{"11b: TTL 0x7fffffff kept", &Cache{}, ttlTestPositive(ttlTestA("example.com.", 0x7fffffff)), 0x7fffffff},
		{"14: DefaultPositiveTTL 600 is no ceiling", &Cache{DefaultPositiveTTL: 600 * time.Second}, ttlTestPositive(ttlTestA("example.com.", 7200)), 7200},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cache.extractTTL(tt.msg); got != tt.want {
				t.Fatalf("extractTTL = %d, want %d", got, tt.want)
			}
		})
	}
}

// Case 2: MaxTTL still caps record TTLs after extraction.
func TestExtractTTLWithOverridesMaxTTL(t *testing.T) {
	msg := ttlTestPositive(ttlTestA("example.com.", 7200))
	if got := (&Cache{MaxTTL: 7200 * time.Second}).extractTTLWithOverrides(msg); got != 7200 {
		t.Fatalf("MaxTTL 7200: got %d, want 7200", got)
	}
	if got := (&Cache{MaxTTL: 3600 * time.Second}).extractTTLWithOverrides(msg); got != 3600 {
		t.Fatalf("MaxTTL 3600: got %d, want 3600", got)
	}
	if got := (&Cache{MinTTL: 10000 * time.Second}).extractTTLWithOverrides(msg); got != 10000 {
		t.Fatalf("MinTTL 10000: got %d, want 10000", got)
	}
}

// Case 12 and 13: the negative-response path is unchanged.
func TestExtractTTLNegativeUnchanged(t *testing.T) {
	soa := &dns.SOA{
		Hdr:    dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 7200},
		Ns:     "ns1.example.com.",
		Mbox:   "hostmaster.example.com.",
		Minttl: 900,
	}

	nx := new(dns.Msg)
	nx.SetQuestion("missing.example.com.", dns.TypeA)
	nx.Rcode = dns.RcodeNameError
	nx.Ns = []dns.RR{soa}
	if got := (&Cache{NegativeTTL: 30 * time.Second}).extractTTL(nx); got != 30 {
		t.Fatalf("12: NXDOMAIN with NegativeTTL 30: got %d, want 30", got)
	}

	nodata := new(dns.Msg)
	nodata.SetQuestion("example.com.", dns.TypeAAAA)
	nodata.Rcode = dns.RcodeSuccess
	nodata.Ns = []dns.RR{soa}
	if got := (&Cache{NoDataTTL: 0, NegativeTTL: 30 * time.Second}).extractTTL(nodata); got != 30 {
		t.Fatalf("13: NODATA with NoDataTTL 0, NegativeTTL 30: got %d, want 30", got)
	}
}

// Case 15: end to end through Resolve, covering the stored lifetime and the
// client-visible TTL on a miss.
func TestResolveHonoursLongRecordTTL(t *testing.T) {
	mock := &mockResolver{response: ttlTestPositive(ttlTestA("example.com.", 7200))}
	c := &Cache{
		Resolver:         mock,
		MaxEntries:       100,
		MaxTTL:           7200 * time.Second,
		TTLJitterPercent: 0.05,
		PrefetchPercent:  1,
	}
	defer c.Stop()

	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	resp, err := c.Resolve(query, 10)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(resp.Answer))
	}
	if got := resp.Answer[0].Header().Ttl; got != 7200 {
		t.Fatalf("client-visible TTL on miss = %d, want 7200", got)
	}

	c.mutex.RLock()
	entry, ok := c.entries[makeCacheKey(query)]
	var original uint32
	if ok {
		original = entry.OriginalTTL
	}
	c.mutex.RUnlock()
	if !ok {
		t.Fatalf("expected the response to be cached")
	}
	if original < 6840 || original > 7560 {
		t.Fatalf("stored OriginalTTL = %d, want within [6840, 7560]", original)
	}
}

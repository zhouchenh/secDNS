package address

import (
	"errors"
	"math"
	"testing"

	"github.com/miekg/dns"
	"github.com/zhouchenh/go-descriptor"
	"github.com/zhouchenh/secDNS/internal/upstream/resolvers/sequence"
	resolverpkg "github.com/zhouchenh/secDNS/pkg/upstream/resolver"
)

func newQuery(name string, qtype uint16) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), qtype)
	return msg
}

func describeAddress(t *testing.T, config interface{}) *Address {
	t.Helper()
	d, ok := resolverpkg.GetResolverDescriptorByTypeName("address")
	if !ok {
		t.Fatal("address descriptor is not registered")
	}
	raw, success, failure := d.Describe(config)
	if failure != 0 || success == 0 {
		t.Fatalf("address config failed: success=%d failure=%d", success, failure)
	}
	addr, ok := raw.(*Address)
	if !ok {
		t.Fatalf("address config produced %T", raw)
	}
	return addr
}

func TestLegacyAddressConfigPreservesDefaults(t *testing.T) {
	tests := []struct {
		name   string
		config interface{}
		qtype  uint16
		count  int
	}{
		{name: "string A", config: "192.0.2.1", qtype: dns.TypeA, count: 1},
		{name: "string has no AAAA", config: "192.0.2.1", qtype: dns.TypeAAAA, count: 0},
		{name: "list AAAA", config: []interface{}{"192.0.2.1", "2001:db8::1"}, qtype: dns.TypeAAAA, count: 1},
		{name: "unsupported type", config: "192.0.2.1", qtype: dns.TypeMX, count: 0},
		// The historical list form ignores malformed entries; keep that behavior.
		{name: "permissive list", config: []interface{}{"invalid", float64(1), "192.0.2.2"}, qtype: dns.TypeA, count: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr := describeAddress(t, tt.config)
			if addr.TTL != nil {
				t.Fatalf("legacy TTL = %v, want omitted", *addr.TTL)
			}
			if addr.Fallthrough {
				t.Fatal("legacy config enabled fallthrough")
			}
			resp, err := addr.Resolve(newQuery("legacy.invalid", tt.qtype), 1)
			if err != nil {
				t.Fatalf("Resolve returned error: %v", err)
			}
			if resp == nil || len(resp.Answer) != tt.count {
				t.Fatalf("answer count = %v, want %d", resp, tt.count)
			}
			for _, rr := range resp.Answer {
				if rr.Header().Ttl != defaultTTL {
					t.Fatalf("TTL = %d, want %d", rr.Header().Ttl, defaultTTL)
				}
			}
		})
	}
}

func TestAddressObjectDefaultsAndExplicitTTL(t *testing.T) {
	defaulted := describeAddress(t, map[string]interface{}{
		"addresses": []interface{}{"192.0.2.10", "2001:db8::10"},
	})
	if defaulted.TTL != nil || defaulted.Fallthrough {
		t.Fatalf("object defaults = TTL %v, fallthrough %v", defaulted.TTL, defaulted.Fallthrough)
	}
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		resp, err := defaulted.Resolve(newQuery("default.invalid", qtype), 1)
		if err != nil || len(resp.Answer) != 1 || resp.Answer[0].Header().Ttl != defaultTTL {
			t.Fatalf("default qtype %d response = %#v, err = %v", qtype, resp, err)
		}
	}

	for _, ttl := range []float64{0, math.MaxUint32} {
		addr := describeAddress(t, map[string]interface{}{
			"addresses":   "192.0.2.20",
			"ttl":         ttl,
			"fallthrough": true,
		})
		resp, err := addr.Resolve(newQuery("ttl.invalid", dns.TypeA), 1)
		if err != nil || len(resp.Answer) != 1 {
			t.Fatalf("TTL %.0f response = %#v, err = %v", ttl, resp, err)
		}
		if got := resp.Answer[0].Header().Ttl; got != uint32(ttl) {
			t.Fatalf("TTL = %d, want %.0f", got, ttl)
		}
	}
}

func TestAddressObjectRejectsInvalidFields(t *testing.T) {
	tests := []struct {
		name   string
		config map[string]interface{}
	}{
		{name: "missing addresses", config: map[string]interface{}{"ttl": float64(60)}},
		{name: "empty addresses", config: map[string]interface{}{"addresses": []interface{}{}}},
		{name: "invalid address", config: map[string]interface{}{"addresses": []interface{}{"192.0.2.1", "invalid"}}},
		{name: "address wrong type", config: map[string]interface{}{"addresses": float64(1)}},
		{name: "negative TTL", config: map[string]interface{}{"addresses": "192.0.2.1", "ttl": float64(-1)}},
		{name: "fractional TTL", config: map[string]interface{}{"addresses": "192.0.2.1", "ttl": 1.5}},
		{name: "TTL overflow", config: map[string]interface{}{"addresses": "192.0.2.1", "ttl": float64(math.MaxUint32) + 1}},
		{name: "TTL string", config: map[string]interface{}{"addresses": "192.0.2.1", "ttl": "60"}},
		{name: "fallthrough wrong type", config: map[string]interface{}{"addresses": "192.0.2.1", "fallthrough": "true"}},
	}
	d, ok := resolverpkg.GetResolverDescriptorByTypeName("address")
	if !ok {
		t.Fatal("address descriptor is not registered")
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, failure := d.Describe(tt.config)
			if failure == 0 {
				t.Fatal("invalid config was accepted")
			}
		})
	}
}

func TestAddressFallthroughByFamilyAndType(t *testing.T) {
	addr := describeAddress(t, map[string]interface{}{
		"addresses":   "192.0.2.30",
		"fallthrough": true,
	})

	if resp, err := addr.Resolve(newQuery("match.invalid", dns.TypeA), 1); err != nil || len(resp.Answer) != 1 {
		t.Fatalf("matching A response = %#v, err = %v", resp, err)
	}
	for _, qtype := range []uint16{dns.TypeAAAA, dns.TypeMX} {
		if resp, err := addr.Resolve(newQuery("miss.invalid", qtype), 1); resp != nil || !errors.Is(err, resolverpkg.ErrNotSupportedQuestion) {
			t.Fatalf("qtype %d response = %#v, err = %v", qtype, resp, err)
		}
	}

	legacy := describeAddress(t, "192.0.2.30")
	for _, qtype := range []uint16{dns.TypeAAAA, dns.TypeMX} {
		if resp, err := legacy.Resolve(newQuery("legacy.invalid", qtype), 1); err != nil || resp == nil || len(resp.Answer) != 0 {
			t.Fatalf("legacy qtype %d response = %#v, err = %v", qtype, resp, err)
		}
	}
}

type fallbackResolver struct {
	calls int
}

func (*fallbackResolver) Type() descriptor.Type { return descriptor.TypeOfNew(new(*fallbackResolver)) }
func (*fallbackResolver) TypeName() string      { return "address-test-fallback" }
func (r *fallbackResolver) Resolve(query *dns.Msg, depth int) (*dns.Msg, error) {
	r.calls++
	resp := new(dns.Msg)
	resp.SetReply(query)
	resp.Answer = append(resp.Answer, &dns.TXT{
		Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 1},
		Txt: []string{"fallback"},
	})
	return resp, nil
}

func TestAddressFallthroughUsesSequence(t *testing.T) {
	newSequence := func(address string, allowFallthrough bool) (*sequence.Sequence, *fallbackResolver) {
		addr := describeAddress(t, map[string]interface{}{
			"addresses":   address,
			"fallthrough": allowFallthrough,
		})
		fallback := new(fallbackResolver)
		seq := sequence.Sequence([]resolverpkg.Resolver{addr, fallback})
		return &seq, fallback
	}

	misses := []struct {
		name    string
		address string
		qtype   uint16
	}{
		{name: "missing IPv6 family", address: "192.0.2.40", qtype: dns.TypeAAAA},
		{name: "missing IPv4 family", address: "2001:db8::40", qtype: dns.TypeA},
		{name: "unsupported type", address: "192.0.2.40", qtype: dns.TypeMX},
	}
	for _, tt := range misses {
		seq, fallback := newSequence(tt.address, true)
		resp, err := seq.Resolve(newQuery("sequence.invalid", tt.qtype), 2)
		if err != nil || len(resp.Answer) != 1 || fallback.calls != 1 {
			t.Fatalf("%s response = %#v, calls = %d, err = %v", tt.name, resp, fallback.calls, err)
		}
	}

	seq, fallback := newSequence("192.0.2.40", true)
	resp, err := seq.Resolve(newQuery("sequence.invalid", dns.TypeA), 2)
	if err != nil || len(resp.Answer) != 1 || fallback.calls != 0 {
		t.Fatalf("matching response = %#v, calls = %d, err = %v", resp, fallback.calls, err)
	}
	if _, ok := resp.Answer[0].(*dns.A); !ok {
		t.Fatalf("matching answer type = %T, want *dns.A", resp.Answer[0])
	}

	for _, tt := range misses {
		seq, fallback = newSequence(tt.address, false)
		resp, err = seq.Resolve(newQuery("sequence.invalid", tt.qtype), 2)
		if err != nil || len(resp.Answer) != 0 || fallback.calls != 0 {
			t.Fatalf("nonfallthrough %s response = %#v, calls = %d, err = %v", tt.name, resp, fallback.calls, err)
		}
	}
}

func TestAddressResolveDepthLimit(t *testing.T) {
	addr := makeAddress()
	if _, err := addr.Resolve(newQuery("example.com", dns.TypeA), -1); !errors.Is(err, resolverpkg.ErrLoopDetected) {
		t.Fatalf("expected ErrLoopDetected, got %v", err)
	}
}

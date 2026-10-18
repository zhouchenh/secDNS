package config

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
	_ "github.com/zhouchenh/secDNS/internal/features"
)

// TestSyntheticMatcherComposition proves only that the existing exact-before-suffix
// rule order can express a bounded suffix policy with two exact exceptions. It uses
// reserved synthetic names and does not assert compatibility with any external DNS
// implementation or regexp engine.
func TestSyntheticMatcherComposition(t *testing.T) {
	const raw = `{
  "listeners": [
    {"type": "dnsServer", "config": {"listen": "127.0.0.1", "port": 5353, "protocol": "udp"}}
  ],
  "resolvers": {
    "address": {
      "default-policy": ["198.51.100.53", "2001:db8::53"],
      "excluded-child": "203.0.113.2",
      "suffix-address": {
        "addresses": "192.0.2.77",
        "ttl": 86400,
        "fallthrough": true
      }
    },
    "notExist": {
      "suffix-fallback": {}
    },
    "sequence": {
      "suffix-policy": ["suffix-address", "suffix-fallback"]
    }
  },
  "rules": [
    {
      "type": "collection",
      "config": [
        {"name": "\"xy.policy.invalid.\"", "resolver": "excluded-child"},
        {"name": "\"policy.invalid.\"", "resolver": "default-policy"},
        {"name": "policy.invalid.", "resolver": "suffix-policy"}
      ]
    }
  ],
  "defaultResolver": "default-policy",
  "resolutionDepth": 42
}`
	instance, err := LoadConfig(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("LoadConfig returned error: %v", err)
	}
	configured, ok := instance.GetResolver()
	if !ok {
		t.Fatal("configured resolver is missing")
	}

	tests := []struct {
		name       string
		qname      string
		qtype      uint16
		wantRcode  int
		wantType   uint16
		wantIP     string
		wantTTL    uint32
		wantAnswer bool
	}{
		{name: "ordinary descendant uses suffix policy", qname: "host.policy.invalid.", qtype: dns.TypeA, wantRcode: dns.RcodeSuccess, wantType: dns.TypeA, wantIP: "192.0.2.77", wantTTL: 86400, wantAnswer: true},
		{name: "one character child uses suffix policy", qname: "x.policy.invalid.", qtype: dns.TypeA, wantRcode: dns.RcodeSuccess, wantType: dns.TypeA, wantIP: "192.0.2.77", wantTTL: 86400, wantAnswer: true},
		{name: "neighbor differing first character uses suffix policy", qname: "zy.policy.invalid.", qtype: dns.TypeA, wantRcode: dns.RcodeSuccess, wantType: dns.TypeA, wantIP: "192.0.2.77", wantTTL: 86400, wantAnswer: true},
		{name: "neighbor differing second character uses suffix policy", qname: "xz.policy.invalid.", qtype: dns.TypeA, wantRcode: dns.RcodeSuccess, wantType: dns.TypeA, wantIP: "192.0.2.77", wantTTL: 86400, wantAnswer: true},
		{name: "three character child uses suffix policy", qname: "xyz.policy.invalid.", qtype: dns.TypeA, wantRcode: dns.RcodeSuccess, wantType: dns.TypeA, wantIP: "192.0.2.77", wantTTL: 86400, wantAnswer: true},
		{name: "mixed case descendant is canonicalized", qname: "HOST.POLICY.INVALID.", qtype: dns.TypeA, wantRcode: dns.RcodeSuccess, wantType: dns.TypeA, wantIP: "192.0.2.77", wantTTL: 86400, wantAnswer: true},
		{name: "deeper name below excluded child uses suffix policy", qname: "deep.xy.policy.invalid.", qtype: dns.TypeA, wantRcode: dns.RcodeSuccess, wantType: dns.TypeA, wantIP: "192.0.2.77", wantTTL: 86400, wantAnswer: true},
		{name: "exact child is excluded", qname: "xy.policy.invalid.", qtype: dns.TypeA, wantRcode: dns.RcodeSuccess, wantType: dns.TypeA, wantIP: "203.0.113.2", wantTTL: 60, wantAnswer: true},
		{name: "suffix apex is excluded", qname: "policy.invalid.", qtype: dns.TypeA, wantRcode: dns.RcodeSuccess, wantType: dns.TypeA, wantIP: "198.51.100.53", wantTTL: 60, wantAnswer: true},
		{name: "suffix apex retains default IPv6", qname: "policy.invalid.", qtype: dns.TypeAAAA, wantRcode: dns.RcodeSuccess, wantType: dns.TypeAAAA, wantIP: "2001:db8::53", wantTTL: 60, wantAnswer: true},
		{name: "outside name uses default", qname: "outside.invalid.", qtype: dns.TypeA, wantRcode: dns.RcodeSuccess, wantType: dns.TypeA, wantIP: "198.51.100.53", wantTTL: 60, wantAnswer: true},
		{name: "missing family falls through sequence", qname: "host.policy.invalid.", qtype: dns.TypeAAAA, wantRcode: dns.RcodeNameError},
		{name: "unsupported type falls through sequence", qname: "host.policy.invalid.", qtype: dns.TypeTXT, wantRcode: dns.RcodeNameError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			query := new(dns.Msg)
			query.SetQuestion(tt.qname, tt.qtype)
			response, err := configured.Resolve(query, 42)
			if err != nil {
				t.Fatalf("Resolve returned error: %v", err)
			}
			if response == nil || response.Rcode != tt.wantRcode {
				t.Fatalf("response = %#v, want rcode %d", response, tt.wantRcode)
			}
			if !tt.wantAnswer {
				if len(response.Answer) != 0 {
					t.Fatalf("answers = %v, want none", response.Answer)
				}
				return
			}
			if len(response.Answer) != 1 {
				t.Fatalf("answer count = %d, want 1", len(response.Answer))
			}
			header := response.Answer[0].Header()
			if header.Rrtype != tt.wantType || header.Ttl != tt.wantTTL {
				t.Fatalf("answer header = type %d TTL %d, want type %d TTL %d", header.Rrtype, header.Ttl, tt.wantType, tt.wantTTL)
			}
			var gotIP string
			switch answer := response.Answer[0].(type) {
			case *dns.A:
				gotIP = answer.A.String()
			case *dns.AAAA:
				gotIP = answer.AAAA.String()
			default:
				t.Fatalf("answer type = %T", response.Answer[0])
			}
			if gotIP != tt.wantIP {
				t.Fatalf("answer IP = %s, want %s", gotIP, tt.wantIP)
			}
		})
	}
}

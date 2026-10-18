package config

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
	_ "github.com/zhouchenh/secDNS/internal/features"
)

func TestAddressObjectSequenceFromConfig(t *testing.T) {
	const raw = `{
  "listeners": [
    {"type": "dnsServer", "config": {"listen": "127.0.0.1", "port": 5353, "protocol": "udp"}}
  ],
  "resolvers": {
    "address": {
      "fallback6": "2001:db8::53"
    }
  },
  "rules": [],
  "defaultResolver": {
    "type": "sequence",
    "config": [
      {
        "type": "address",
        "config": {
          "addresses": "192.0.2.53",
          "ttl": 0,
          "fallthrough": true
        }
      },
      "fallback6"
    ]
  },
  "resolutionDepth": 42
}`
	instance, err := LoadConfig(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("LoadConfig returned error: %v", err)
	}
	configured, ok := instance.GetResolver()
	if !ok {
		t.Fatal("default resolver is missing")
	}

	query := func(qtype uint16) *dns.Msg {
		msg := new(dns.Msg)
		msg.SetQuestion("config.invalid.", qtype)
		return msg
	}
	a, err := configured.Resolve(query(dns.TypeA), 4)
	if err != nil || len(a.Answer) != 1 || a.Answer[0].Header().Rrtype != dns.TypeA || a.Answer[0].Header().Ttl != 0 {
		t.Fatalf("A response = %#v, err = %v", a, err)
	}
	aaaa, err := configured.Resolve(query(dns.TypeAAAA), 4)
	if err != nil || len(aaaa.Answer) != 1 || aaaa.Answer[0].Header().Rrtype != dns.TypeAAAA || aaaa.Answer[0].Header().Ttl != defaultAddressTTLForTest {
		t.Fatalf("AAAA response = %#v, err = %v", aaaa, err)
	}
}

const defaultAddressTTLForTest uint32 = 60

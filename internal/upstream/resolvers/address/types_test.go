package address

import (
	"errors"
	"github.com/miekg/dns"
	resolverpkg "github.com/zhouchenh/secDNS/pkg/upstream/resolver"
	"net"
	"testing"
)

func newQuery(name string, qtype uint16) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), qtype)
	return msg
}

func TestAddressResolveA(t *testing.T) {
	addr := makeAddress()
	addr[v4] = append(addr[v4], net.IP{1, 2, 3, 4}, net.IP{5, 6, 7, 8})
	resolver := &addr

	resp, err := resolver.Resolve(newQuery("example.com", dns.TypeA), 1)
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}
	if len(resp.Answer) != 2 {
		t.Fatalf("expected 2 A answers, got %d", len(resp.Answer))
	}
	for i, rr := range resp.Answer {
		a, ok := rr.(*dns.A)
		if !ok {
			t.Fatalf("answer %d is %T, want *dns.A", i, rr)
		}
		expected := addr[v4][i].String()
		if a.A.String() != expected {
			t.Fatalf("answer %d IP = %s, want %s", i, a.A.String(), expected)
		}
	}
}

func TestAddressResolveAAAA(t *testing.T) {
	addr := makeAddress()
	addr[v6] = append(addr[v6], net.IP{0xca, 0xfe, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	resolver := &addr

	resp, err := resolver.Resolve(newQuery("ipv6.example", dns.TypeAAAA), 1)
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 AAAA answer, got %d", len(resp.Answer))
	}
	if got, want := resp.Answer[0].(*dns.AAAA).AAAA.String(), addr[v6][0].String(); got != want {
		t.Fatalf("AAAA IP = %s, want %s", got, want)
	}
}

func TestAddressResolveDepthLimit(t *testing.T) {
	addr := makeAddress()
	res := &addr
	if _, err := res.Resolve(newQuery("example.com", dns.TypeA), -1); !errors.Is(err, resolverpkg.ErrLoopDetected) {
		t.Fatalf("expected ErrLoopDetected, got %v", err)
	}
}

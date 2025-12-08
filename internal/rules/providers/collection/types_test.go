package collection

import (
	"github.com/miekg/dns"
	"github.com/zhouchenh/go-descriptor"
	"github.com/zhouchenh/secDNS/internal/rules/providers/collection/rule"
	"github.com/zhouchenh/secDNS/pkg/upstream/resolver"
	"testing"
)

type stubResolver struct {
	name string
}

func (s *stubResolver) Type() descriptor.Type                   { return descriptor.TypeOfNew(new(*stubResolver)) }
func (s *stubResolver) TypeName() string                        { return "stub" }
func (s *stubResolver) Resolve(*dns.Msg, int) (*dns.Msg, error) { return nil, nil }
func (s *stubResolver) NameServerResolver()                     {}

func TestCollectionProvideSequential(t *testing.T) {
	resA := &stubResolver{name: "A"}
	resB := &stubResolver{name: "B"}
	resC := &stubResolver{name: "C"}
	c := &Collection{
		Rules: []*rule.NameResolutionRule{
			{Name: "example.com", Resolver: resA},
			{Name: "", Resolver: resB},
			{Name: "test.org", Resolver: resC},
		},
	}

	var received []string
	var resolvers []resolver.Resolver
	var errs []error

	for {
		more := c.Provide(func(name string, r resolver.Resolver) {
			received = append(received, name)
			resolvers = append(resolvers, r)
		}, func(err error) {
			errs = append(errs, err)
		})
		if !more {
			break
		}
	}

	if want, got := 2, len(received); got != want {
		t.Fatalf("expected %d domains, got %d", want, got)
	}
	if received[0] != "example.com." || received[1] != "test.org." {
		t.Fatalf("unexpected domains: %v", received)
	}
	if resolvers[0] != resA || resolvers[1] != resC {
		t.Fatalf("unexpected resolvers returned")
	}
	if len(errs) != 1 {
		t.Fatalf("expected 1 error for invalid domain, got %d", len(errs))
	}
	if _, ok := errs[0].(InvalidDomainNameError); !ok {
		t.Fatalf("expected InvalidDomainNameError, got %T", errs[0])
	}
	if c.Provide(func(string, resolver.Resolver) {}, nil) {
		t.Fatalf("expected no more entries after enumeration")
	}
}

func TestCollectionProvideNilReceiver(t *testing.T) {
	c := &Collection{}
	if c.Provide(nil, nil) {
		t.Fatalf("Provide should return false when receive is nil")
	}
	var nilCollection *Collection
	if nilCollection.Provide(func(string, resolver.Resolver) {}, nil) {
		t.Fatalf("nil collection should return false")
	}
}

func TestCollectionProvideCanonicalizesNames(t *testing.T) {
	res := &stubResolver{name: "A"}
	c := &Collection{
		Rules: []*rule.NameResolutionRule{
			{Name: "ExAmPle.CoM", Resolver: res},
		},
	}

	var received []string
	for c.Provide(func(name string, r resolver.Resolver) {
		received = append(received, name)
		if r != res {
			t.Fatalf("unexpected resolver returned")
		}
	}, nil) {
	}

	if len(received) != 1 {
		t.Fatalf("expected one entry, got %d", len(received))
	}
	if received[0] != "example.com." {
		t.Fatalf("expected canonical fqdn, got %q", received[0])
	}
}

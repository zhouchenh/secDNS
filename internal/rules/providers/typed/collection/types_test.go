package collection

import (
	"github.com/miekg/dns"
	"github.com/zhouchenh/go-descriptor"
	"github.com/zhouchenh/secDNS/internal/rules/providers/collection/rule"
	"github.com/zhouchenh/secDNS/pkg/upstream/resolver"
	"testing"
)

type stubResolver struct{}

func (s *stubResolver) Type() descriptor.Type { return descriptor.TypeOfNew(new(*stubResolver)) }
func (s *stubResolver) TypeName() string      { return "stub" }
func (s *stubResolver) Resolve(*dns.Msg, int) (*dns.Msg, error) {
	return nil, nil
}
func (s *stubResolver) NameServerResolver() {}

func newRule(name string, res resolver.Resolver) *rule.NameResolutionRule {
	return &rule.NameResolutionRule{Name: name, Resolver: res}
}

func TestTypedCollectionBehavesLikeCollection(t *testing.T) {
	rules := []*rule.NameResolutionRule{
		newRule("example.com", &stubResolver{}),
		newRule("test.org", &stubResolver{}),
	}
	typed := &TypedCollection{}
	typed.Rules = rules

	var names []string
	for more := true; more; {
		more = typed.Provide(func(name string, r resolver.Resolver) {
			names = append(names, name)
		}, func(err error) {
			t.Fatalf("unexpected error: %v", err)
		})
	}
	if len(names) != 2 || names[0] != "example.com." || names[1] != "test.org." {
		t.Fatalf("collection did not emit expected domains: %v", names)
	}
}

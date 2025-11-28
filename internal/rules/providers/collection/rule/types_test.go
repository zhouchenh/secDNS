package rule

import (
	"github.com/miekg/dns"
	"github.com/zhouchenh/go-descriptor"
	resolverpkg "github.com/zhouchenh/secDNS/pkg/upstream/resolver"
	"testing"
)

type stubResolver struct{}

func (s *stubResolver) Type() descriptor.Type                   { return descriptor.TypeOfNew(new(*stubResolver)) }
func (s *stubResolver) TypeName() string                        { return "stub" }
func (s *stubResolver) Resolve(*dns.Msg, int) (*dns.Msg, error) { return nil, nil }
func (s *stubResolver) NameServerResolver()                     {}

func init() {
	resolverpkg.RegisterAssignmentFunctionByType(descriptor.TypeOfNew(new(*stubResolver)), func(i interface{}) (interface{}, bool) {
		sr, ok := i.(*stubResolver)
		return sr, ok
	})
}

func TestNameResolutionRuleDescriptor(t *testing.T) {
	stub := &stubResolver{}
	obj := map[string]interface{}{
		"name":     "example.com",
		"resolver": stub,
	}
	raw, s, f := NameResolutionRuleDescriptor().Describe(obj)
	if s < 1 || f > 0 {
		t.Fatalf("descriptor describe failed: s=%d f=%d", s, f)
	}
	rule, ok := raw.(*NameResolutionRule)
	if !ok {
		t.Fatalf("expected *NameResolutionRule, got %T", raw)
	}
	if rule.Name != "example.com" {
		t.Fatalf("unexpected name %s", rule.Name)
	}
	if rule.Resolver != stub {
		t.Fatalf("resolver mismatch")
	}
}

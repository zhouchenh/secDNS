package core

import (
	"github.com/miekg/dns"
	"github.com/zhouchenh/go-descriptor"
	"github.com/zhouchenh/secDNS/pkg/upstream/resolver"
	"testing"
)

type stubResolver struct{}

func (stubResolver) Type() descriptor.Type { return nil }
func (stubResolver) TypeName() string      { return "stub" }
func (stubResolver) Resolve(_ *dns.Msg, _ int) (*dns.Msg, error) {
	return nil, nil
}

type stubProvider struct {
	names []string
	idx   int
	res   resolver.Resolver
}

func (s *stubProvider) Type() descriptor.Type { return nil }
func (s *stubProvider) TypeName() string      { return "stub" }
func (s *stubProvider) Provide(receive func(name string, r resolver.Resolver), _ func(err error)) (more bool) {
	if s.idx >= len(s.names) {
		return false
	}
	receive(s.names[s.idx], s.res)
	s.idx++
	return s.idx < len(s.names)
}

func TestAcceptProviderDuplicateWarning(t *testing.T) {
	inst := &instance{}
	inst.initInstance()
	res := stubResolver{}
	prov := &stubProvider{
		names: []string{"example.com.", "example.com."},
		res:   res,
	}

	var warnings []error
	inst.AcceptProvider(prov, func(err error) {
		warnings = append(warnings, err)
	})

	if len(warnings) != 1 {
		t.Fatalf("expected 1 duplicate warning, got %d", len(warnings))
	}
	if _, ok := warnings[0].(DuplicateRuleWarning); !ok {
		t.Fatalf("expected DuplicateRuleWarning, got %v", warnings[0])
	}
}

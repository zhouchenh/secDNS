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

type recordingResolver struct {
	name   string
	called bool
}

func (r *recordingResolver) Type() descriptor.Type { return nil }
func (r *recordingResolver) TypeName() string      { return r.name }
func (r *recordingResolver) Resolve(_ *dns.Msg, _ int) (*dns.Msg, error) {
	r.called = true
	return new(dns.Msg), nil
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

func TestAcceptProviderDeduplicatesSilently(t *testing.T) {
	inst := &instance{}
	inst.initInstance()
	first := stubResolver{}
	second := stubResolver{}

	firstProvider := &stubProvider{
		names: []string{"example.com."},
		res:   first,
	}
	secondProvider := &stubProvider{
		names: []string{"example.com."},
		res:   second,
	}

	var receivedErrors []error
	inst.AcceptProvider(firstProvider, func(err error) {
		receivedErrors = append(receivedErrors, err)
	})
	inst.AcceptProvider(secondProvider, func(err error) {
		receivedErrors = append(receivedErrors, err)
	})

	if len(receivedErrors) != 0 {
		t.Fatalf("expected no duplicate warnings, got %d", len(receivedErrors))
	}

	inst.mapMutex.RLock()
	defer inst.mapMutex.RUnlock()

	if got := len(inst.nameResolverMap); got != 1 {
		t.Fatalf("expected 1 resolver in map, got %d", got)
	}
	if got := inst.nameResolverMap["example.com."]; got != first {
		t.Fatalf("expected first resolver to be kept, got %#v", got)
	}
}

func TestResolveUsesCaseInsensitiveMatch(t *testing.T) {
	inst := &instance{}
	inst.initInstance()

	ruleResolver := &recordingResolver{name: "rule"}
	defaultResolver := &recordingResolver{name: "default"}

	provider := &stubProvider{
		names: []string{"ExAmPlE.CoM"},
		res:   ruleResolver,
	}
	inst.AcceptProvider(provider, nil)
	inst.SetDefaultResolver(defaultResolver)

	query := new(dns.Msg)
	query.SetQuestion("WWW.EXAMPLE.COM.", dns.TypeA)

	if _, err := inst.Resolve(query, 4); err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if !ruleResolver.called {
		t.Fatalf("expected rule resolver to be called for mixed-case query")
	}
	if defaultResolver.called {
		t.Fatalf("default resolver should not be called when rule matches")
	}
}

func TestResolveUsesLiteralCaseInsensitiveMatch(t *testing.T) {
	inst := &instance{}
	inst.initInstance()

	literalResolver := &recordingResolver{name: "literal"}
	defaultResolver := &recordingResolver{name: "default"}

	provider := &stubProvider{
		names: []string{"\"Example.Com\""},
		res:   literalResolver,
	}
	inst.AcceptProvider(provider, nil)
	inst.SetDefaultResolver(defaultResolver)

	query := new(dns.Msg)
	query.SetQuestion("EXAMPLE.COM.", dns.TypeA)

	if _, err := inst.Resolve(query, 4); err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if !literalResolver.called {
		t.Fatalf("expected literal resolver to be called for exact case-insensitive match")
	}
	if defaultResolver.called {
		t.Fatalf("default resolver should not be called for literal match")
	}

	// Subdomain should not match literal rule
	literalResolver.called = false
	defaultResolver.called = false
	subQuery := new(dns.Msg)
	subQuery.SetQuestion("sub.EXAMPLE.COM.", dns.TypeA)

	if _, err := inst.Resolve(subQuery, 4); err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if literalResolver.called {
		t.Fatalf("literal resolver should not match subdomain queries")
	}
	if !defaultResolver.called {
		t.Fatalf("default resolver should handle unmatched subdomain")
	}
}

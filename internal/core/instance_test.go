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

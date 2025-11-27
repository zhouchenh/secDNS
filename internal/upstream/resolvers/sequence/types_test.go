package sequence

import (
	"errors"
	"github.com/miekg/dns"
	"github.com/zhouchenh/go-descriptor"
	resolverpkg "github.com/zhouchenh/secDNS/pkg/upstream/resolver"
	"net"
	"testing"
)

type stubResolver struct {
	response *dns.Msg
	err      error
	calls    int
}

func (s *stubResolver) Type() descriptor.Type { return descriptor.TypeOfNew(new(*stubResolver)) }
func (s *stubResolver) TypeName() string      { return "stub" }
func (s *stubResolver) Resolve(query *dns.Msg, depth int) (*dns.Msg, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	if s.response != nil {
		return s.response.Copy(), nil
	}
	return nil, nil
}
func (s *stubResolver) NameServerResolver() {}

func TestSequenceResolveNoResolvers(t *testing.T) {
	var seq Sequence
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)

	if _, err := seq.Resolve(msg, 5); !errors.Is(err, ErrNoAvailableResolver) {
		t.Fatalf("expected ErrNoAvailableResolver, got %v", err)
	}
}

func TestSequenceResolveNilResolvers(t *testing.T) {
	resp := new(dns.Msg)
	resp.SetQuestion("example.com.", dns.TypeA)
	resp.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{
			Name:   "example.com.",
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    60,
		},
		A: net.IP{1, 2, 3, 4},
	}}
	r1 := &stubResolver{response: resp}
	var seq Sequence = []resolverpkg.Resolver{nil, r1}
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)

	resp, err := seq.Resolve(msg, 5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatalf("expected non-nil response")
	}
	if r1.calls != 1 {
		t.Fatalf("expected downstream resolver to be invoked once, got %d", r1.calls)
	}
}

func TestSequenceResolveFallsBackOnError(t *testing.T) {
	failure := &stubResolver{err: errors.New("boom")}
	success := &stubResolver{
		response: new(dns.Msg),
	}
	success.response.SetQuestion("example.org.", dns.TypeAAAA)

	var seq Sequence = []resolverpkg.Resolver{failure, success}
	msg := new(dns.Msg)
	msg.SetQuestion("example.org.", dns.TypeAAAA)

	resp, err := seq.Resolve(msg, 5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || resp.Question[0].Name != "example.org." {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if failure.calls != 1 || success.calls != 1 {
		t.Fatalf("expected both resolvers to be tried once, got failure=%d success=%d", failure.calls, success.calls)
	}
}

func TestSequenceResolveDepthLimit(t *testing.T) {
	res := &stubResolver{}
	var seq Sequence = []resolverpkg.Resolver{res}
	msg := new(dns.Msg)
	msg.SetQuestion("depth.example.", dns.TypeA)

	if _, err := seq.Resolve(msg, -1); !errors.Is(err, resolverpkg.ErrLoopDetected) {
		t.Fatalf("expected ErrLoopDetected, got %v", err)
	}
	if res.calls != 0 {
		t.Fatalf("resolver should not be called when depth check fails")
	}
}

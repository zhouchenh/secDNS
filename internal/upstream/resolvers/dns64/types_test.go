package dns64

import (
	"errors"
	"github.com/miekg/dns"
	"github.com/zhouchenh/go-descriptor"
	resolverpkg "github.com/zhouchenh/secDNS/pkg/upstream/resolver"
	"net"
	"testing"
)

type fakeResolver struct {
	response *dns.Msg
	err      error
	calls    int
	lastType uint16
}

func (f *fakeResolver) Type() descriptor.Type { return descriptor.TypeOfNew(new(*fakeResolver)) }
func (f *fakeResolver) TypeName() string      { return "fake" }
func (f *fakeResolver) Resolve(query *dns.Msg, depth int) (*dns.Msg, error) {
	f.calls++
	if len(query.Question) > 0 {
		f.lastType = query.Question[0].Qtype
	}
	if f.err != nil {
		return nil, f.err
	}
	if f.response == nil {
		return nil, nil
	}
	return f.response.Copy(), nil
}
func (f *fakeResolver) NameServerResolver() {}

func newAAAAResponse(name string, rrs ...dns.RR) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(name, dns.TypeAAAA)
	msg.Response = true
	msg.Rcode = dns.RcodeSuccess
	msg.Answer = append([]dns.RR{}, rrs...)
	return msg
}

func newAResponse(name string, rrs ...dns.RR) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(name, dns.TypeA)
	msg.Response = true
	msg.Rcode = dns.RcodeSuccess
	msg.Answer = append([]dns.RR{}, rrs...)
	return msg
}

func TestDNS64ReturnsExistingAAAA(t *testing.T) {
	answer := &dns.AAAA{
		Hdr: dns.RR_Header{
			Name:   "example.com.",
			Rrtype: dns.TypeAAAA,
			Class:  dns.ClassINET,
			Ttl:    60,
		},
		AAAA: net.ParseIP("2001:db8::1"),
	}
	upstream := &fakeResolver{
		response: newAAAAResponse("example.com.", answer),
	}
	res := &DNS64{
		Resolver: upstream,
		Prefix:   net.ParseIP("64:ff9b::"),
	}

	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeAAAA)
	resp, err := res.Resolve(query, 4)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if upstream.calls != 1 || upstream.lastType != dns.TypeAAAA {
		t.Fatalf("expected single AAAA upstream call, got calls=%d type=%d", upstream.calls, upstream.lastType)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected one answer, got %d", len(resp.Answer))
	}
	if _, ok := resp.Answer[0].(*dns.AAAA); !ok {
		t.Fatalf("expected AAAA response, got %T", resp.Answer[0])
	}
}

func TestDNS64SynthesizesFromA(t *testing.T) {
	answer := &dns.A{
		Hdr: dns.RR_Header{
			Name:   "ipv4.example.",
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    123,
		},
		A: net.IP{93, 184, 216, 34},
	}
	upstream := &fakeResolver{
		response: newAResponse("ipv4.example.", answer),
	}
	res := &DNS64{
		Resolver: upstream,
		Prefix:   net.ParseIP("64:ff9b::"),
	}

	query := new(dns.Msg)
	query.SetQuestion("ipv4.example.", dns.TypeAAAA)
	resp, err := res.Resolve(query, 4)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if upstream.lastType != dns.TypeA {
		t.Fatalf("expected fallback query type A, got %d", upstream.lastType)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected one synthesized answer, got %d", len(resp.Answer))
	}
	aaaa, ok := resp.Answer[0].(*dns.AAAA)
	if !ok {
		t.Fatalf("expected AAAA, got %T", resp.Answer[0])
	}
	if aaaa.Hdr.Ttl != 123 {
		t.Fatalf("expected TTL preserved, got %d", aaaa.Hdr.Ttl)
	}
	if got, want := aaaa.AAAA.String(), "64:ff9b::5db8:d822"; got != want {
		t.Fatalf("unexpected synthesized IPv6 %s", got)
	}
}

func TestDNS64IgnoreExistingAAAAForcesSynthesis(t *testing.T) {
	answer := &dns.A{
		Hdr: dns.RR_Header{
			Name:   "force.example.",
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    30,
		},
		A: net.IP{10, 0, 0, 1},
	}
	upstream := &fakeResolver{
		response: newAResponse("force.example.", answer),
	}
	res := &DNS64{
		Resolver:           upstream,
		Prefix:             net.ParseIP("64:ff9b::"),
		IgnoreExistingAAAA: true,
	}

	query := new(dns.Msg)
	query.SetQuestion("force.example.", dns.TypeAAAA)
	resp, err := res.Resolve(query, 4)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if upstream.calls != 1 || upstream.lastType != dns.TypeA {
		t.Fatalf("expected resolver to be called for A records, got calls=%d type=%d", upstream.calls, upstream.lastType)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected synthesized AAAA answer, got %d", len(resp.Answer))
	}
	if _, ok := resp.Answer[0].(*dns.AAAA); !ok {
		t.Fatalf("expected synthesized AAAA answers, got %T", resp.Answer[0])
	}
}

func TestDNS64DepthLimit(t *testing.T) {
	res := &DNS64{
		Resolver: &fakeResolver{},
		Prefix:   net.ParseIP("64:ff9b::"),
	}

	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeAAAA)
	if _, err := res.Resolve(query, -1); !errors.Is(err, resolverpkg.ErrLoopDetected) {
		t.Fatalf("expected ErrLoopDetected, got %v", err)
	}
}

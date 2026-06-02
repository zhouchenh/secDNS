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

func TestDNS64DoesNotSynthesizeOnServfail(t *testing.T) {
	servfail := new(dns.Msg)
	servfail.SetQuestion("svc.example.", dns.TypeAAAA)
	servfail.Response = true
	servfail.Rcode = dns.RcodeServerFailure
	upstream := &fakeResolver{response: servfail}
	res := &DNS64{Resolver: upstream, Prefix: net.ParseIP("64:ff9b::")}

	query := new(dns.Msg)
	query.SetQuestion("svc.example.", dns.TypeAAAA)
	resp, err := res.Resolve(query, 4)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if resp == nil || resp.Rcode != dns.RcodeServerFailure {
		t.Fatalf("expected SERVFAIL to pass through unchanged, got %v", resp)
	}
	if upstream.calls != 1 {
		t.Fatalf("expected no A fallback on SERVFAIL, got %d upstream calls", upstream.calls)
	}
}

func TestDNS64DoesNotMutateCallerQuery(t *testing.T) {
	a := &dns.A{
		Hdr: dns.RR_Header{Name: "x.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   net.IP{192, 0, 2, 1},
	}
	upstream := &fakeResolver{response: newAResponse("x.example.", a)}
	res := &DNS64{Resolver: upstream, Prefix: net.ParseIP("64:ff9b::")}

	query := new(dns.Msg)
	query.SetQuestion("x.example.", dns.TypeAAAA)
	if _, err := res.Resolve(query, 4); err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if query.Question[0].Qtype != dns.TypeAAAA {
		t.Fatalf("caller query qtype was mutated to %d", query.Question[0].Qtype)
	}
}

func TestDNS64EmptyQuestionReturnsError(t *testing.T) {
	res := &DNS64{Resolver: &fakeResolver{}, Prefix: net.ParseIP("64:ff9b::")}
	query := new(dns.Msg) // no question section
	if _, err := res.Resolve(query, 4); err == nil {
		t.Fatalf("expected an error for a query with no question, got nil")
	}
}

func TestDNS64SynthesisStripsSignaturesAndAD(t *testing.T) {
	a := &dns.A{
		Hdr: dns.RR_Header{Name: "svc.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   net.IP{192, 0, 2, 9},
	}
	sig := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: "svc.example.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 60},
		TypeCovered: dns.TypeA, Algorithm: 13, Labels: 2, OrigTtl: 60,
		Expiration:  2000000000, Inception: 1000000000, KeyTag: 12345,
		SignerName:  "example.", Signature: "aGVsbG8=",
	}
	resp := newAResponse("svc.example.", a, sig)
	resp.AuthenticatedData = true

	res := &DNS64{Resolver: &fakeResolver{response: resp}, Prefix: net.ParseIP("64:ff9b::")}
	query := new(dns.Msg)
	query.SetQuestion("svc.example.", dns.TypeAAAA)
	out, err := res.Resolve(query, 4)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if out.AuthenticatedData {
		t.Fatalf("synthesized response must not set the AD bit (RFC 6147 5.5)")
	}
	var aaaa, rrsig int
	for _, rr := range out.Answer {
		switch rr.(type) {
		case *dns.AAAA:
			aaaa++
		case *dns.RRSIG:
			rrsig++
		}
	}
	if aaaa != 1 {
		t.Fatalf("expected 1 synthesized AAAA, got %d", aaaa)
	}
	if rrsig != 0 {
		t.Fatalf("synthesized response must not retain RRSIG records, got %d", rrsig)
	}
}

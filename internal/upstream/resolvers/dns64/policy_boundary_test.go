package dns64

import (
	"github.com/miekg/dns"
	"github.com/zhouchenh/go-descriptor"
	"net"
	"testing"
)

type sharedAnswer struct {
	response *dns.Msg
	calls    int
}

func (*sharedAnswer) Type() descriptor.Type                     { return nil }
func (*sharedAnswer) TypeName() string                          { return "shared-test" }
func (s *sharedAnswer) Resolve(*dns.Msg, int) (*dns.Msg, error) { s.calls++; return s.response, nil }
func TestDNS64SharedReplyCNAMEAndTTLIsolation(t *testing.T) {
	upstream := new(dns.Msg)
	upstream.SetQuestion("alias.invalid.", dns.TypeA)
	upstream.Response = true
	upstream.AuthenticatedData = true
	upstream.Answer = []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: "alias.invalid.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300}, Target: "target.invalid."}, &dns.A{Hdr: dns.RR_Header{Name: "target.invalid.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 700}, A: net.ParseIP("192.0.2.10").To4()}}
	before := upstream.String()
	shared := &sharedAnswer{response: upstream}
	r := &DNS64{Resolver: shared, Prefix: net.ParseIP("64:ff9b::"), IgnoreExistingAAAA: true}
	q := new(dns.Msg)
	q.SetQuestion("alias.invalid.", dns.TypeAAAA)
	answer, err := r.Resolve(q, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(answer.Answer) != 2 || answer.Answer[0].Header().Ttl != 300 || answer.Answer[1].Header().Ttl != 700 || answer.AuthenticatedData {
		t.Fatal(answer)
	}
	if _, ok := answer.Answer[1].(*dns.AAAA); !ok {
		t.Fatal(answer)
	}
	answer.Answer[0].(*dns.CNAME).Target = "changed.invalid."
	if upstream.String() != before || q.Question[0].Qtype != dns.TypeAAAA {
		t.Fatal("shared reply or query mutated")
	}
}
func TestDNS64NXDomainDoesNotRequestA(t *testing.T) {
	q := new(dns.Msg)
	q.SetQuestion("missing.invalid.", dns.TypeAAAA)
	shared := &sharedAnswer{response: new(dns.Msg).SetRcode(q, dns.RcodeNameError)}
	r := &DNS64{Resolver: shared, Prefix: net.ParseIP("64:ff9b::")}
	answer, err := r.Resolve(q, 5)
	if err != nil || answer.Rcode != dns.RcodeNameError || shared.calls != 1 {
		t.Fatal(answer, err, shared.calls)
	}
}

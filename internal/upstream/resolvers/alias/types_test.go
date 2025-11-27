package alias

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
	lastName string
	lastType uint16
	calls    int
}

func (s *stubResolver) Type() descriptor.Type { return descriptor.TypeOfNew(new(*stubResolver)) }
func (s *stubResolver) TypeName() string      { return "stub" }
func (s *stubResolver) Resolve(query *dns.Msg, depth int) (*dns.Msg, error) {
	s.calls++
	if len(query.Question) > 0 {
		s.lastName = query.Question[0].Name
		s.lastType = query.Question[0].Qtype
	}
	if s.err != nil {
		return nil, s.err
	}
	if s.response != nil {
		return s.response.Copy(), nil
	}
	return nil, nil
}
func (s *stubResolver) NameServerResolver() {}

func newAliasResolver(target string, upstream resolverpkg.Resolver) *Alias {
	return &Alias{
		Alias:    target,
		Resolver: upstream,
	}
}

func TestAliasDepthLimit(t *testing.T) {
	res := newAliasResolver("alias.example.", &stubResolver{})
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	if _, err := res.Resolve(query, -1); !errors.Is(err, resolverpkg.ErrLoopDetected) {
		t.Fatalf("expected ErrLoopDetected, got %v", err)
	}
}

func TestAliasRejectsSelfReference(t *testing.T) {
	res := newAliasResolver("example.com.", &stubResolver{})
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	if _, err := res.Resolve(query, 5); !errors.Is(err, ErrAliasSameAsName) {
		t.Fatalf("expected ErrAliasSameAsName, got %v", err)
	}
}

func TestAliasReturnsCNAMEOnlyForCNAMEQuery(t *testing.T) {
	upstream := &stubResolver{}
	res := newAliasResolver("target.example.", upstream)
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeCNAME)

	resp, err := res.Resolve(query, 5)
	if err != nil {
		t.Fatalf("Resolve error = %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected single CNAME answer, got %d", len(resp.Answer))
	}
	if _, ok := resp.Answer[0].(*dns.CNAME); !ok {
		t.Fatalf("expected CNAME answer, got %T", resp.Answer[0])
	}
	if upstream.calls != 0 {
		t.Fatalf("upstream should not be called for pure CNAME queries")
	}
}

func TestAliasResolvesTargetForAQuery(t *testing.T) {
	answer := &dns.A{
		Hdr: dns.RR_Header{
			Name:   "target.example.",
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    120,
		},
		A: net.IP{192, 0, 2, 1},
	}
	upstream := &stubResolver{
		response: func() *dns.Msg {
			msg := new(dns.Msg)
			msg.SetQuestion("target.example.", dns.TypeA)
			msg.Answer = []dns.RR{answer}
			return msg
		}(),
	}
	res := newAliasResolver("target.example.", upstream)

	query := new(dns.Msg)
	query.SetQuestion("app.example.", dns.TypeA)
	resp, err := res.Resolve(query, 5)
	if err != nil {
		t.Fatalf("Resolve error = %v", err)
	}
	if upstream.calls != 1 || upstream.lastName != "target.example." || upstream.lastType != dns.TypeA {
		t.Fatalf("upstream Resolve not called with alias target")
	}
	if len(resp.Answer) != 2 {
		t.Fatalf("expected CNAME + A answers, got %d", len(resp.Answer))
	}
	if _, ok := resp.Answer[0].(*dns.CNAME); !ok {
		t.Fatalf("first answer should be CNAME, got %T", resp.Answer[0])
	}
	if got := resp.Answer[1].(*dns.A).A.String(); got != answer.A.String() {
		t.Fatalf("unexpected synthesized A record: %s", got)
	}
}

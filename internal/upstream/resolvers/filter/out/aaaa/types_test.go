package aaaa

import (
	"github.com/miekg/dns"
	"github.com/zhouchenh/go-descriptor"
	"testing"
)

type stubResolver struct {
	response *dns.Msg
	err      error
	lastType uint16
}

func (s *stubResolver) Type() descriptor.Type { return descriptor.TypeOfNew(new(*stubResolver)) }
func (s *stubResolver) TypeName() string      { return "stub" }
func (s *stubResolver) Resolve(query *dns.Msg, depth int) (*dns.Msg, error) {
	if len(query.Question) > 0 {
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

func makeResponse(name string, answers ...dns.RR) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(name, dns.TypeAAAA)
	msg.Response = true
	msg.Rcode = dns.RcodeSuccess
	msg.Answer = append([]dns.RR{}, answers...)
	return msg
}

func TestFilterOutAAAAImmediateEmpty(t *testing.T) {
	f := &FilterOutAAAA{}
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeAAAA)
	resp, err := f.Resolve(query, 5)
	if err != nil {
		t.Fatalf("Resolve error = %v", err)
	}
	if len(resp.Answer) != 0 {
		t.Fatalf("expected no answers for AAAA query, got %d", len(resp.Answer))
	}
}

func TestFilterOutAAAARemovesRecords(t *testing.T) {
	answers := []dns.RR{
		&dns.AAAA{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60}, AAAA: []byte{32, 1, 13, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}},
		&dns.MX{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 60}, Preference: 10, Mx: "mail.example.com."},
	}
	upstream := &stubResolver{
		response: makeResponse("example.com.", answers...),
	}
	f := &FilterOutAAAA{Resolver: upstream}

	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	resp, err := f.Resolve(query, 5)
	if err != nil {
		t.Fatalf("Resolve error = %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected only non-AAAA answers, got %d", len(resp.Answer))
	}
	if _, ok := resp.Answer[0].(*dns.MX); !ok {
		t.Fatalf("unexpected answer type %T", resp.Answer[0])
	}
}

package aaaa

import (
	"github.com/miekg/dns"
	"github.com/zhouchenh/go-descriptor"
	"testing"
)

type stubResolver struct {
	responses map[uint16]*dns.Msg
	calls     []uint16
}

func (s *stubResolver) Type() descriptor.Type { return descriptor.TypeOfNew(new(*stubResolver)) }
func (s *stubResolver) TypeName() string      { return "stub" }
func (s *stubResolver) Resolve(query *dns.Msg, depth int) (*dns.Msg, error) {
	qtype := query.Question[0].Qtype
	s.calls = append(s.calls, qtype)
	if resp, ok := s.responses[qtype]; ok && resp != nil {
		return resp.Copy(), nil
	}
	return nil, nil
}
func (s *stubResolver) NameServerResolver() {}

func newMessage(name string, qtype uint16, answers ...dns.RR) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(name, qtype)
	msg.Response = true
	msg.Rcode = dns.RcodeSuccess
	msg.Answer = append([]dns.RR{}, answers...)
	return msg
}

func TestFilterOutAAAAIfAPresentsNoA(t *testing.T) {
	upstream := &stubResolver{
		responses: map[uint16]*dns.Msg{
			dns.TypeA:    newMessage("example.com.", dns.TypeA),
			dns.TypeAAAA: newMessage("example.com.", dns.TypeAAAA, &dns.AAAA{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60}, AAAA: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}),
		},
	}
	filter := &FilterOutAAAAIfAPresents{Resolver: upstream}

	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeAAAA)
	resp, err := filter.Resolve(query, 5)
	if err != nil {
		t.Fatalf("Resolve error = %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected upstream AAAA answers when A absent, got %d", len(resp.Answer))
	}
	if upstream.calls[0] != dns.TypeA {
		t.Fatalf("expected probe A query first")
	}
}

func TestFilterOutAAAAIfAPresentsDropsAAAAWhenAExists(t *testing.T) {
	upstream := &stubResolver{
		responses: map[uint16]*dns.Msg{
			dns.TypeA:    newMessage("example.com.", dns.TypeA, &dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: []byte{1, 1, 1, 1}}),
			dns.TypeAAAA: newMessage("example.com.", dns.TypeAAAA, &dns.AAAA{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60}, AAAA: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}}),
		},
	}
	filter := &FilterOutAAAAIfAPresents{Resolver: upstream}

	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeAAAA)
	resp, err := filter.Resolve(query, 5)
	if err != nil {
		t.Fatalf("Resolve error = %v", err)
	}
	if len(resp.Answer) != 0 {
		t.Fatalf("expected AAAA answers to be dropped when A exists, got %d", len(resp.Answer))
	}
}

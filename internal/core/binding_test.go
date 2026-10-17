package core

import (
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/zhouchenh/go-descriptor"
	"github.com/zhouchenh/secDNS/internal/upstream/resolvers/address"
	"github.com/zhouchenh/secDNS/internal/upstream/resolvers/dns64"
	"github.com/zhouchenh/secDNS/pkg/listeners/server"
)

type captureListener struct {
	query  *dns.Msg
	answer chan *dns.Msg
}

func (*captureListener) Type() descriptor.Type { return nil }
func (*captureListener) TypeName() string      { return "capture" }
func (s *captureListener) Serve(handler func(*dns.Msg) *dns.Msg, _ func(error)) {
	s.answer <- handler(s.query)
}

func TestBindingUsesExistingHandlerAndNormalGraph(t *testing.T) {
	i := NewInstance()
	normal := address.Address{[]net.IP{net.ParseIP("192.0.2.10").To4()}, nil}
	i.SetDefaultResolver(&normal)
	i.SetResolutionDepth(32)
	r, _ := i.GetResolver()
	synth := &dns64.DNS64{Resolver: r, Prefix: net.ParseIP("64:ff9b::")}
	q := new(dns.Msg)
	q.SetQuestion("test.invalid.", dns.TypeAAAA)
	a := &captureListener{query: q, answer: make(chan *dns.Msg, 1)}
	b := &captureListener{query: q, answer: make(chan *dns.Msg, 1)}
	i.AddListener(a, &server.Binding{Server: b, Resolver: synth})
	errorReply := func(q *dns.Msg) *dns.Msg { return new(dns.Msg).SetRcode(q, dns.RcodeServerFailure) }
	i.Listen(errorReply, errorReply, func(e error) { t.Error(e) })
	if len((<-a.answer).Answer) != 0 {
		t.Fatal("normal listener synthesized")
	}
	reply := <-b.answer
	if len(reply.Answer) != 1 || reply.Answer[0].(*dns.AAAA).AAAA.String() != "64:ff9b::c000:20a" {
		t.Fatal("selected listener failed", reply)
	}
}

func TestBindingPreservesMalformedQueryAndDepthHandling(t *testing.T) {
	for _, malformed := range []bool{false, true} {
		i := NewInstance()
		normal := address.Address{[]net.IP{net.ParseIP("192.0.2.10").To4()}, nil}
		i.SetDefaultResolver(&normal)
		i.SetResolutionDepth(-1)
		q := new(dns.Msg)
		if !malformed {
			q.SetQuestion("depth.invalid.", dns.TypeAAAA)
		}
		listener := &captureListener{query: q, answer: make(chan *dns.Msg, 1)}
		i.AddListener(&server.Binding{Server: listener, Resolver: &dns64.DNS64{Resolver: &normal, Prefix: net.ParseIP("64:ff9b::")}})
		clientError := func(q *dns.Msg) *dns.Msg { return new(dns.Msg).SetRcode(q, dns.RcodeFormatError) }
		serverError := func(q *dns.Msg) *dns.Msg { return new(dns.Msg).SetRcode(q, dns.RcodeServerFailure) }
		i.Listen(clientError, serverError, func(error) {})
		expected := dns.RcodeServerFailure
		if malformed {
			expected = dns.RcodeFormatError
		}
		if r := <-listener.answer; r.Rcode != expected {
			t.Fatal(r)
		}
	}
}

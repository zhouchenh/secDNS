package core

import (
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/zhouchenh/go-descriptor"
	"github.com/zhouchenh/secDNS/internal/sourcepolicy"
	"github.com/zhouchenh/secDNS/internal/upstream/resolvers/address"
	"github.com/zhouchenh/secDNS/internal/upstream/resolvers/dns64"
	"github.com/zhouchenh/secDNS/pkg/listeners/server"
	"github.com/zhouchenh/secDNS/pkg/upstream/resolver"
)

type captureListener struct {
	query  *dns.Msg
	answer chan *dns.Msg
}

type capturePeerListener struct {
	query  *dns.Msg
	peer   netip.Addr
	answer chan *dns.Msg
}

func (*capturePeerListener) Type() descriptor.Type { return nil }
func (*capturePeerListener) TypeName() string      { return "capture-peer" }
func (*capturePeerListener) Serve(func(*dns.Msg) *dns.Msg, func(error)) {
	panic("peer-aware binding used legacy Serve")
}
func (s *capturePeerListener) ServePeer(handler func(*dns.Msg, netip.Addr) *dns.Msg, _ func(error)) {
	s.answer <- handler(s.query, s.peer)
}

type recordingPeerResolver struct {
	result resolver.Resolver
	err    error
	calls  int
	peer   netip.Addr
	now    time.Time
}

func (s *recordingPeerResolver) ResolverFor(peer netip.Addr, now time.Time) (resolver.Resolver, error) {
	s.calls++
	s.peer = peer
	s.now = now
	return s.result, s.err
}

func (s *recordingPeerResolver) ResolverDependencies() []resolver.Resolver {
	return []resolver.Resolver{s.result}
}

func (*captureListener) Type() descriptor.Type { return nil }
func (*captureListener) TypeName() string      { return "capture" }
func (s *captureListener) Serve(handler func(*dns.Msg) *dns.Msg, _ func(error)) {
	s.answer <- handler(s.query)
}

func TestBindingUsesExistingHandlerAndNormalGraph(t *testing.T) {
	i := NewInstance()
	normal := address.Address{Addresses: [2][]net.IP{{net.ParseIP("192.0.2.10").To4()}}}
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
		normal := address.Address{Addresses: [2][]net.IP{{net.ParseIP("192.0.2.10").To4()}}}
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

func TestPeerBindingSelectsFromSocketPeerBeforeResolution(t *testing.T) {
	i := NewInstance()
	defaultResolver := &address.Address{}
	selected := &address.Address{Addresses: [2][]net.IP{{net.ParseIP("192.0.2.22").To4()}}}
	i.SetDefaultResolver(defaultResolver)
	i.SetResolutionDepth(16)
	query := new(dns.Msg)
	query.SetQuestion("peer.invalid.", dns.TypeA)
	listener := &capturePeerListener{
		query: query, peer: netip.MustParseAddr("::ffff:127.0.0.2"), answer: make(chan *dns.Msg, 1),
	}
	selection := &recordingPeerResolver{result: selected}
	i.AddListener(&server.Binding{Server: listener, PeerResolver: selection})
	errorReply := func(q *dns.Msg) *dns.Msg { return new(dns.Msg).SetRcode(q, dns.RcodeServerFailure) }
	i.Listen(errorReply, errorReply, func(err error) { t.Error(err) })
	reply := <-listener.answer
	if len(reply.Answer) != 1 || reply.Answer[0].(*dns.A).A.String() != "192.0.2.22" {
		t.Fatal(reply)
	}
	if selection.calls != 1 || selection.peer != netip.MustParseAddr("127.0.0.2") || selection.now.IsZero() {
		t.Fatalf("selection inputs: calls=%d peer=%v now=%v", selection.calls, selection.peer, selection.now)
	}
}

func TestPeerBindingFailsClosedWithoutSocketIdentity(t *testing.T) {
	i := NewInstance()
	i.SetDefaultResolver(&address.Address{})
	i.SetResolutionDepth(16)
	query := new(dns.Msg)
	query.SetQuestion("peer.invalid.", dns.TypeA)
	listener := &capturePeerListener{query: query, answer: make(chan *dns.Msg, 1)}
	selection := &recordingPeerResolver{result: &address.Address{}}
	i.AddListener(&server.Binding{Server: listener, PeerResolver: selection})
	var captured error
	errorReply := func(q *dns.Msg) *dns.Msg { return new(dns.Msg).SetRcode(q, dns.RcodeServerFailure) }
	i.Listen(errorReply, errorReply, func(err error) { captured = err })
	if reply := <-listener.answer; reply.Rcode != dns.RcodeServerFailure {
		t.Fatal(reply)
	}
	if !errors.Is(captured, server.ErrPeerUnavailable) || selection.calls != 0 {
		t.Fatalf("peer failure not closed: calls=%d err=%v", selection.calls, captured)
	}
}

func TestPeerBindingFailsClosedWhenSelectionRejectsRole(t *testing.T) {
	i := NewInstance()
	i.SetDefaultResolver(&address.Address{})
	i.SetResolutionDepth(16)
	query := new(dns.Msg)
	query.SetQuestion("peer.invalid.", dns.TypeA)
	listener := &capturePeerListener{query: query, peer: netip.MustParseAddr("127.0.0.1"), answer: make(chan *dns.Msg, 1)}
	selection := &recordingPeerResolver{err: sourcepolicy.ErrUnknownRole}
	i.AddListener(&server.Binding{Server: listener, PeerResolver: selection})
	var captured error
	errorReply := func(q *dns.Msg) *dns.Msg { return new(dns.Msg).SetRcode(q, dns.RcodeServerFailure) }
	i.Listen(errorReply, errorReply, func(err error) { captured = err })
	if reply := <-listener.answer; reply.Rcode != dns.RcodeServerFailure {
		t.Fatal(reply)
	}
	if !errors.Is(captured, sourcepolicy.ErrUnknownRole) || selection.calls != 1 {
		t.Fatalf("selection failure not closed: calls=%d err=%v", selection.calls, captured)
	}
}

func TestPeerBindingRejectsConflictingOrUnsupportedBinding(t *testing.T) {
	for _, binding := range []*server.Binding{
		{Server: &capturePeerListener{}, Resolver: &address.Address{}, PeerResolver: &recordingPeerResolver{result: &address.Address{}}},
		{Server: &captureListener{}, PeerResolver: &recordingPeerResolver{result: &address.Address{}}},
	} {
		i := NewInstance()
		i.SetDefaultResolver(&address.Address{})
		i.AddListener(binding)
		var captured error
		errorReply := func(q *dns.Msg) *dns.Msg { return new(dns.Msg).SetRcode(q, dns.RcodeServerFailure) }
		i.Listen(errorReply, errorReply, func(err error) { captured = err })
		if !errors.Is(captured, ErrInvalidListenerBinding) {
			t.Fatalf("invalid binding admitted: %v", captured)
		}
	}
}

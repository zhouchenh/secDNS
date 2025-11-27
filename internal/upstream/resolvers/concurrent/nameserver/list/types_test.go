package list

import (
	"errors"
	"github.com/miekg/dns"
	"github.com/zhouchenh/go-descriptor"
	resolverpkg "github.com/zhouchenh/secDNS/pkg/upstream/resolver"
	"github.com/zhouchenh/secDNS/pkg/upstream/resolver/nameserver"
	"testing"
	"time"
)

type stubNameServer struct {
	answer *dns.Msg
	err    error
	delay  time.Duration
	calls  int
}

func (s *stubNameServer) Type() descriptor.Type { return nameserver.Type() }
func (s *stubNameServer) TypeName() string      { return "stubNameServer" }
func (s *stubNameServer) NameServerResolver()   {}
func (s *stubNameServer) Resolve(query *dns.Msg, depth int) (*dns.Msg, error) {
	s.calls++
	if s.delay > 0 {
		time.Sleep(s.delay)
	}
	if s.err != nil {
		return nil, s.err
	}
	if s.answer != nil {
		return s.answer.Copy(), nil
	}
	return nil, nil
}

func newQuery(name string, qtype uint16) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(name, qtype)
	return msg
}

func TestConcurrentListReturnsFirstSuccess(t *testing.T) {
	fast := &stubNameServer{
		answer: newQuery("example.com.", dns.TypeA),
		delay:  5 * time.Millisecond,
	}
	slow := &stubNameServer{
		answer: newQuery("example.com.", dns.TypeA),
		delay:  25 * time.Millisecond,
	}
	var list ConcurrentNameServerList = []resolverpkg.Resolver{slow, fast}

	query := newQuery("example.com.", dns.TypeA)
	resp, err := list.Resolve(query, 10)
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}
	if resp == nil {
		t.Fatalf("expected response, got nil")
	}
	if fast.calls != 1 {
		t.Fatalf("expected fast resolver to be called once, got %d", fast.calls)
	}
}

func TestConcurrentListAllErrors(t *testing.T) {
	failure := &stubNameServer{err: errors.New("boom")}
	var list ConcurrentNameServerList = []resolverpkg.Resolver{failure}

	query := newQuery("example.net.", dns.TypeA)
	resp, err := list.Resolve(query, 5)
	if err == nil || resp != nil {
		t.Fatalf("expected error with nil response, got resp=%v err=%v", resp, err)
	}
}

func TestConcurrentListNilEntry(t *testing.T) {
	var list ConcurrentNameServerList = []resolverpkg.Resolver{nil}

	query := newQuery("example.org.", dns.TypeA)
	resp, err := list.Resolve(query, 5)
	if !errors.Is(err, ErrNilNameServer) || resp != nil {
		t.Fatalf("expected ErrNilNameServer and nil response, got resp=%v err=%v", resp, err)
	}
}

func TestConcurrentListDepthLimit(t *testing.T) {
	res := &stubNameServer{}
	var list ConcurrentNameServerList = []resolverpkg.Resolver{res}
	query := newQuery("example.com.", dns.TypeA)
	if _, err := list.Resolve(query, -1); !errors.Is(err, resolverpkg.ErrLoopDetected) {
		t.Fatalf("expected ErrLoopDetected, got %v", err)
	}
	if res.calls != 0 {
		t.Fatalf("resolver should not be invoked when depth limit triggers")
	}
}

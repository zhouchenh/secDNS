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

// mutatingStub repeatedly mutates the query it is handed (like the filterOut*IfPresents
// resolvers do), to exercise per-child message isolation in the fan-out under -race.
type mutatingStub struct{}

func (m *mutatingStub) Type() descriptor.Type { return nameserver.Type() }
func (m *mutatingStub) TypeName() string      { return "mutatingStub" }
func (m *mutatingStub) NameServerResolver()   {}
func (m *mutatingStub) Resolve(query *dns.Msg, depth int) (*dns.Msg, error) {
	for i := 0; i < 256; i++ {
		if len(query.Question) > 0 {
			query.Question[0].Qtype = dns.TypeAAAA
		}
	}
	reply := new(dns.Msg)
	reply.SetReply(query)
	return reply, nil
}

// readingStub repeatedly reads the query it is handed (like a real nameServer reading
// Id/Question before copying), so a sibling's write races a read on a shared message.
type readingStub struct{}

func (r *readingStub) Type() descriptor.Type { return nameserver.Type() }
func (r *readingStub) TypeName() string      { return "readingStub" }
func (r *readingStub) NameServerResolver()   {}
func (r *readingStub) Resolve(query *dns.Msg, depth int) (*dns.Msg, error) {
	for i := 0; i < 256; i++ {
		_ = query.Id
		if len(query.Question) > 0 {
			_ = query.Question[0].Qtype
		}
	}
	reply := new(dns.Msg)
	reply.SetReply(query)
	return reply, nil
}

// TestConcurrentListIsolatesQueryPerChild ensures the list hands each concurrent child
// its own copy of the query: a child that mutates its message must neither corrupt the
// caller's query (deterministic assertion below) nor race a sibling reading it (caught
// by -race). Without per-child copies this both fails the assertion and trips the race
// detector.
func TestConcurrentListIsolatesQueryPerChild(t *testing.T) {
	var list ConcurrentNameServerList = []resolverpkg.Resolver{&mutatingStub{}, &readingStub{}}

	for i := 0; i < 50; i++ {
		q := newQuery("example.com.", dns.TypeA)
		if _, err := list.Resolve(q, 10); err != nil {
			t.Fatalf("Resolve returned error: %v", err)
		}
		if q.Question[0].Qtype != dns.TypeA {
			t.Fatalf("a child mutated the caller's shared query (Qtype=%d)", q.Question[0].Qtype)
		}
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

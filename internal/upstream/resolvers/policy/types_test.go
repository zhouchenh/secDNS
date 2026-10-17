package policy

import (
	"github.com/miekg/dns"
	"github.com/zhouchenh/go-descriptor"
	"testing"
)

type depthSpy struct{ depth, calls int }

func (*depthSpy) Type() descriptor.Type { return nil }
func (*depthSpy) TypeName() string      { return "test" }
func (s *depthSpy) Resolve(q *dns.Msg, d int) (*dns.Msg, error) {
	s.depth = d
	s.calls++
	return new(dns.Msg).SetReply(q), nil
}
func TestPolicyConsumesExistingDepth(t *testing.T) {
	spy := new(depthSpy)
	p := &Policy{Graph: spy}
	q := new(dns.Msg)
	q.SetQuestion("test.invalid.", dns.TypeA)
	if _, err := p.Resolve(q, 3); err != nil || spy.depth != 2 || spy.calls != 1 {
		t.Fatal("depth reset", spy, err)
	}
	if _, err := p.Resolve(q, -1); err == nil || spy.calls != 1 {
		t.Fatal("exhausted depth invoked child")
	}
}

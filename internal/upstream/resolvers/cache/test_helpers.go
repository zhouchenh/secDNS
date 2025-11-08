package cache

import (
	"github.com/miekg/dns"
	"github.com/zhouchenh/go-descriptor"
)

// Mock resolver for testing and benchmarking
type mockResolver struct {
	response *dns.Msg
	err      error
	calls    int
}

func (m *mockResolver) Type() descriptor.Type { return descriptor.TypeOfNew(new(*mockResolver)) }
func (m *mockResolver) TypeName() string      { return "mock" }
func (m *mockResolver) NameServerResolver()   {}

func (m *mockResolver) Resolve(query *dns.Msg, depth int) (*dns.Msg, error) {
	m.calls++
	if m.err != nil {
		return nil, m.err
	}
	if m.response != nil {
		return m.response.Copy(), nil
	}
	return nil, nil
}

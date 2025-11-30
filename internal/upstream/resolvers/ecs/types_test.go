package ecsresolver

import (
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/zhouchenh/go-descriptor"
)

type stubResolver struct {
	last *dns.Msg
	err  error
}

func (s *stubResolver) Type() descriptor.Type { return nil }
func (s *stubResolver) TypeName() string      { return "stub" }
func (s *stubResolver) Resolve(query *dns.Msg, depth int) (*dns.Msg, error) {
	s.last = query
	return &dns.Msg{}, s.err
}

func TestECSAdd(t *testing.T) {
	stub := &stubResolver{}
	r := &Resolver{
		Resolver:        stub,
		EcsMode:         "add",
		EcsClientSubnet: "192.0.2.0/24",
	}
	query := new(dns.Msg)
	query.SetQuestion("example.", dns.TypeA)

	if _, err := r.Resolve(query, 1); err != nil {
		t.Fatalf("resolve returned error: %v", err)
	}
	if stub.last == nil {
		t.Fatalf("downstream resolver not invoked")
	}
	if opt := stub.last.IsEdns0(); opt == nil {
		t.Fatalf("expected OPT with ECS")
	} else if ecs := extractECS(opt); ecs == nil {
		t.Fatalf("expected ECS to be added")
	} else if ecs.Address.String() != "192.0.2.0" || ecs.SourceNetmask != 24 {
		t.Fatalf("unexpected ECS: %+v", ecs)
	}
	// original query should remain without ECS
	if query.IsEdns0() != nil {
		t.Fatalf("original query mutated with OPT")
	}
}

func TestECSOverride(t *testing.T) {
	stub := &stubResolver{}
	r := &Resolver{
		Resolver:        stub,
		EcsMode:         "override",
		EcsClientSubnet: "198.51.100.0/24",
	}
	query := new(dns.Msg)
	query.SetQuestion("example.", dns.TypeA)
	query.SetEdns0(1232, true)
	origOpt := query.IsEdns0()
	origOpt.Option = append(origOpt.Option, &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        1,
		SourceNetmask: 32,
		Address:       net.IP{203, 0, 113, 5},
	})

	if _, err := r.Resolve(query, 1); err != nil {
		t.Fatalf("resolve returned error: %v", err)
	}
	ecs := extractECS(stub.last.IsEdns0())
	if ecs == nil {
		t.Fatalf("expected ECS to be present")
	}
	if ecs.Address.String() != "198.51.100.0" || ecs.SourceNetmask != 24 {
		t.Fatalf("expected override to use configured subnet, got %+v", ecs)
	}
	// ensure original ECS untouched
	origECS := extractECS(query.IsEdns0())
	if origECS == nil || origECS.Address.String() != "203.0.113.5" {
		t.Fatalf("original query ECS should remain unchanged")
	}
}

func TestECSStrip(t *testing.T) {
	stub := &stubResolver{}
	r := &Resolver{
		Resolver: stub,
		EcsMode:  "strip",
	}
	query := new(dns.Msg)
	query.SetQuestion("example.", dns.TypeA)
	query.SetEdns0(1232, true)
	query.IsEdns0().Option = append(query.IsEdns0().Option, &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        1,
		SourceNetmask: 32,
		Address:       net.IP{203, 0, 113, 5},
	})

	if _, err := r.Resolve(query, 1); err != nil {
		t.Fatalf("resolve returned error: %v", err)
	}
	if ecs := extractECS(stub.last.IsEdns0()); ecs != nil {
		t.Fatalf("expected ECS to be stripped, got %+v", ecs)
	}
	// original query should remain unchanged
	if extractECS(query.IsEdns0()) == nil {
		t.Fatalf("original query ECS should remain")
	}
}

func extractECS(opt *dns.OPT) *dns.EDNS0_SUBNET {
	if opt == nil {
		return nil
	}
	for _, o := range opt.Option {
		if ecs, ok := o.(*dns.EDNS0_SUBNET); ok {
			return ecs
		}
	}
	return nil
}

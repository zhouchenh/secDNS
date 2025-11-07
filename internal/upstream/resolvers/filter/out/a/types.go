package a

import (
	"github.com/miekg/dns"
	"github.com/zhouchenh/go-descriptor"
	"github.com/zhouchenh/secDNS/internal/common"
	"github.com/zhouchenh/secDNS/pkg/upstream/resolver"
)

type FilterOutA struct {
	Resolver resolver.Resolver
}

var typeOfFilterOutA = descriptor.TypeOfNew(new(*FilterOutA))

func (fa *FilterOutA) Type() descriptor.Type {
	return typeOfFilterOutA
}

func (fa *FilterOutA) TypeName() string {
	return "filterOutA"
}

func (fa *FilterOutA) Resolve(query *dns.Msg, depth int) (*dns.Msg, error) {
	if depth < 0 {
		return nil, resolver.ErrLoopDetected
	}
	switch query.Question[0].Qtype {
	case dns.TypeA:
		msg := new(dns.Msg)
		msg.SetReply(query)
		return msg, nil
	default:
		reply, err := fa.Resolver.Resolve(query, depth-1)
		if err != nil {
			return nil, err
		}
		notA := func(rr dns.RR) bool {
			_, isA := rr.(*dns.A)
			return !isA
		}
		reply.Answer = common.FilterResourceRecords(reply.Answer, notA)
		reply.Ns = common.FilterResourceRecords(reply.Ns, notA)
		reply.Extra = common.FilterResourceRecords(reply.Extra, notA)
		return reply, nil
	}
}

func (fa *FilterOutA) NameServerResolver() {}

func init() {
	if err := resolver.RegisterResolver(&descriptor.Descriptor{
		Type: typeOfFilterOutA,
		Filler: descriptor.ObjectFiller{
			ObjectPath: descriptor.Path{"Resolver"},
			ValueSource: descriptor.ObjectAtPath{
				ObjectPath: descriptor.Root,
				AssignableKind: descriptor.AssignmentFunction(func(i interface{}) (object interface{}, ok bool) {
					object, s, f := resolver.Descriptor().Describe(i)
					ok = s > 0 && f < 1
					return
				}),
			},
		},
	}); err != nil {
		common.ErrOutput(err)
	}
}

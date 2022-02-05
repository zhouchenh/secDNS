package a

import (
	"github.com/miekg/dns"
	"github.com/zhouchenh/go-descriptor"
	"github.com/zhouchenh/secDNS/internal/common"
	"github.com/zhouchenh/secDNS/pkg/upstream/resolver"
)

type FilterA struct {
	Resolver resolver.Resolver
}

var typeOfFilterA = descriptor.TypeOfNew(new(*FilterA))

func (fa *FilterA) Type() descriptor.Type {
	return typeOfFilterA
}

func (fa *FilterA) TypeName() string {
	return "filterA"
}

func (fa *FilterA) Resolve(query *dns.Msg, depth int) (*dns.Msg, error) {
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

func init() {
	if err := resolver.RegisterResolver(&descriptor.Descriptor{
		Type: typeOfFilterA,
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

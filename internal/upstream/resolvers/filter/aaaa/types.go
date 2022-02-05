package aaaa

import (
	"github.com/miekg/dns"
	"github.com/zhouchenh/go-descriptor"
	"github.com/zhouchenh/secDNS/internal/common"
	"github.com/zhouchenh/secDNS/pkg/upstream/resolver"
)

type FilterAAAA struct {
	Resolver resolver.Resolver
}

var typeOfFilterAAAA = descriptor.TypeOfNew(new(*FilterAAAA))

func (fa *FilterAAAA) Type() descriptor.Type {
	return typeOfFilterAAAA
}

func (fa *FilterAAAA) TypeName() string {
	return "filterAAAA"
}

func (fa *FilterAAAA) Resolve(query *dns.Msg, depth int) (*dns.Msg, error) {
	if depth < 0 {
		return nil, resolver.ErrLoopDetected
	}
	switch query.Question[0].Qtype {
	case dns.TypeAAAA:
		msg := new(dns.Msg)
		msg.SetReply(query)
		return msg, nil
	default:
		reply, err := fa.Resolver.Resolve(query, depth-1)
		if err != nil {
			return nil, err
		}
		notAAAA := func(rr dns.RR) bool {
			_, isAAAA := rr.(*dns.AAAA)
			return !isAAAA
		}
		reply.Answer = common.FilterResourceRecords(reply.Answer, notAAAA)
		reply.Ns = common.FilterResourceRecords(reply.Ns, notAAAA)
		reply.Extra = common.FilterResourceRecords(reply.Extra, notAAAA)
		return reply, nil
	}
}

func init() {
	if err := resolver.RegisterResolver(&descriptor.Descriptor{
		Type: typeOfFilterAAAA,
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

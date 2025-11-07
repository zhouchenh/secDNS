package aaaa

import (
	"github.com/miekg/dns"
	"github.com/zhouchenh/go-descriptor"
	"github.com/zhouchenh/secDNS/internal/common"
	"github.com/zhouchenh/secDNS/pkg/upstream/resolver"
)

type FilterOutAAAA struct {
	Resolver resolver.Resolver
}

var typeOfFilterOutAAAA = descriptor.TypeOfNew(new(*FilterOutAAAA))

func (fa *FilterOutAAAA) Type() descriptor.Type {
	return typeOfFilterOutAAAA
}

func (fa *FilterOutAAAA) TypeName() string {
	return "filterOutAAAA"
}

func (fa *FilterOutAAAA) Resolve(query *dns.Msg, depth int) (*dns.Msg, error) {
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

func (fa *FilterOutAAAA) NameServerResolver() {}

func init() {
	if err := resolver.RegisterResolver(&descriptor.Descriptor{
		Type: typeOfFilterOutAAAA,
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

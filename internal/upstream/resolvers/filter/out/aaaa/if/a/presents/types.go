package aaaa

import (
	"github.com/miekg/dns"
	"github.com/zhouchenh/go-descriptor"
	"github.com/zhouchenh/secDNS/internal/common"
	"github.com/zhouchenh/secDNS/pkg/upstream/resolver"
)

type FilterOutAAAAIfAPresents struct {
	Resolver resolver.Resolver
}

var typeOfFilterOutAAAAIfAPresents = descriptor.TypeOfNew(new(*FilterOutAAAAIfAPresents))

func (fa *FilterOutAAAAIfAPresents) Type() descriptor.Type {
	return typeOfFilterOutAAAAIfAPresents
}

func (fa *FilterOutAAAAIfAPresents) TypeName() string {
	return "filterOutAAAAIfAPresents"
}

func (fa *FilterOutAAAAIfAPresents) Resolve(query *dns.Msg, depth int) (*dns.Msg, error) {
	if depth < 0 {
		return nil, resolver.ErrLoopDetected
	}
	canResolveToA, err := fa.canResolveToA(query, depth)
	if err != nil {
		return nil, err
	}
	if !canResolveToA {
		return fa.Resolver.Resolve(query, depth-1)
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

func (fa *FilterOutAAAAIfAPresents) canResolveToA(query *dns.Msg, depth int) (bool, error) {
	originalQuestionType := query.Question[0].Qtype
	query.Question[0].Qtype = dns.TypeA
	reply, err := fa.Resolver.Resolve(query, depth-1)
	query.Question[0].Qtype = originalQuestionType
	if err != nil {
		return false, err
	}
	return isNoErrorReply(reply) && hasA(reply), nil
}

func isNoErrorReply(reply *dns.Msg) bool {
	return reply != nil && reply.Response && reply.Rcode == dns.RcodeSuccess
}

func hasA(reply *dns.Msg) bool {
	for _, rr := range reply.Answer {
		if _, ok := rr.(*dns.A); ok {
			return true
		}
	}
	return false
}

func (fa *FilterOutAAAAIfAPresents) NameServerResolver() {}

func init() {
	if err := resolver.RegisterResolver(&descriptor.Descriptor{
		Type: typeOfFilterOutAAAAIfAPresents,
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

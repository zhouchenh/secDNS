package a

import (
	"github.com/miekg/dns"
	"github.com/zhouchenh/go-descriptor"
	"github.com/zhouchenh/secDNS/internal/common"
	"github.com/zhouchenh/secDNS/pkg/upstream/resolver"
)

type FilterOutAIfAAAAPresents struct {
	Resolver resolver.Resolver
}

var typeOfFilterOutAIfAAAAPresents = descriptor.TypeOfNew(new(*FilterOutAIfAAAAPresents))

func (fa *FilterOutAIfAAAAPresents) Type() descriptor.Type {
	return typeOfFilterOutAIfAAAAPresents
}

func (fa *FilterOutAIfAAAAPresents) TypeName() string {
	return "filterOutAIfAAAAPresents"
}

func (fa *FilterOutAIfAAAAPresents) Resolve(query *dns.Msg, depth int) (*dns.Msg, error) {
	if depth < 0 {
		return nil, resolver.ErrLoopDetected
	}
	canResolveToAAAA, err := fa.canResolveToAAAA(query, depth)
	if err != nil {
		return nil, err
	}
	if !canResolveToAAAA {
		return fa.Resolver.Resolve(query, depth-1)
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

func (fa *FilterOutAIfAAAAPresents) canResolveToAAAA(query *dns.Msg, depth int) (bool, error) {
	originalQuestionType := query.Question[0].Qtype
	query.Question[0].Qtype = dns.TypeAAAA
	reply, err := fa.Resolver.Resolve(query, depth-1)
	query.Question[0].Qtype = originalQuestionType
	if err != nil {
		return false, err
	}
	return isNoErrorReply(reply) && hasAAAA(reply), nil
}

func isNoErrorReply(reply *dns.Msg) bool {
	return reply != nil && reply.Response && reply.Rcode == dns.RcodeSuccess
}

func hasAAAA(reply *dns.Msg) bool {
	for _, rr := range reply.Answer {
		if _, ok := rr.(*dns.AAAA); ok {
			return true
		}
	}
	return false
}

func init() {
	if err := resolver.RegisterResolver(&descriptor.Descriptor{
		Type: typeOfFilterOutAIfAAAAPresents,
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

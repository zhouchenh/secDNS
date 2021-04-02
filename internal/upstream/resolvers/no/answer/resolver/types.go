package resolver

import (
	"github.com/miekg/dns"
	"github.com/zhouchenh/go-descriptor"
	"github.com/zhouchenh/secDNS/internal/common"
	"github.com/zhouchenh/secDNS/pkg/upstream/resolver"
)

type NoAnswerResolver struct{}

var NoAnswer = new(NoAnswerResolver)

var typeOfNoAnswerResolver = descriptor.TypeOfNew(&NoAnswer)

func (na *NoAnswerResolver) Type() descriptor.Type {
	return typeOfNoAnswerResolver
}

func (na *NoAnswerResolver) TypeName() string {
	return "noAnswer"
}

func (na *NoAnswerResolver) Resolve(query *dns.Msg, depth int) (*dns.Msg, error) {
	if depth < 0 {
		return nil, resolver.ErrLoopDetected
	}
	msg := new(dns.Msg)
	msg.SetReply(query)
	return msg, nil
}

func init() {
	if err := resolver.RegisterResolver(&descriptor.Descriptor{
		Type:   typeOfNoAnswerResolver,
		Filler: descriptor.ObjectFiller{ValueSource: descriptor.DefaultValue{Value: NoAnswer}},
	}); err != nil {
		common.ErrOutput(err)
	}
}

package resolver

import (
	"common"
	"github.com/miekg/dns"
	"github.com/zhouchenh/go-descriptor"
	"upstream/resolver"
)

type NotExistResolver struct{}

var NotExist = new(NotExistResolver)

var typeOfNotExistResolver = descriptor.TypeOfNew(&NotExist)

func (ne *NotExistResolver) Type() descriptor.Type {
	return typeOfNotExistResolver
}

func (ne *NotExistResolver) TypeName() string {
	return "notExist"
}

func (ne *NotExistResolver) Resolve(query *dns.Msg, depth int) (*dns.Msg, error) {
	if depth < 0 {
		return nil, resolver.ErrLoopDetected
	}
	msg := new(dns.Msg)
	msg.SetRcode(query, dns.RcodeNameError)
	return msg, nil
}

func init() {
	if err := resolver.RegisterResolver(&descriptor.Descriptor{
		Type:   typeOfNotExistResolver,
		Filler: descriptor.ObjectFiller{ValueSource: descriptor.DefaultValue{Value: NotExist}},
	}); err != nil {
		common.ErrOutput(err)
	}
}

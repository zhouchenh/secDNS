package nameserver

import (
	"github.com/miekg/dns"
	"github.com/zhouchenh/go-descriptor"
)

type Resolver interface {
	Type() descriptor.Type
	TypeName() string
	Resolve(query *dns.Msg, depth int) (*dns.Msg, error)
	NameServerResolver()
}

var typeOfResolver = descriptor.TypeOfNew(new(Resolver))

func Type() descriptor.Type {
	return typeOfResolver
}

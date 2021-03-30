package resolver

import (
	"github.com/zhouchenh/go-descriptor"
	"github.com/zhouchenh/secDNS/pkg/common"
)

var registeredResolver = make(map[string]descriptor.Describable)

func RegisterResolver(describable descriptor.Describable) error {
	if describable == nil {
		return NotRegistrableError(common.TypeString(nil))
	}
	resolver, ok := describable.GetPrototype().(Resolver)
	if !ok {
		return NotRegistrableError(common.TypeString(describable.GetPrototype()))
	}
	t := resolver.TypeName()
	if len(t) < 1 {
		return NotRegistrableError(common.TypeString(resolver))
	}
	if _, hasKey := registeredResolver[t]; hasKey {
		return AlreadyRegisteredError(t)
	}
	registeredResolver[t] = describable
	return nil
}

func GetResolverDescriptorByTypeName(typeName string) (describable descriptor.Describable, ok bool) {
	describable, ok = registeredResolver[typeName]
	return
}

package provider

import (
	"common"
	"github.com/zhouchenh/go-descriptor"
)

var registeredProvider = make(map[string]descriptor.Describable)

func RegisterProvider(describable descriptor.Describable) error {
	if describable == nil {
		return NotRegistrableError(common.TypeString(nil))
	}
	provider, ok := describable.GetPrototype().(Provider)
	if !ok {
		return NotRegistrableError(common.TypeString(describable.GetPrototype()))
	}
	t := provider.TypeName()
	if len(t) < 1 {
		return NotRegistrableError(common.TypeString(provider))
	}
	if _, hasKey := registeredProvider[t]; hasKey {
		return AlreadyRegisteredError(t)
	}
	registeredProvider[t] = describable
	return nil
}

func GetProviderDescriptorByTypeName(typeName string) (describable descriptor.Describable, ok bool) {
	describable, ok = registeredProvider[typeName]
	return
}

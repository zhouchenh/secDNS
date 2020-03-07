package server

import (
	"common"
	"github.com/zhouchenh/go-descriptor"
)

var registeredServer = make(map[string]descriptor.Describable)

func RegisterServer(describable descriptor.Describable) error {
	if describable == nil {
		return NotRegistrableError(common.TypeString(nil))
	}
	server, ok := describable.GetPrototype().(Server)
	if !ok {
		return NotRegistrableError(common.TypeString(describable.GetPrototype()))
	}
	t := server.TypeName()
	if len(t) < 1 {
		return NotRegistrableError(common.TypeString(server))
	}
	if _, hasKey := registeredServer[t]; hasKey {
		return AlreadyRegisteredError(t)
	}
	registeredServer[t] = describable
	return nil
}

func GetServerDescriptorByTypeName(typeName string) (describable descriptor.Describable, ok bool) {
	describable, ok = registeredServer[typeName]
	return
}

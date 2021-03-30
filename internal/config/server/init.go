package server

import (
	"github.com/zhouchenh/go-descriptor"
	"github.com/zhouchenh/secDNS/internal/config/typed"
	"github.com/zhouchenh/secDNS/pkg/listeners/server"
)

func init() {
	server.RegisterAssignmentFunctionByKind(descriptor.KindMap, func(i interface{}) (object interface{}, ok bool) {
		typedValue, s, f := typed.ValueDescriptor.Describe(i)
		ok = s > 0 && f < 1
		if !ok {
			return
		}
		object, s, f = server.Descriptor().Describe(typedValue)
		ok = s > 0 && f < 1
		return
	})
}

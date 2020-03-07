package resolver

import (
	"config/typed"
	"github.com/zhouchenh/go-descriptor"
	"upstream/resolver"
)

func init() {
	resolver.RegisterAssignmentFunctionByKind(descriptor.KindMap, func(i interface{}) (object interface{}, ok bool) {
		typedValue, s, f := typed.ValueDescriptor.Describe(i)
		ok = s > 0 && f < 1
		if !ok {
			return
		}
		object, s, f = resolver.Descriptor().Describe(typedValue)
		ok = s > 0 && f < 1
		return
	})
}

package provider

import (
	"config/typed"
	"github.com/zhouchenh/go-descriptor"
	"rules/provider"
)

func init() {
	provider.RegisterAssignmentFunctionByType(descriptor.TypeOfNew(new(typed.Value)), func(i interface{}) (object interface{}, ok bool) {
		typedValue, ok := i.(typed.Value)
		if !ok {
			return
		}
		describable, ok := provider.GetProviderDescriptorByTypeName(typedValue.Type)
		if !ok {
			return
		}
		if describable == nil {
			return nil, false
		}
		object, s, f := describable.Describe(typedValue.Value)
		ok = s > 0 && f < 1
		return
	})
}

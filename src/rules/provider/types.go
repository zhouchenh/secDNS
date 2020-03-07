package provider

import (
	"github.com/zhouchenh/go-descriptor"
	"upstream/resolver"
)

type Provider interface {
	Type() descriptor.Type
	TypeName() string
	Provide(receive func(name string, r resolver.Resolver), receiveError func(err error)) (more bool)
}

var typeOfProvider = descriptor.TypeOfNew(new(Provider))

func Type() descriptor.Type {
	return typeOfProvider
}

var registeredAssignmentFunctionByType = make(map[descriptor.Type]descriptor.AssignmentFunction)
var registeredAssignmentFunctionByKind = make(map[descriptor.Kind]descriptor.AssignmentFunction)

var privateDescriptor = descriptor.Descriptor{
	Type: typeOfProvider,
	Filler: descriptor.ObjectFiller{
		ValueSource: descriptor.ObjectAtPath{
			ObjectPath: descriptor.Root,
			AssignableKind: descriptor.AssignmentFunction(func(i interface{}) (object interface{}, ok bool) {
				t := descriptor.TypeOf(i)
				f, ok := registeredAssignmentFunctionByType[t]
				if !ok {
					k := descriptor.KindOf(i)
					f, ok = registeredAssignmentFunctionByKind[k]
					if !ok {
						return
					}
				}
				return f(i)
			}),
		},
	},
}

func Descriptor() descriptor.Describable {
	return &privateDescriptor
}

func RegisterAssignmentFunctionByType(t descriptor.Type, f descriptor.AssignmentFunction) {
	if t == nil || f == nil {
		return
	}
	registeredAssignmentFunctionByType[t] = f
}

func RegisterAssignmentFunctionByKind(k descriptor.Kind, f descriptor.AssignmentFunction) {
	if f == nil {
		return
	}
	registeredAssignmentFunctionByKind[k] = f
}

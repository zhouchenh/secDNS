package rule

import (
	"github.com/zhouchenh/go-descriptor"
	"github.com/zhouchenh/secDNS/pkg/upstream/resolver"
)

type NameResolutionRule struct {
	Name     string
	Resolver resolver.Resolver
}

var typeOfNameResolutionRule = descriptor.TypeOfNew(new(*NameResolutionRule))

var nameResolutionRuleDescriptor = descriptor.Descriptor{
	Type: typeOfNameResolutionRule,
	Filler: descriptor.Fillers{
		descriptor.ObjectFiller{
			ObjectPath: descriptor.Path{"Name"},
			ValueSource: descriptor.ObjectAtPath{
				ObjectPath:     descriptor.Path{"name"},
				AssignableKind: descriptor.KindString,
			},
		},
		descriptor.ObjectFiller{
			ObjectPath: descriptor.Path{"Resolver"},
			ValueSource: descriptor.ObjectAtPath{
				ObjectPath: descriptor.Path{"resolver"},
				AssignableKind: descriptor.AssignmentFunction(func(i interface{}) (object interface{}, ok bool) {
					object, s, f := resolver.Descriptor().Describe(i)
					ok = s > 0 && f < 1
					return
				}),
			},
		},
	},
}

func NameResolutionRuleDescriptor() descriptor.Describable {
	return &nameResolutionRuleDescriptor
}

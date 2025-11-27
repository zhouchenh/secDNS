package collection

import (
	"github.com/zhouchenh/go-descriptor"
	"github.com/zhouchenh/secDNS/internal/common"
	"github.com/zhouchenh/secDNS/internal/rules/providers/collection"
	"github.com/zhouchenh/secDNS/internal/rules/providers/collection/rule"
	"github.com/zhouchenh/secDNS/pkg/rules/provider"
)

type TypedCollection struct {
	collection.Collection
}

var typeOfTypedCollection = descriptor.TypeOfNew(new(*TypedCollection))

func (c *TypedCollection) Type() descriptor.Type {
	return typeOfTypedCollection
}

func (c *TypedCollection) TypeName() string {
	return "typedCollection"
}

func init() {
	if err := provider.RegisterProvider(&descriptor.Descriptor{
		Type: typeOfTypedCollection,
		Filler: descriptor.ObjectFiller{
			ObjectPath: descriptor.Path{"Rules"},
			ValueSource: descriptor.ObjectAtPath{
				ObjectPath: descriptor.Root,
				AssignableKind: descriptor.ConvertibleKind{
					Kind: descriptor.KindSlice,
					ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
						interfaces, ok := original.([]interface{})
						if !ok {
							return
						}
						var nameResolutionRules []*rule.NameResolutionRule
						for _, i := range interfaces {
							rawNameResolutionRule, s, f := rule.NameResolutionRuleDescriptor().Describe(i)
							ok := s > 0 && f < 1
							if !ok {
								continue
							}
							nameResolutionRule, ok := rawNameResolutionRule.(*rule.NameResolutionRule)
							if !ok {
								continue
							}
							nameResolutionRules = append(nameResolutionRules, nameResolutionRule)
						}
						return nameResolutionRules, true
					},
				},
			},
		},
	}); err != nil {
		common.ErrOutput(err)
	}
}

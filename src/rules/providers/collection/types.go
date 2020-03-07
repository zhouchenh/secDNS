package collection

import (
	"common"
	"github.com/zhouchenh/go-descriptor"
	"rules/provider"
	"rules/providers/collection/rule"
	"upstream/resolver"
)

type Collection struct {
	Rules []*rule.NameResolutionRule
	index int
}

var typeOfCollection = descriptor.TypeOfNew(new(*Collection))

func (c *Collection) Type() descriptor.Type {
	return typeOfCollection
}

func (c *Collection) TypeName() string {
	return "collection"
}

func (c *Collection) Provide(receive func(name string, r resolver.Resolver), receiveError func(err error)) (more bool) {
	if c == nil || receive == nil {
		return false
	}
	canReceiveError := receiveError != nil
	for c.index < len(c.Rules) {
		if !common.IsDomainName(c.Rules[c.index].Name) {
			if canReceiveError {
				receiveError(InvalidDomainNameError(c.Rules[c.index].Name))
			}
			c.index++
			continue
		}
		receive(common.EnsureFQDN(c.Rules[c.index].Name), c.Rules[c.index].Resolver)
		c.index++
		break
	}
	return c.index < len(c.Rules)
}

func init() {
	if err := provider.RegisterProvider(&descriptor.Descriptor{
		Type: typeOfCollection,
		Filler: descriptor.ObjectFiller{
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
						return descriptor.PointerOf(Collection{Rules: nameResolutionRules}), true
					},
				},
			},
		},
	}); err != nil {
		common.ErrOutput(err)
	}
}

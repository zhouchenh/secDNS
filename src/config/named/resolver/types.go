package resolver

import (
	"github.com/miekg/dns"
	"github.com/zhouchenh/go-descriptor"
	"upstream/resolver"
)

type NamedResolver struct {
	Name         string
	NameRegistry *NameRegistry
	resolver     resolver.Resolver
}

func (nr *NamedResolver) Init() {
	if nr == nil {
		return
	}
	if nr.NameRegistry == nil {
		return
	}
	if nr.NameRegistry.registry == nil {
		nr.NameRegistry.registry = make(map[string]resolver.Resolver)
	}
	r, ok := nr.NameRegistry.registry[nr.Name]
	if !ok || r == nil {
		return
	}
	nr.resolver = r
}

func (nr *NamedResolver) Type() descriptor.Type {
	if nr == nil {
		return nil
	}
	if nr.resolver == nil {
		nr.Init()
		if nr.resolver == nil {
			return nil
		}
	}
	return nr.resolver.Type()
}

func (nr *NamedResolver) TypeName() string {
	if nr == nil {
		return ""
	}
	if nr.resolver == nil {
		nr.Init()
		if nr.resolver == nil {
			return ""
		}
	}
	return nr.resolver.TypeName()
}

func (nr *NamedResolver) Resolve(query *dns.Msg, depth int) (*dns.Msg, error) {
	if nr.resolver == nil {
		nr.Init()
		if nr.resolver == nil {
			return nil, NotFoundError(nr.Name)
		}
	}
	return nr.resolver.Resolve(query, depth)
}

var namedResolverDescriptor = descriptor.Descriptor{
	Type: descriptor.TypeOfNew(new(*NamedResolver)),
	Filler: descriptor.Fillers{
		descriptor.ObjectFiller{
			ObjectPath: descriptor.Path{"Name"},
			ValueSource: descriptor.ObjectAtPath{
				ObjectPath:     descriptor.Root,
				AssignableKind: descriptor.KindString,
			},
		},
		descriptor.ObjectFiller{
			ObjectPath: descriptor.Path{"NameRegistry"},
			ValueSource: descriptor.ObjectAtPath{
				ObjectPath: descriptor.Root,
				AssignableKind: descriptor.AssignmentFunction(func(i interface{}) (object interface{}, ok bool) {
					if nameRegistryAssignmentFunction == nil {
						return nil, false
					}
					return nameRegistryAssignmentFunction(i)
				}),
			},
		},
	},
}

func init() {
	resolver.RegisterAssignmentFunctionByKind(descriptor.KindString, func(i interface{}) (object interface{}, ok bool) {
		object, s, f := namedResolverDescriptor.Describe(i)
		ok = s > 0 && f < 1
		if ok {
			if nr, isNR := object.(*NamedResolver); isNR {
				reportNamedResolver(nr)
			}
		}
		return
	})
}

var nameRegistryAssignmentFunction descriptor.AssignmentFunction

func SetNameRegistryAssignmentFunction(f descriptor.AssignmentFunction) {
	nameRegistryAssignmentFunction = f
}

var knownNamedResolvers []*NamedResolver

func reportNamedResolver(namedResolver *NamedResolver) {
	if namedResolver == nil {
		return
	}
	knownNamedResolvers = append(knownNamedResolvers, namedResolver)
}

func InitKnownNamedResolvers() error {
	for _, namedResolver := range knownNamedResolvers {
		if namedResolver.resolver != nil {
			continue
		}
		namedResolver.Init()
		if namedResolver.resolver == nil {
			return NotFoundError(namedResolver.Name)
		}
	}
	knownNamedResolvers = nil
	return nil
}

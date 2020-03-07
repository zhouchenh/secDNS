package config

import (
	named "config/named/resolver"
	"github.com/zhouchenh/go-descriptor"
	"listeners/server"
	"rules/provider"
	"strconv"
	"upstream/resolver"
)

type Config struct {
	Listeners       []server.Server
	Resolvers       *named.NameRegistry
	Rules           []provider.Provider
	DefaultResolver resolver.Resolver
	ResolutionDepth int
}

var typeOfConfig = descriptor.TypeOfNew(new(*Config))

func Type() descriptor.Type {
	return typeOfConfig
}

func Descriptor() descriptor.Describable {
	nameRegistry := new(named.NameRegistry)
	return &descriptor.Descriptor{
		Type: typeOfConfig,
		Filler: descriptor.Fillers{
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"Listeners"},
				ValueSource: descriptor.ObjectAtPath{
					ObjectPath: descriptor.Path{"listeners"},
					AssignableKind: descriptor.ConvertibleKind{
						Kind: descriptor.KindSlice,
						ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
							arr, ok := original.([]interface{})
							if !ok {
								return
							}
							var listeners []server.Server
							errorCount := 0
							for _, i := range arr {
								rawListener, s, f := server.Descriptor().Describe(i)
								if s < 1 || f > 0 {
									errorCount++
									continue
								}
								listener, ok := rawListener.(server.Server)
								if !ok {
									errorCount++
									continue
								}
								listeners = append(listeners, listener)
							}
							converted = listeners
							ok = errorCount < 1
							return
						},
					},
				},
			},
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"Resolvers"},
				ValueSource: descriptor.ObjectAtPath{
					AssignableKind: descriptor.AssignmentFunction(func(interface{}) (interface{}, bool) {
						named.SetNameRegistryAssignmentFunction(func(interface{}) (interface{}, bool) {
							return nameRegistry, true
						})
						return nameRegistry, true
					}),
				},
			},
			descriptor.ObjectFiller{
				ValueSource: descriptor.ValueSources{
					descriptor.ObjectAtPath{
						ObjectPath: descriptor.Path{"resolvers"},
						AssignableKind: descriptor.ConvertibleKind{
							Kind: descriptor.KindMap,
							ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
								m, ok := original.(map[string]interface{})
								if !ok {
									return
								}
								for resolverTypeName, resolversByType := range m {
									describable, ok := resolver.GetResolverDescriptorByTypeName(resolverTypeName)
									if !ok {
										continue
									}
									resolvers, ok := resolversByType.(map[string]interface{})
									if !ok {
										continue
									}
									for name, config := range resolvers {
										rawResolver, s, f := describable.Describe(config)
										ok := s > 0 && f < 1
										if !ok {
											continue
										}
										r, ok := rawResolver.(resolver.Resolver)
										if !ok {
											continue
										}
										err := nameRegistry.NameResolver(name, r)
										if err != nil {
											continue
										}
									}
								}
								return nil, true
							},
						},
					},
					descriptor.DefaultValue{Value: nil},
				},
			},
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"Rules"},
				ValueSource: descriptor.ValueSources{
					descriptor.ObjectAtPath{
						ObjectPath: descriptor.Path{"rules"},
						AssignableKind: descriptor.ConvertibleKind{
							Kind: descriptor.KindSlice,
							ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
								arr, ok := original.([]interface{})
								if !ok {
									return
								}
								var rules []provider.Provider
								errorCount := 0
								for _, i := range arr {
									rawRule, s, f := provider.Descriptor().Describe(i)
									if s < 1 || f > 0 {
										errorCount++
										continue
									}
									rule, ok := rawRule.(provider.Provider)
									if !ok {
										errorCount++
										continue
									}
									rules = append(rules, rule)
								}
								converted = rules
								ok = errorCount < 1
								return
							},
						},
					},
					descriptor.DefaultValue{Value: nil},
				},
			},
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"DefaultResolver"},
				ValueSource: descriptor.ObjectAtPath{
					ObjectPath: descriptor.Path{"defaultResolver"},
					AssignableKind: descriptor.AssignmentFunction(func(i interface{}) (object interface{}, ok bool) {
						object, s, f := resolver.Descriptor().Describe(i)
						ok = s > 0 && f < 1
						return
					}),
				},
			},
			descriptor.ObjectFiller{
				ValueSource: descriptor.ObjectAtPath{
					AssignableKind: descriptor.AssignmentFunction(func(interface{}) (interface{}, bool) {
						named.SetNameRegistryAssignmentFunction(nil)
						return nil, true
					}),
				},
			},
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"ResolutionDepth"},
				ValueSource: descriptor.ValueSources{
					descriptor.ObjectAtPath{
						ObjectPath: descriptor.Path{"resolutionDepth"},
						AssignableKind: descriptor.AssignableKinds{
							descriptor.ConvertibleKind{
								Kind: descriptor.KindFloat64,
								ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
									f, ok := original.(float64)
									if !ok {
										return
									}
									converted = int(f)
									return
								},
							},
							descriptor.ConvertibleKind{
								Kind: descriptor.KindString,
								ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
									str, ok := original.(string)
									if !ok {
										return
									}
									i, err := strconv.Atoi(str)
									if err != nil {
										return nil, false
									}
									return i, true
								},
							},
						},
					},
					descriptor.DefaultValue{Value: 64},
				},
			},
		},
	}
}

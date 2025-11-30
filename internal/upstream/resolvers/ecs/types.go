package ecs

import (
	"github.com/miekg/dns"
	"github.com/zhouchenh/go-descriptor"
	"github.com/zhouchenh/secDNS/internal/common"
	ednsecs "github.com/zhouchenh/secDNS/internal/edns/ecs"
	"github.com/zhouchenh/secDNS/pkg/upstream/resolver"
	"sync"
)

// Resolver applies EDNS Client Subnet manipulation (passthrough/add/override) before delegating to another resolver.
// Useful to share downstream caches (cache/recursive) while varying ECS policy without duplicate cache instances.
type Resolver struct {
	Resolver        resolver.Resolver
	EcsMode         string
	EcsClientSubnet string
	ecsConfig       *ednsecs.Config
	initOnce        sync.Once
	initErr         error
}

var typeOfResolver = descriptor.TypeOfNew(new(*Resolver))

func (r *Resolver) Type() descriptor.Type {
	return typeOfResolver
}

func (r *Resolver) TypeName() string {
	return "ecs"
}

func (r *Resolver) Resolve(query *dns.Msg, depth int) (*dns.Msg, error) {
	if depth < 0 {
		return nil, resolver.ErrLoopDetected
	}
	if query == nil || len(query.Question) == 0 {
		return nil, resolver.ErrNotSupportedQuestion
	}

	r.initOnce.Do(func() {
		r.ecsConfig, r.initErr = ednsecs.ParseConfig(r.EcsMode, r.EcsClientSubnet)
		if r.initErr != nil {
			common.ErrOutput(r.initErr)
		}
	})
	if r.initErr != nil {
		return nil, r.initErr
	}

	msg := query.Copy()
	if r.ecsConfig != nil {
		if err := r.ecsConfig.ApplyToQuery(msg); err != nil {
			return nil, err
		}
	}

	return r.Resolver.Resolve(msg, depth-1)
}

func init() {
	if err := resolver.RegisterResolver(&descriptor.Descriptor{
		Type: typeOfResolver,
		Filler: descriptor.Fillers{
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
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"EcsMode"},
				ValueSource: descriptor.ValueSources{
					descriptor.ObjectAtPath{
						ObjectPath: descriptor.Path{"ecsMode"},
						AssignableKind: descriptor.ConvertibleKind{
							Kind: descriptor.KindString,
							ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
								str, ok := original.(string)
								if !ok {
									return
								}
								if !ednsecs.ValidateMode(str) {
									return nil, false
								}
								return str, true
							},
						},
					},
					descriptor.DefaultValue{Value: ""},
				},
			},
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"EcsClientSubnet"},
				ValueSource: descriptor.ValueSources{
					descriptor.ObjectAtPath{
						ObjectPath: descriptor.Path{"ecsClientSubnet"},
						AssignableKind: descriptor.ConvertibleKind{
							Kind: descriptor.KindString,
							ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
								str, ok := original.(string)
								if !ok {
									return
								}
								if str == "" {
									return str, true
								}
								if _, _, err := ednsecs.ParseClientSubnet(str); err != nil {
									return nil, false
								}
								return str, true
							},
						},
					},
					descriptor.DefaultValue{Value: ""},
				},
			},
		},
	}); err != nil {
		common.ErrOutput(err)
	}
}

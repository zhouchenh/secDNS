package sequence

import (
	"github.com/miekg/dns"
	"github.com/zhouchenh/go-descriptor"
	"github.com/zhouchenh/secDNS/internal/common"
	"github.com/zhouchenh/secDNS/pkg/upstream/resolver"
)

type Sequence []resolver.Resolver

var typeOfSequence = descriptor.TypeOfNew(new(*Sequence))

func (seq *Sequence) Type() descriptor.Type {
	return typeOfSequence
}

func (seq *Sequence) TypeName() string {
	return "sequence"
}

func (seq *Sequence) Resolve(query *dns.Msg, depth int) (*dns.Msg, error) {
	if depth < 0 {
		return nil, resolver.ErrLoopDetected
	}
	if len(*seq) < 1 {
		return nil, ErrNoAvailableResolver
	}
	var msg *dns.Msg
	var err error
	for _, r := range *seq {
		if r == nil {
			err = ErrNilResolver
			continue
		}
		msg, err = r.Resolve(query, depth-1)
		if err != nil {
			continue
		}
		break
	}
	return msg, err
}

func init() {
	if err := resolver.RegisterResolver(&descriptor.Descriptor{
		Type: typeOfSequence,
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
						var resolvers []resolver.Resolver
						for _, i := range interfaces {
							rawResolver, s, f := resolver.Descriptor().Describe(i)
							ok := s > 0 && f < 1
							if !ok {
								continue
							}
							r, ok := rawResolver.(resolver.Resolver)
							if !ok {
								continue
							}
							resolvers = append(resolvers, r)
						}
						return descriptor.PointerOf(Sequence(resolvers)), true
					},
				},
			},
		},
	}); err != nil {
		common.ErrOutput(err)
	}
}

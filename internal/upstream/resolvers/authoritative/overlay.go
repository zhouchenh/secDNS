package authoritative

import (
	"strconv"
	"strings"

	"github.com/miekg/dns"
	"github.com/zhouchenh/go-descriptor"
	"github.com/zhouchenh/secDNS/internal/common"
	"github.com/zhouchenh/secDNS/internal/recordstore"
	"github.com/zhouchenh/secDNS/pkg/upstream/resolver"
)

// ExactStoreOverlay answers owners present in one immutable exact-store view
// and otherwise delegates once to the already selected ordinary resolver graph.
// It never creates a legacy store or changes source-policy selection.
type ExactStoreOverlay struct {
	Store         string
	CompleteCNAME bool
	NegativeTTL   uint32
	Fallback      resolver.Resolver
}

var typeOfExactStoreOverlay = descriptor.TypeOfNew(new(*ExactStoreOverlay))

func (o *ExactStoreOverlay) Type() descriptor.Type { return typeOfExactStoreOverlay }
func (o *ExactStoreOverlay) TypeName() string      { return "exactStoreOverlay" }

func (o *ExactStoreOverlay) ResolverDependencies() []resolver.Resolver {
	return []resolver.Resolver{o.Fallback}
}

func (o *ExactStoreOverlay) Resolve(query *dns.Msg, depth int) (*dns.Msg, error) {
	if depth < 0 {
		return nil, resolver.ErrLoopDetected
	}
	if query == nil {
		return nil, resolver.ErrNilQuery
	}
	if len(query.Question) == 0 {
		return nil, resolver.ErrNotSupportedQuestion
	}
	view, err := recordstore.AcquireExactView(o.Store)
	if err != nil {
		return serverFailure(query), nil
	}
	return o.resolveView(query, depth, view), nil
}

func (o *ExactStoreOverlay) resolveView(query *dns.Msg, depth int, view exactLookupView) *dns.Msg {
	reader := viewReader{view: view}
	if !reader.HasName(query.Question[0].Name) {
		if o.Fallback == nil {
			return serverFailure(query)
		}
		reply, fallbackErr := o.Fallback.Resolve(query, depth-1)
		if fallbackErr != nil || reply == nil || !reply.Response {
			return serverFailure(query)
		}
		return reply
	}
	negativeTTL := o.NegativeTTL
	if negativeTTL == 0 {
		negativeTTL = 60
	}
	authority := &Authoritative{CompleteCNAME: o.CompleteCNAME, NegativeTTL: negativeTTL}
	return authority.resolveFromReader(query, depth, reader)
}

func resolverValue(original interface{}) (interface{}, bool) {
	object, successes, failures := resolver.Descriptor().Describe(original)
	return object, successes > 0 && failures == 0
}

func init() {
	if err := resolver.RegisterResolver(&descriptor.Descriptor{
		Type: typeOfExactStoreOverlay,
		Filler: descriptor.Fillers{
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"Store"},
				ValueSource: descriptor.ObjectAtPath{
					ObjectPath: descriptor.Path{"store"},
					AssignableKind: descriptor.ConvertibleKind{Kind: descriptor.KindString, ConvertFunction: func(original interface{}) (interface{}, bool) {
						value, ok := original.(string)
						return value, ok && value != "" && strings.TrimSpace(value) == value
					}},
				},
			},
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"CompleteCNAME"},
				ValueSource: descriptor.ValueSources{
					descriptor.ObjectAtPath{ObjectPath: descriptor.Path{"completeCNAME"}, AssignableKind: descriptor.KindBool},
					descriptor.DefaultValue{Value: false},
				},
			},
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"NegativeTTL"},
				ValueSource: descriptor.ValueSources{
					descriptor.ObjectAtPath{ObjectPath: descriptor.Path{"negativeTTL"}, AssignableKind: descriptor.AssignableKinds{
						descriptor.ConvertibleKind{Kind: descriptor.KindFloat64, ConvertFunction: func(original interface{}) (interface{}, bool) {
							value := int(original.(float64))
							if value < 0 || value > 2147483647 {
								return nil, false
							}
							return uint32(value), true
						}},
						descriptor.ConvertibleKind{Kind: descriptor.KindString, ConvertFunction: func(original interface{}) (interface{}, bool) {
							value, err := strconv.Atoi(strings.TrimSpace(original.(string)))
							if err != nil || value < 0 || value > 2147483647 {
								return nil, false
							}
							return uint32(value), true
						}},
					}},
					descriptor.DefaultValue{Value: uint32(60)},
				},
			},
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"Fallback"},
				ValueSource: descriptor.ObjectAtPath{
					ObjectPath:     descriptor.Path{"fallback"},
					AssignableKind: descriptor.AssignmentFunction(resolverValue),
				},
			},
		},
	}); err != nil {
		common.ErrOutput(err)
	}
}

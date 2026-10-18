package address

import (
	"math"
	"net"

	"github.com/miekg/dns"
	"github.com/zhouchenh/go-descriptor"
	"github.com/zhouchenh/secDNS/internal/common"
	"github.com/zhouchenh/secDNS/pkg/upstream/resolver"
)

const (
	v4 = 0
	v6 = 1
)

const defaultTTL uint32 = 60

// Address answers A and AAAA questions from configured static addresses. TTL is a
// pointer so an omitted value can retain the historical 60-second default while an
// explicitly configured zero remains meaningful.
type Address struct {
	Addresses   [2][]net.IP
	TTL         *uint32
	Fallthrough bool
}

var typeOfAddress = descriptor.TypeOfNew(new(*Address))

func (addr *Address) Type() descriptor.Type {
	return typeOfAddress
}

func (addr *Address) TypeName() string {
	return "address"
}

func makeAddress() Address {
	return Address{}
}

func (addr *Address) responseTTL() uint32 {
	if addr.TTL == nil {
		return defaultTTL
	}
	return *addr.TTL
}

func (addr *Address) Resolve(query *dns.Msg, depth int) (*dns.Msg, error) {
	if depth < 0 {
		return nil, resolver.ErrLoopDetected
	}
	var addresses []net.IP
	switch query.Question[0].Qtype {
	case dns.TypeA:
		addresses = addr.Addresses[v4]
	case dns.TypeAAAA:
		addresses = addr.Addresses[v6]
	default:
		if addr.Fallthrough {
			return nil, resolver.ErrNotSupportedQuestion
		}
	}
	if len(addresses) == 0 && addr.Fallthrough {
		return nil, resolver.ErrNotSupportedQuestion
	}

	msg := new(dns.Msg)
	msg.SetReply(query)
	ttl := addr.responseTTL()
	switch query.Question[0].Qtype {
	case dns.TypeA:
		for _, ip := range addresses {
			msg.Answer = append(msg.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
				A:   ip,
			})
		}
	case dns.TypeAAAA:
		for _, ip := range addresses {
			msg.Answer = append(msg.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl},
				AAAA: ip,
			})
		}
	}
	return msg, nil
}

func parseAddressValue(original interface{}, strict bool) (converted interface{}, ok bool) {
	address := makeAddress()
	appendAddress := func(value interface{}) bool {
		str, ok := value.(string)
		if !ok {
			return false
		}
		ip := common.ParseIPv4v6(str)
		if ip == nil {
			return false
		}
		switch len(ip) {
		case net.IPv4len:
			address.Addresses[v4] = append(address.Addresses[v4], ip)
		case net.IPv6len:
			address.Addresses[v6] = append(address.Addresses[v6], ip)
		default:
			return false
		}
		return true
	}

	switch value := original.(type) {
	case string:
		if !appendAddress(value) {
			return nil, false
		}
	case []interface{}:
		if strict && len(value) == 0 {
			return nil, false
		}
		for _, item := range value {
			if !appendAddress(item) && strict {
				return nil, false
			}
		}
	default:
		return nil, false
	}
	return address.Addresses, true
}

func addressKinds(strict bool) descriptor.AssignableKinds {
	return descriptor.AssignableKinds{
		descriptor.ConvertibleKind{
			Kind: descriptor.KindString,
			ConvertFunction: func(original interface{}) (interface{}, bool) {
				return parseAddressValue(original, strict)
			},
		},
		descriptor.ConvertibleKind{
			Kind: descriptor.KindSlice,
			ConvertFunction: func(original interface{}) (interface{}, bool) {
				return parseAddressValue(original, strict)
			},
		},
	}
}

func ttlValue(original interface{}) (interface{}, bool) {
	value, ok := original.(float64)
	if !ok || math.IsNaN(value) || math.IsInf(value, 0) || value < 0 || value > math.MaxUint32 || math.Trunc(value) != value {
		return nil, false
	}
	ttl := uint32(value)
	return &ttl, true
}

func optionalTTL(data interface{}) (interface{}, bool) {
	object, isObject := data.(map[string]interface{})
	if !isObject {
		return nil, true
	}
	raw, present := object["ttl"]
	if !present {
		return nil, true
	}
	return ttlValue(raw)
}

func optionalFallthrough(data interface{}) (interface{}, bool) {
	object, isObject := data.(map[string]interface{})
	if !isObject {
		return false, true
	}
	raw, present := object["fallthrough"]
	if !present {
		return false, true
	}
	value, ok := raw.(bool)
	return value, ok
}

func init() {
	if err := resolver.RegisterResolver(&descriptor.Descriptor{
		Type: typeOfAddress,
		Filler: descriptor.Fillers{
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"Addresses"},
				ValueSource: descriptor.ValueSources{
					descriptor.ObjectAtPath{ObjectPath: descriptor.Path{"addresses"}, AssignableKind: addressKinds(true)},
					descriptor.ObjectAtPath{ObjectPath: descriptor.Root, AssignableKind: addressKinds(false)},
				},
			},
			descriptor.ObjectFiller{
				ObjectPath:  descriptor.Path{"TTL"},
				ValueSource: descriptor.ValueGenerator(optionalTTL),
			},
			descriptor.ObjectFiller{
				ObjectPath:  descriptor.Path{"Fallthrough"},
				ValueSource: descriptor.ValueGenerator(optionalFallthrough),
			},
		},
	}); err != nil {
		common.ErrOutput(err)
	}
}

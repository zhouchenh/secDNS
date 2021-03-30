package address

import (
	"github.com/miekg/dns"
	"github.com/zhouchenh/go-descriptor"
	"github.com/zhouchenh/secDNS/pkg/common"
	"github.com/zhouchenh/secDNS/pkg/upstream/resolver"
	"net"
)

type Address net.IP

var typeOfAddress = descriptor.TypeOfNew(new(*Address))

func (addr *Address) Type() descriptor.Type {
	return typeOfAddress
}

func (addr *Address) TypeName() string {
	return "address"
}

func (addr *Address) Resolve(query *dns.Msg, depth int) (*dns.Msg, error) {
	if depth < 0 {
		return nil, resolver.ErrLoopDetected
	}
	msg := new(dns.Msg)
	msg.SetReply(query)
	switch query.Question[0].Qtype {
	case dns.TypeA:
		ip := net.IP(*addr)
		if ip = ip.To4(); ip != nil {
			msg.Answer = append(msg.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   ip,
			})
		}
	case dns.TypeAAAA:
		ip := net.IP(*addr)
		if len(ip) == net.IPv6len {
			msg.Answer = append(msg.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   ip,
			})
		}
	}
	return msg, nil
}

func init() {
	if err := resolver.RegisterResolver(&descriptor.Descriptor{
		Type: typeOfAddress,
		Filler: descriptor.ObjectFiller{
			ValueSource: descriptor.ObjectAtPath{
				ObjectPath: descriptor.Root,
				AssignableKind: descriptor.ConvertibleKind{
					Kind: descriptor.KindString,
					ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
						str, ok := original.(string)
						if !ok {
							return
						}
						converted = descriptor.PointerOf(Address(net.ParseIP(str)))
						ok = converted != nil
						return
					},
				},
			},
		},
	}); err != nil {
		common.ErrOutput(err)
	}
}

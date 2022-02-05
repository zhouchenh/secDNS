package address

import (
	"github.com/miekg/dns"
	"github.com/zhouchenh/go-descriptor"
	"github.com/zhouchenh/secDNS/internal/common"
	"github.com/zhouchenh/secDNS/pkg/upstream/resolver"
	"net"
)

const (
	v4 = 0
	v6 = 1
)

type Address [2][]net.IP

var typeOfAddress = descriptor.TypeOfNew(new(*Address))

func (addr *Address) Type() descriptor.Type {
	return typeOfAddress
}

func (addr *Address) TypeName() string {
	return "address"
}

func makeAddress() Address {
	var v4AddrList []net.IP
	var v6AddrList []net.IP
	var addrLists [2][]net.IP
	addrLists[v4] = v4AddrList
	addrLists[v6] = v6AddrList
	return addrLists
}

func (addr *Address) Resolve(query *dns.Msg, depth int) (*dns.Msg, error) {
	if depth < 0 {
		return nil, resolver.ErrLoopDetected
	}
	msg := new(dns.Msg)
	msg.SetReply(query)
	switch query.Question[0].Qtype {
	case dns.TypeA:
		for _, ip := range addr[v4] {
			msg.Answer = append(msg.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   ip,
			})
		}
	case dns.TypeAAAA:
		for _, ip := range addr[v6] {
			msg.Answer = append(msg.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
				AAAA: ip,
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
				AssignableKind: descriptor.AssignableKinds{
					descriptor.ConvertibleKind{
						Kind: descriptor.KindString,
						ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
							var str string
							str, ok = original.(string)
							if !ok {
								return
							}
							ip := common.ParseIPv4v6(str)
							ok = ip != nil
							if !ok {
								return
							}
							address := makeAddress()
							switch len(ip) {
							case net.IPv4len:
								address[v4] = append(address[v4], ip)
							case net.IPv6len:
								address[v6] = append(address[v6], ip)
							default:
								return nil, false
							}
							converted = &address
							return
						},
					},
					descriptor.ConvertibleKind{
						Kind: descriptor.KindSlice,
						ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
							interfaces, ok := original.([]interface{})
							if !ok {
								return
							}
							address := makeAddress()
							for _, i := range interfaces {
								str, ok := i.(string)
								if !ok {
									continue
								}
								ip := common.ParseIPv4v6(str)
								ok = ip != nil
								if !ok {
									continue
								}
								switch len(ip) {
								case net.IPv4len:
									address[v4] = append(address[v4], ip)
								case net.IPv6len:
									address[v6] = append(address[v6], ip)
								default:
									continue
								}
							}
							return &address, true
						},
					},
				},
			},
		},
	}); err != nil {
		common.ErrOutput(err)
	}
}

package dns64

import (
	"github.com/miekg/dns"
	"github.com/zhouchenh/go-descriptor"
	"github.com/zhouchenh/secDNS/internal/common"
	"github.com/zhouchenh/secDNS/pkg/upstream/resolver"
	"net"
)

type DNS64 struct {
	Resolver           resolver.Resolver
	Prefix             net.IP
	IgnoreExistingAAAA bool
}

var typeOfDNS64 = descriptor.TypeOfNew(new(*DNS64))

func (d *DNS64) Type() descriptor.Type {
	return typeOfDNS64
}

func (d *DNS64) TypeName() string {
	return "dns64"
}

func (d *DNS64) Resolve(query *dns.Msg, depth int) (*dns.Msg, error) {
	if depth < 0 {
		return nil, resolver.ErrLoopDetected
	}
	switch qType := query.Question[0].Qtype; qType {
	case dns.TypeAAAA:
		if d.IgnoreExistingAAAA {
			return d.dns64(query, depth)
		} else {
			reply, err := d.Resolver.Resolve(query, depth-1)
			if err != nil || !isNoErrorReply(reply) || !hasAAAA(reply) {
				return d.dns64(query, depth)
			}
			return reply, nil
		}
	default:
		return d.Resolver.Resolve(query, depth-1)
	}
}

func (d *DNS64) dns64(query *dns.Msg, depth int) (*dns.Msg, error) {
	query.Question[0].Qtype = dns.TypeA
	reply, err := d.Resolver.Resolve(query, depth-1)
	query.Question[0].Qtype = dns.TypeAAAA
	if err != nil {
		return nil, err
	}
	reply.Question[0].Qtype = dns.TypeAAAA
	if isNoErrorReply(reply) {
		for i := range reply.Answer {
			if a, ok := reply.Answer[i].(*dns.A); ok {
				reply.Answer[i] = d.aToAAAA(a)
			}
		}
	}
	return reply, nil
}

func (d *DNS64) aToAAAA(a *dns.A) *dns.AAAA {
	return &dns.AAAA{
		Hdr: dns.RR_Header{
			Name:   a.Hdr.Name,
			Rrtype: dns.TypeAAAA,
			Class:  a.Hdr.Class,
			Ttl:    a.Hdr.Ttl,
		},
		AAAA: d.ipv4ToIPv6(a.A),
	}
}

func (d *DNS64) ipv4ToIPv6(ipv4 net.IP) net.IP {
	ipv6 := make(net.IP, net.IPv6len)
	copy(ipv6, d.Prefix[0:12])
	copy(ipv6[12:16], ipv4.To4())
	return ipv6
}

func isNoErrorReply(reply *dns.Msg) bool {
	return reply != nil && reply.Response && reply.Rcode == dns.RcodeSuccess
}

func hasAAAA(reply *dns.Msg) bool {
	for _, rr := range reply.Answer {
		if _, ok := rr.(*dns.AAAA); ok {
			return true
		}
	}
	return false
}

func init() {
	if err := resolver.RegisterResolver(&descriptor.Descriptor{
		Type: typeOfDNS64,
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
				ObjectPath: descriptor.Path{"Prefix"},
				ValueSource: descriptor.ValueSources{
					descriptor.ObjectAtPath{
						ObjectPath: descriptor.Path{"prefix"},
						AssignableKind: descriptor.ConvertibleKind{
							Kind: descriptor.KindString,
							ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
								var str string
								str, ok = original.(string)
								if !ok {
									return
								}
								ip := common.ParseIPv4v6(str)
								if ok = ip != nil && len(ip) == net.IPv6len; !ok {
									return
								}
								converted = ip
								return
							},
						},
					},
					descriptor.DefaultValue{Value: net.IP{0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
				},
			},
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"IgnoreExistingAAAA"},
				ValueSource: descriptor.ValueSources{
					descriptor.ObjectAtPath{
						ObjectPath: descriptor.Path{"ignoreExistingAAAA"},
						AssignableKind: descriptor.AssignableKinds{
							descriptor.KindBool,
							descriptor.ConvertibleKind{
								Kind: descriptor.KindString,
								ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
									str, ok := original.(string)
									if !ok {
										return
									}
									switch str {
									case "true":
										return true, true
									case "false":
										return false, true
									default:
										return
									}
								},
							},
						},
					},
					descriptor.DefaultValue{Value: false},
				},
			},
		},
	}); err != nil {
		common.ErrOutput(err)
	}
}

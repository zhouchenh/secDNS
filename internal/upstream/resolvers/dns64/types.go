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
	if len(query.Question) == 0 {
		return nil, resolver.ErrNotSupportedQuestion
	}
	if query.Question[0].Qtype != dns.TypeAAAA {
		return d.Resolver.Resolve(query, depth-1)
	}
	if d.IgnoreExistingAAAA {
		return d.synthesize(query, depth)
	}
	reply, err := d.Resolver.Resolve(query, depth-1)
	if err != nil {
		return nil, err
	}
	// Only synthesize on an authoritative "no AAAA records" answer (NOERROR with no
	// AAAA). SERVFAIL/REFUSED/NXDOMAIN and existing AAAA are returned unchanged, so
	// DNS64 never masks an upstream or DNSSEC failure with a synthesized address.
	if reply == nil || !isNoErrorReply(reply) || hasAAAA(reply) {
		return reply, nil
	}
	return d.synthesize(query, depth)
}

// synthesize resolves the A records for the query name and rewrites them as AAAA
// records under the DNS64 prefix. It operates on copies so neither the caller's
// query nor the upstream resolver's response is mutated.
func (d *DNS64) synthesize(query *dns.Msg, depth int) (*dns.Msg, error) {
	aQuery := query.Copy()
	aQuery.Question[0].Qtype = dns.TypeA
	reply, err := d.Resolver.Resolve(aQuery, depth-1)
	if err != nil {
		return nil, err
	}
	if reply == nil {
		return nil, nil
	}
	out := reply.Copy()
	if len(out.Question) > 0 {
		out.Question[0].Qtype = dns.TypeAAAA
	}
	if isNoErrorReply(out) {
		// Rewrite A records as synthesized AAAA and drop the A RRset's signatures:
		// those RRSIGs cover the A records, not the synthesized AAAA, and synthesized
		// data cannot be DNSSEC-authenticated (RFC 6147 section 5.5).
		filtered := out.Answer[:0]
		for _, rr := range out.Answer {
			switch v := rr.(type) {
			case *dns.A:
				filtered = append(filtered, d.aToAAAA(v))
			case *dns.RRSIG:
				// drop signatures over the original A RRset
			default:
				filtered = append(filtered, rr)
			}
		}
		out.Answer = filtered
	}
	// Never advertise DNSSEC authentication for a synthesized response.
	out.AuthenticatedData = false
	return out, nil
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

func (d *DNS64) NameServerResolver() {}

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

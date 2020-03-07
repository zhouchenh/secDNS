package alias

import (
	"common"
	"github.com/miekg/dns"
	"github.com/zhouchenh/go-descriptor"
	"upstream/resolver"
)

type Alias struct {
	Alias    string
	Resolver resolver.Resolver
}

var typeOfAlias = descriptor.TypeOfNew(new(*Alias))

func (alias *Alias) Type() descriptor.Type {
	return typeOfAlias
}

func (alias *Alias) TypeName() string {
	return "alias"
}

func (alias *Alias) Resolve(query *dns.Msg, depth int) (*dns.Msg, error) {
	if depth < 0 {
		return nil, resolver.ErrLoopDetected
	}
	if alias.Alias == query.Question[0].Name {
		return nil, ErrAliasSameAsName
	}
	msg := new(dns.Msg)
	msg.SetReply(query)
	switch qType := query.Question[0].Qtype; qType {
	case dns.TypeCNAME, dns.TypeA, dns.TypeAAAA:
		msg.Answer = append(msg.Answer, &dns.CNAME{
			Hdr:    dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
			Target: alias.Alias,
		})
		switch qType {
		case dns.TypeA, dns.TypeAAAA:
			q := new(dns.Msg)
			q.SetQuestion(alias.Alias, qType)
			r, err := alias.Resolver.Resolve(q, depth-1)
			if err != nil {
				return nil, err
			}
			msg.Answer = append(msg.Answer, r.Answer...)
		}
	}
	return msg, nil
}

func init() {
	if err := resolver.RegisterResolver(&descriptor.Descriptor{
		Type: typeOfAlias,
		Filler: descriptor.Fillers{
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"Alias"},
				ValueSource: descriptor.ObjectAtPath{
					ObjectPath: descriptor.Root,
					AssignableKind: descriptor.ConvertibleKind{
						Kind: descriptor.KindString,
						ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
							str, ok := original.(string)
							if !ok {
								return
							}
							if ok = common.IsDomainName(str); !ok {
								return
							}
							return common.EnsureFQDN(str), true
						},
					},
				},
			},
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"Resolver"},
				ValueSource: descriptor.ObjectAtPath{
					ObjectPath: descriptor.Root,
					AssignableKind: descriptor.AssignmentFunction(func(interface{}) (object interface{}, ok bool) {
						object, s, f := resolver.Descriptor().Describe("")
						ok = s > 0 && f < 1
						return
					}),
				},
			},
		},
	}); err != nil {
		common.ErrOutput(err)
	}
}

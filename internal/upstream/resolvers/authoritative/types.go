// Package authoritative implements a resolver that answers from a process-local
// recordstore.Store instead of forwarding upstream. Names routed to it (via rules)
// return the store's records; unknown names get NXDOMAIN, known names without the
// queried type get NODATA, each with a synthesized SOA in the authority section for
// negative caching. The store is populated out of band — typically by the admin API —
// and shared by name, so a resolver and an admin listener configured with the same
// store name operate on one record set.
package authoritative

import (
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"github.com/zhouchenh/go-descriptor"
	"github.com/zhouchenh/secDNS/internal/common"
	"github.com/zhouchenh/secDNS/internal/recordstore"
	"github.com/zhouchenh/secDNS/pkg/upstream/resolver"
)

// Authoritative answers from a shared record store. DNSSEC signing, zone transfer, and
// dynamic DNS updates are out of scope; answers are unsigned (Insecure).
type Authoritative struct {
	Store       string // shared store name; empty joins recordstore.DefaultName
	NegativeTTL uint32 // SOA TTL / MINTTL for NXDOMAIN and NODATA answers

	initOnce sync.Once
	store    *recordstore.Store
}

var typeOfAuthoritative = descriptor.TypeOfNew(new(*Authoritative))

func (a *Authoritative) Type() descriptor.Type {
	return typeOfAuthoritative
}

func (a *Authoritative) TypeName() string {
	return "authoritative"
}

func (a *Authoritative) init() {
	a.store = recordstore.GetOrCreate(a.Store)
	if a.NegativeTTL == 0 {
		a.NegativeTTL = 60
	}
}

func (a *Authoritative) Resolve(query *dns.Msg, depth int) (*dns.Msg, error) {
	if depth < 0 {
		return nil, resolver.ErrLoopDetected
	}
	if query == nil {
		return nil, resolver.ErrNilQuery
	}
	if len(query.Question) == 0 {
		return nil, resolver.ErrNotSupportedQuestion
	}
	a.initOnce.Do(a.init)

	q := query.Question[0]
	resp := new(dns.Msg)
	resp.SetReply(query)
	resp.Authoritative = true

	// Exact {name, type} hit.
	if rec, ok := a.store.Get(q.Name, q.Qtype); ok {
		resp.Answer = append(resp.Answer, recordToRRs(rec, q.Name, q.Qclass)...)
		return resp, nil
	}
	// A CNAME at the name answers any other type (the requester re-queries the target).
	if q.Qtype != dns.TypeCNAME {
		if cn, ok := a.store.Get(q.Name, dns.TypeCNAME); ok {
			resp.Answer = append(resp.Answer, recordToRRs(cn, q.Name, q.Qclass)...)
			return resp, nil
		}
	}
	// No matching record: NODATA when the name exists for another type, else NXDOMAIN.
	if a.store.HasName(q.Name) {
		resp.Rcode = dns.RcodeSuccess
	} else {
		resp.Rcode = dns.RcodeNameError
	}
	resp.Ns = append(resp.Ns, a.soa(q.Name))
	return resp, nil
}

// recordToRRs renders a stored record as resource records owned by the queried name.
// Malformed values (e.g. an unparseable IP) are skipped rather than served.
func recordToRRs(rec recordstore.Record, owner string, qclass uint16) []dns.RR {
	hdr := func(rrtype uint16) dns.RR_Header {
		return dns.RR_Header{Name: owner, Rrtype: rrtype, Class: qclass, Ttl: rec.TTL}
	}
	var out []dns.RR
	switch rec.Type {
	case dns.TypeA:
		for _, v := range rec.Values {
			if ip := net.ParseIP(strings.TrimSpace(v)); ip != nil && ip.To4() != nil {
				out = append(out, &dns.A{Hdr: hdr(dns.TypeA), A: ip.To4()})
			}
		}
	case dns.TypeAAAA:
		for _, v := range rec.Values {
			ip := net.ParseIP(strings.TrimSpace(v))
			if ip != nil && ip.To4() == nil && ip.To16() != nil {
				out = append(out, &dns.AAAA{Hdr: hdr(dns.TypeAAAA), AAAA: ip.To16()})
			}
		}
	case dns.TypeCNAME:
		if len(rec.Values) > 0 {
			out = append(out, &dns.CNAME{Hdr: hdr(dns.TypeCNAME), Target: dns.Fqdn(rec.Values[0])})
		}
	case dns.TypeTXT:
		out = append(out, &dns.TXT{Hdr: hdr(dns.TypeTXT), Txt: append([]string(nil), rec.Values...)})
	}
	return out
}

// soa synthesizes the authority-section SOA for a negative answer. The owner is the
// queried name (the resolver does not track a true zone apex), and the reserved
// .invalid. TLD (RFC 6761) is used for the placeholder mname/rname; the MINTTL drives
// the downstream negative cache.
func (a *Authoritative) soa(owner string) *dns.SOA {
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: owner, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: a.NegativeTTL},
		Ns:      "ns.invalid.",
		Mbox:    "hostmaster.invalid.",
		Serial:  1,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minttl:  a.NegativeTTL,
	}
}

func init() {
	if err := resolver.RegisterResolver(&descriptor.Descriptor{
		Type: typeOfAuthoritative,
		Filler: descriptor.Fillers{
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"Store"},
				ValueSource: descriptor.ValueSources{
					descriptor.ObjectAtPath{
						ObjectPath:     descriptor.Path{"store"},
						AssignableKind: descriptor.KindString,
					},
					descriptor.DefaultValue{Value: ""},
				},
			},
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"NegativeTTL"},
				ValueSource: descriptor.ValueSources{
					descriptor.ObjectAtPath{
						ObjectPath: descriptor.Path{"negativeTTL"},
						AssignableKind: descriptor.AssignableKinds{
							descriptor.ConvertibleKind{
								Kind: descriptor.KindFloat64,
								ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
									v := int(original.(float64))
									if v < 0 || v > 2147483647 {
										return nil, false
									}
									return uint32(v), true
								},
							},
							descriptor.ConvertibleKind{
								Kind: descriptor.KindString,
								ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
									v, err := strconv.Atoi(strings.TrimSpace(original.(string)))
									if err != nil || v < 0 || v > 2147483647 {
										return nil, false
									}
									return uint32(v), true
								},
							},
						},
					},
					descriptor.DefaultValue{Value: uint32(60)},
				},
			},
		},
	}); err != nil {
		common.ErrOutput(err)
	}
}

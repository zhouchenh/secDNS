package authoritative

import (
	"github.com/miekg/dns"
	"strings"
)

const maxCNAMEHops = 16

// resolveChain never consults another resolver. Malformed chains fail with a DNS
// response, not a Go error: core must not fall through to an upstream on failure.
func (a *Authoritative) resolveChain(query *dns.Msg, depth int) *dns.Msg {
	q := query.Question[0]
	resp := new(dns.Msg)
	resp.SetReply(query)
	resp.Authoritative = true
	fail := func() *dns.Msg {
		resp.Rcode = dns.RcodeServerFailure
		resp.Authoritative = false
		resp.Answer = nil
		resp.Ns = nil
		return resp
	}
	name := q.Name
	visited := make(map[string]bool)
	hops := 0
	for {
		canonical := dns.CanonicalName(name)
		if visited[canonical] {
			return fail()
		}
		visited[canonical] = true
		records := a.store.RecordsForName(name)
		cn, alias := records[dns.TypeCNAME]
		if alias {
			// A CNAME must have exactly one valid target and no coexisting RRsets.
			if len(records) != 1 || len(cn.Values) != 1 {
				return fail()
			}
			target := cn.Values[0]
			if target == "" || strings.TrimSpace(target) != target {
				return fail()
			}
			if _, valid := dns.IsDomainName(target); !valid {
				return fail()
			}
			if hops >= maxCNAMEHops || hops >= depth {
				return fail()
			}
			resp.Answer = append(resp.Answer, recordToRRs(cn, name, q.Qclass)...)
			name = dns.Fqdn(target)
			hops++
			continue
		}
		if rec, ok := records[q.Qtype]; ok {
			answers := recordToRRs(rec, name, q.Qclass)
			if len(answers) == 0 || len(answers) != len(rec.Values) {
				return fail()
			}
			resp.Answer = append(resp.Answer, answers...)
			return resp
		}
		if hops > 0 {
			// No zone boundary model exists. Preserve the chain without inventing
			// authoritative nonexistence for an absent target or target family.
			return resp
		}
		if len(records) == 0 {
			resp.Rcode = dns.RcodeNameError
		}
		resp.Ns = append(resp.Ns, a.soa(name))
		return resp
	}
}

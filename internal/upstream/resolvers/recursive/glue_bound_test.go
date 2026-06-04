package recursive

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// TestResolveGlueBoundsFanout verifies that out-of-band glue resolution is bounded: a
// referral with many glueless NS names chases at most maxGlueNamesChased of them, and a
// resolveGlue call with no remaining depth budget does not chase glue at all.
func TestResolveGlueBoundsFanout(t *testing.T) {
	root := net.ParseIP("192.0.2.53")
	newR := func() (*Recursive, *map[string]bool, *sync.Mutex) {
		var mu sync.Mutex
		queried := map[string]bool{}
		r := &Recursive{
			MaxDepth: 32, MaxReferrals: 16, EDNSSize: 1232,
			scoreboard: newScoreboard([]RootServer{{Addresses: []net.IP{root}}}, 5),
			glueCache:  make(map[string]glueCacheEntry),
		}
		r.exchangeFn = func(q *dns.Msg, ip net.IP) (*dns.Msg, time.Duration, error) {
			name := q.Question[0].Name
			mu.Lock()
			queried[name] = true
			mu.Unlock()
			resp := new(dns.Msg)
			resp.SetReply(q)
			resp.Rcode = dns.RcodeSuccess
			switch q.Question[0].Qtype {
			case dns.TypeA:
				resp.Answer = append(resp.Answer, &dns.A{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IP{1, 2, 3, 4}})
			case dns.TypeAAAA:
				resp.Answer = append(resp.Answer, &dns.AAAA{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60}, AAAA: net.ParseIP("2001:db8::1")})
			}
			return resp, time.Millisecond, nil
		}
		return r, &queried, &mu
	}

	var nsNames []string
	for i := 0; i < 20; i++ {
		nsNames = append(nsNames, fmt.Sprintf("ns%d.example.", i))
	}

	// Many glueless NS names, ample depth: only a bounded number are chased.
	r, queried, mu := newR()
	ips := r.resolveGlue(nsNames, new(dns.Msg), 10, nil)
	mu.Lock()
	n := len(*queried)
	mu.Unlock()
	if n > maxGlueNamesChased {
		t.Fatalf("resolveGlue chased %d distinct NS names, want <= %d", n, maxGlueNamesChased)
	}
	if len(ips) == 0 {
		t.Fatalf("expected some glue to be resolved")
	}

	// No remaining depth budget: glue is not chased at all.
	r, queried, mu = newR()
	_ = r.resolveGlue(nsNames, new(dns.Msg), 0, nil)
	mu.Lock()
	n = len(*queried)
	mu.Unlock()
	if n != 0 {
		t.Fatalf("resolveGlue at depth 0 must not chase glue, but queried %d names", n)
	}
}

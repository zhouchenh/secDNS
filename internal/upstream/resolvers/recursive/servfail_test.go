package recursive

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// TestResolveWithServersSkipsServfailSibling verifies that a SERVFAIL/FORMERR from one
// server does not short-circuit the sibling-server loop: a later server's NOERROR answer
// wins, and only an all-failed set surfaces the failure response.
func TestResolveWithServersSkipsServfailSibling(t *testing.T) {
	serverA := net.ParseIP("192.0.2.1") // SERVFAIL
	serverB := net.ParseIP("192.0.2.2") // NOERROR + answer

	newR := func() *Recursive {
		return &Recursive{
			MaxReferrals: 16,
			EDNSSize:     1232,
			scoreboard:   newScoreboard(nil, 5),
			glueCache:    make(map[string]glueCacheEntry),
		}
	}

	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)

	// Case 1: serverA (tried first) SERVFAILs, serverB answers -> must return the answer.
	r := newR()
	r.exchangeFn = func(q *dns.Msg, ip net.IP) (*dns.Msg, time.Duration, error) {
		resp := new(dns.Msg)
		resp.SetReply(q)
		if ip.Equal(serverA) {
			resp.Rcode = dns.RcodeServerFailure
			return resp, time.Millisecond, nil
		}
		resp.Rcode = dns.RcodeSuccess
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.IP{1, 2, 3, 4},
		})
		return resp, time.Millisecond, nil
	}
	out, err := r.resolveWithServers(query, []net.IP{serverA, serverB}, 10, 0, false, nil, r.newBudget())
	if err != nil {
		t.Fatalf("resolveWithServers error: %v", err)
	}
	if out.Rcode != dns.RcodeSuccess || len(out.Answer) != 1 {
		t.Fatalf("a SERVFAIL sibling short-circuited the loop: rcode=%d answers=%d", out.Rcode, len(out.Answer))
	}

	// Case 2: every server SERVFAILs -> surface a SERVFAIL response (not a synthetic error).
	r = newR()
	r.exchangeFn = func(q *dns.Msg, ip net.IP) (*dns.Msg, time.Duration, error) {
		resp := new(dns.Msg)
		resp.SetReply(q)
		resp.Rcode = dns.RcodeServerFailure
		return resp, time.Millisecond, nil
	}
	out, err = r.resolveWithServers(query, []net.IP{serverA, serverB}, 10, 0, false, nil, r.newBudget())
	if err != nil || out == nil || out.Rcode != dns.RcodeServerFailure {
		t.Fatalf("all-SERVFAIL should surface a SERVFAIL response: out=%v err=%v", out, err)
	}
}

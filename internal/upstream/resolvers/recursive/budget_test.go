package recursive

import (
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestQueryBudgetChargeCount(t *testing.T) {
	b := &queryBudget{remaining: 3, now: time.Now}
	for i := 0; i < 3; i++ {
		if err := b.charge(); err != nil {
			t.Fatalf("charge %d should succeed, got %v", i, err)
		}
	}
	if err := b.charge(); !errors.Is(err, ErrResolutionBudgetExceeded) {
		t.Fatalf("charge past the allowance should fail, got %v", err)
	}
}

func TestQueryBudgetDeadline(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	// Plenty of exchange allowance, but the deadline has already passed.
	b := &queryBudget{remaining: 1000, deadline: now.Add(-time.Second), now: func() time.Time { return now }}
	if err := b.charge(); !errors.Is(err, ErrResolutionBudgetExceeded) {
		t.Fatalf("an expired deadline should fail the charge, got %v", err)
	}

	// A zero deadline means no time limit.
	b2 := &queryBudget{remaining: 1, now: func() time.Time { return now }}
	if err := b2.charge(); err != nil {
		t.Fatalf("a zero deadline must not bound time, got %v", err)
	}
}

func TestQueryBudgetNilIsUnbudgeted(t *testing.T) {
	var b *queryBudget
	if err := b.charge(); err != nil {
		t.Fatalf("a nil budget must be unbudgeted, got %v", err)
	}
}

func TestNewBudgetRespectsConfig(t *testing.T) {
	// MaxResolutionTime 0 -> no deadline; MaxQueries carried through.
	r := &Recursive{MaxQueries: 42, MaxResolutionTime: 0}
	b := r.newBudget()
	if b.remaining != 42 {
		t.Fatalf("remaining = %d, want 42", b.remaining)
	}
	if !b.deadline.IsZero() {
		t.Fatalf("MaxResolutionTime 0 must leave the deadline unset")
	}

	// MaxResolutionTime > 0 -> deadline set in the future.
	r2 := &Recursive{MaxQueries: 5, MaxResolutionTime: time.Minute}
	b2 := r2.newBudget()
	if b2.deadline.IsZero() || !b2.deadline.After(time.Now()) {
		t.Fatalf("a positive MaxResolutionTime must set a future deadline")
	}

	// MaxQueries 0 -> falls back to the default (matches a directly-constructed resolver).
	r3 := &Recursive{}
	if got := r3.newBudget().remaining; got != defaultMaxQueries {
		t.Fatalf("unset MaxQueries should default to %d, got %d", defaultMaxQueries, got)
	}
}

// TestResolveWithServersBudgetCapsExchanges drives a resolver against an upstream that
// answers every query with a fresh in-band-glue referral — an endless delegation that
// the depth and referral limits are set high enough not to bind. The per-query budget
// must stop it at exactly MaxQueries exchanges and surface the budget error.
func TestResolveWithServersBudgetCapsExchanges(t *testing.T) {
	const maxQueries = 10
	var exchanges int
	r := &Recursive{
		MaxReferrals: 1000, // high, so the referral counter is not what binds
		MaxQueries:   maxQueries,
		EDNSSize:     1232,
		scoreboard:   newScoreboard(nil, 5),
		glueCache:    make(map[string]glueCacheEntry),
	}
	r.exchangeFn = func(q *dns.Msg, ip net.IP) (*dns.Msg, time.Duration, error) {
		exchanges++
		nsName := fmt.Sprintf("ns%d.sub.example.", exchanges)
		resp := new(dns.Msg)
		resp.SetReply(q)
		resp.Rcode = dns.RcodeSuccess
		resp.Ns = []dns.RR{&dns.NS{
			Hdr: dns.RR_Header{Name: "sub.example.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60},
			Ns:  nsName,
		}}
		resp.Extra = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: nsName, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.IPv4(10, 0, byte(exchanges>>8), byte(exchanges)),
		}}
		return resp, time.Millisecond, nil
	}

	query := new(dns.Msg)
	query.SetQuestion("deep.example.", dns.TypeA)
	_, err := r.resolveWithServers(query, []net.IP{net.IPv4(192, 0, 2, 1)}, 1000, 0, false, nil, r.newBudget())

	if !errors.Is(err, ErrResolutionBudgetExceeded) {
		t.Fatalf("an endless delegation should exhaust the budget, got %v", err)
	}
	if exchanges != maxQueries {
		t.Fatalf("budget allowed %d exchanges, want exactly %d", exchanges, maxQueries)
	}
}

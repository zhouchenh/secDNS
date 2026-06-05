package recursive

import (
	"errors"
	"time"
)

// defaultMaxQueries bounds the number of upstream exchanges a single client query may
// trigger across its whole iterative resolution tree when MaxQueries is unset. It is
// generous — a legitimate resolution, even a deep one with in-band glue and DNSSEC,
// rarely exceeds a few dozen exchanges — but finite, so a maliciously glueless or deep
// delegation cannot fan one query out into unbounded upstream traffic.
const defaultMaxQueries = 256

// defaultMaxResolutionTime is the wall-clock backstop for a single client query when
// MaxResolutionTime is unset. The per-exchange Timeout bounds one hop; this bounds the
// whole tree, so a chain of slow/timing-out servers cannot keep a resolution (and its
// goroutine) alive far longer than any client would wait. It is deliberately well above
// real resolution latency; set MaxResolutionTime to 0 to disable it.
const defaultMaxResolutionTime = 30 * time.Second

// ErrResolutionBudgetExceeded is returned when a single client query exhausts its
// per-query work budget (total upstream exchanges) or its wall-clock deadline. The
// depth budget caps how DEEP iterative resolution recurses, but not how WIDE — a
// referral can branch into a glue chase per nameserver, and each chase is itself a full
// resolution — so without a global cap one client query could fan out into unbounded
// upstream traffic. At the top of Resolve this surfaces as SERVFAIL.
var ErrResolutionBudgetExceeded = errors.New("recursive resolver: per-query resolution budget exceeded")

// queryBudget is the per-client-query work-and-time budget, shared across the whole
// iterative resolution tree: referrals, CNAME chases, and out-of-band glue chasing all
// draw from the same counter. It is created once per Resolve call and threaded through
// the resolution functions. A single query's resolution runs in one goroutine
// (resolveWithServers, resolveGlue, and followCNAME are all sequential — the recursive
// resolver never fans out into goroutines), so the counter needs no synchronization.
type queryBudget struct {
	remaining int              // upstream exchanges left before the budget is spent
	deadline  time.Time        // wall-clock cap; the zero time means no time limit
	now       func() time.Time // injectable clock (tests)
}

// charge accounts for one upstream exchange. It returns ErrResolutionBudgetExceeded
// when the deadline has passed or the exchange allowance is spent, and otherwise
// consumes one unit. A nil budget is treated as unbudgeted (defensive — the resolution
// paths always pass a real one).
func (b *queryBudget) charge() error {
	if b == nil {
		return nil
	}
	if !b.deadline.IsZero() && b.now().After(b.deadline) {
		return ErrResolutionBudgetExceeded
	}
	if b.remaining <= 0 {
		return ErrResolutionBudgetExceeded
	}
	b.remaining--
	return nil
}

// newBudget builds the per-query budget from the resolver's configured limits. It is
// called once per client query (and once per DNSKEY/DS validation fetch, which is
// bounded independently of the main query's tree).
func (r *Recursive) newBudget() *queryBudget {
	max := r.MaxQueries
	if max <= 0 {
		max = defaultMaxQueries
	}
	b := &queryBudget{remaining: max, now: time.Now}
	if r.MaxResolutionTime > 0 {
		b.deadline = b.now().Add(r.MaxResolutionTime)
	}
	return b
}

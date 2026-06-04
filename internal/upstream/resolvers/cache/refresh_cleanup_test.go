package cache

import (
	"container/heap"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/zhouchenh/go-descriptor"
)

// TestCleanupExpiredSkipsStaleHeapDuplicate guards the data-loss bug where a re-cache
// (refresh/prefetch) pushes a fresh heap item without removing the prior one, so a
// still-fresh entry could be deleted by cleanupExpired via the leftover stale item when
// ServeStale is off.
func TestCleanupExpiredSkipsStaleHeapDuplicate(t *testing.T) {
	c := &Cache{ServeStale: false}
	c.entries = make(map[string]*Entry)
	c.lru = NewLRUList()

	past := time.Now().Add(-time.Minute)
	future := time.Now().Add(time.Hour)

	// A refreshed entry: its current expiry is in the future, but a stale heap item
	// from a superseded (shorter) TTL still references it with a past expiry.
	fresh := &Entry{ExpiresAt: future, lruNode: c.lru.AddToFront("fresh")}
	c.entries["fresh"] = fresh
	heap.Push(&c.queue, expirationItem{key: "fresh", expiresAt: past})

	// A genuinely expired entry: the popped item's expiry matches the entry's expiry.
	dead := &Entry{ExpiresAt: past, lruNode: c.lru.AddToFront("dead")}
	c.entries["dead"] = dead
	heap.Push(&c.queue, expirationItem{key: "dead", expiresAt: past})

	c.cleanupExpired()

	if _, ok := c.entries["fresh"]; !ok {
		t.Fatalf("refreshed entry was wrongly deleted by a stale heap duplicate")
	}
	if _, ok := c.entries["dead"]; ok {
		t.Fatalf("genuinely expired entry should have been deleted")
	}
}

// gateResolver blocks inside Resolve until released, so a test can hold a refresh
// in flight and observe whether a second refresh is (incorrectly) started.
type gateResolver struct {
	mu      sync.Mutex
	calls   int
	entered chan struct{}
	release chan struct{}
}

func (g *gateResolver) Type() descriptor.Type { return descriptor.TypeOfNew(new(*gateResolver)) }
func (g *gateResolver) TypeName() string      { return "gate" }
func (g *gateResolver) NameServerResolver()   {}

func (g *gateResolver) Resolve(query *dns.Msg, depth int) (*dns.Msg, error) {
	g.mu.Lock()
	g.calls++
	g.mu.Unlock()
	g.entered <- struct{}{}
	<-g.release
	resp := new(dns.Msg)
	resp.SetReply(query)
	resp.Answer = append(resp.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   net.IP{1, 2, 3, 4},
	})
	return resp, nil
}

// TestTriggerRefreshBoundsToOnePerEntry verifies that serving stale for a hot name does
// not spawn a refresh goroutine per request: while one refresh is in flight, further
// triggerRefresh calls for the same entry are no-ops (gated by the prefetching CAS).
func TestTriggerRefreshBoundsToOnePerEntry(t *testing.T) {
	g := &gateResolver{entered: make(chan struct{}, 8), release: make(chan struct{})}
	c := &Cache{Resolver: g, MaxEntries: 16, CleanupInterval: time.Hour}
	c.initOnce.Do(c.init)
	defer c.Stop()

	q := new(dns.Msg)
	q.SetQuestion("example.org.", dns.TypeA)
	entry := &Entry{ExpiresAt: time.Now().Add(time.Hour)}

	// First refresh claims the flag and enters the (blocked) resolver.
	c.triggerRefresh("k", entry, q, 5)
	select {
	case <-g.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("first refresh did not start")
	}

	// Several more refreshes while the first is in flight must all be no-ops.
	for i := 0; i < 5; i++ {
		c.triggerRefresh("k", entry, q, 5)
	}
	select {
	case <-g.entered:
		t.Fatal("a second refresh started while one was already in flight")
	case <-time.After(150 * time.Millisecond):
	}

	close(g.release) // unblock the in-flight refresh

	// Wait for the flag to reset (refresh completed) without a fixed sleep race.
	deadline := time.Now().Add(2 * time.Second)
	for atomic.LoadUint32(&entry.prefetching) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("prefetching flag was not reset after refresh completed")
		}
		time.Sleep(5 * time.Millisecond)
	}

	g.mu.Lock()
	calls := g.calls
	g.mu.Unlock()
	if calls != 1 {
		t.Fatalf("expected exactly 1 upstream refresh call, got %d", calls)
	}
}

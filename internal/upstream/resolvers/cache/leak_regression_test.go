package cache

import (
	"container/heap"
	"fmt"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/zhouchenh/go-descriptor"
)

// echoResolver answers every A query with 192.0.2.1, TTL 1 s. No network.
type echoResolver struct{}

func (echoResolver) Type() descriptor.Type { return descriptor.TypeOfNew(new(*echoResolver)) }
func (echoResolver) TypeName() string      { return "echo" }
func (echoResolver) NameServerResolver()   {}
func (echoResolver) Resolve(q *dns.Msg, depth int) (*dns.Msg, error) {
	r := new(dns.Msg)
	r.SetReply(q)
	r.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1}, A: net.ParseIP("192.0.2.1")}}
	return r, nil
}

func fill(t *testing.T, c *Cache, n int, tag string) {
	for i := 0; i < n; i++ {
		q := new(dns.Msg)
		q.SetQuestion(fmt.Sprintf("secdnshealth%s%06d.1-1-1-1.sslip.io.", tag, i), dns.TypeA)
		if _, err := c.Resolve(q, 8); err != nil {
			t.Fatal(err)
		}
	}
}

// Leak A: with ServeStale on, an entry popped inside its stale window is skipped without being re-queued,
// so it is never swept again (stays until MaxEntries eviction).
func TestReproLeakA_StaleOrphans(t *testing.T) {
	c := &Cache{Resolver: echoResolver{}, MaxEntries: 100000, ServeStale: true, StaleDuration: 400 * time.Millisecond,
		CleanupInterval: time.Hour, PrefetchPercent: 1}
	defer c.Stop()
	const n = 1000
	fill(t, c, n, "a")
	time.Sleep(1100 * time.Millisecond) // expired, inside the 400 ms stale window
	c.cleanupExpired()
	time.Sleep(600 * time.Millisecond) // now past the stale window
	c.cleanupExpired()
	c.mutex.RLock()
	left, queued := len(c.entries), len(c.queue)
	c.mutex.RUnlock()
	t.Logf("entries after expiry+stale+2 sweeps: %d, queue items: %d", left, queued)
	if left != 0 {
		t.Errorf("LEAK A reproduced: %d of %d expired entries were never swept (queue has %d items)", left, n, queued)
	}
}

// Control: same sequence with ServeStale off sweeps everything.
func TestReproLeakA_ControlServeStaleOff(t *testing.T) {
	c := &Cache{Resolver: echoResolver{}, MaxEntries: 100000, ServeStale: false, CleanupInterval: time.Hour, PrefetchPercent: 1}
	defer c.Stop()
	fill(t, c, 1000, "c")
	time.Sleep(1100 * time.Millisecond)
	c.cleanupExpired()
	c.mutex.RLock()
	left := len(c.entries)
	c.mutex.RUnlock()
	if left != 0 {
		t.Errorf("control: %d entries left", left)
	}
}

// Leak B (regression form, valid on both trees): resolving many unique names into a small cache must not
// retain per-name state once the entries are gone. Old code keeps a domainStats key per name (~10 MB here).
func TestReproLeakB_HeapBounded(t *testing.T) {
	c := &Cache{Resolver: echoResolver{}, MaxEntries: 100, ServeStale: false, CleanupInterval: time.Hour, PrefetchPercent: 1}
	defer c.Stop()
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	const n = 50000
	fill(t, c, n, "b")
	time.Sleep(1100 * time.Millisecond)
	c.cleanupExpired()
	runtime.GC()
	runtime.ReadMemStats(&after)
	c.mutex.RLock()
	left := len(c.entries)
	c.mutex.RUnlock()
	delta := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	t.Logf("unique names %d, live entries %d, retained heap delta %.1f MiB", n, left, float64(delta)/(1<<20))
	runtime.KeepAlive(c)
	if delta > 2<<20 {
		t.Errorf("LEAK B: %.1f MiB retained after %d unique names with %d live entries", float64(delta)/(1<<20), n, left)
	}
}

// Review F3a: ServeStale with StaleDuration 0 means grace 0, so an expired item is swept on the first pass.
// (Via Resolve, init() normalises StaleDuration 0 to 30s; this exercises the cleanup arithmetic directly,
// the same way TestCleanupExpiredSkipsStaleHeapDuplicate does.)
func TestSweepGraceZeroWhenStaleDurationZero(t *testing.T) {
	c := &Cache{ServeStale: true, StaleDuration: 0}
	c.entries = make(map[string]*Entry)
	c.lru = NewLRUList()
	past := time.Now().Add(-10 * time.Millisecond)
	c.entries["k"] = &Entry{ExpiresAt: past, lruNode: c.lru.AddToFront("k")}
	heap.Push(&c.queue, expirationItem{key: "k", expiresAt: past})
	c.cleanupExpired()
	if _, ok := c.entries["k"]; ok {
		t.Fatalf("expired entry with zero stale grace was not swept")
	}
	if c.queue.Len() != 0 {
		t.Fatalf("queue not drained: %d", c.queue.Len())
	}
}

// Review F3a (documented default): through Resolve, a zero StaleDuration with ServeStale on becomes 30s.
func TestStaleDurationZeroDefaultsToThirtySeconds(t *testing.T) {
	c := &Cache{Resolver: echoResolver{}, MaxEntries: 10, ServeStale: true, CleanupInterval: time.Hour, PrefetchPercent: 1}
	defer c.Stop()
	fill(t, c, 1, "d")
	if c.StaleDuration != 30*time.Second {
		t.Fatalf("StaleDuration = %v, want 30s default", c.StaleDuration)
	}
}

// Fix A must not change stale serving: inside the window the entry is still served stale and not swept;
// after the window the sweep removes it (base code orphans it here). Deadlines are relative to the entry's own
// ExpiresAt with a 5 s window, so a slow scheduler has seconds of margin on both sides.
func TestServeStaleServedInsideWindowThenSwept(t *testing.T) {
	const window = 5 * time.Second
	c := &Cache{Resolver: echoResolver{}, MaxEntries: 10, ServeStale: true, StaleDuration: window,
		CleanupInterval: time.Hour, PrefetchPercent: 1}
	defer c.Stop()
	q := new(dns.Msg)
	q.SetQuestion("stale.example.", dns.TypeA)
	if _, err := c.Resolve(q, 8); err != nil {
		t.Fatal(err)
	}
	key := makeCacheKey(q)
	c.mutex.RLock()
	expires := c.entries[key].ExpiresAt
	c.mutex.RUnlock()

	time.Sleep(time.Until(expires.Add(500 * time.Millisecond))) // expired, 4.5 s before the window ends
	c.cleanupExpired()
	if since := time.Since(expires); since >= window {
		t.Skipf("scheduler overran the %v stale window (%v after expiry); cannot check stale serving", window, since)
	}
	if _, _, _, stale, found := c.get(key); !found || !stale {
		t.Fatalf("inside stale window: found=%v stale=%v, want served stale", found, stale)
	}

	time.Sleep(time.Until(expires.Add(window + time.Second))) // 1 s past the window
	c.cleanupExpired()
	c.mutex.RLock()
	_, still := c.entries[key]
	c.mutex.RUnlock()
	if still {
		t.Fatalf("entry still present after the stale window and a sweep")
	}
}

// Review F3b: concurrent Resolve (misses, hits, stale refreshes) and direct set() racing cleanupExpired.
// Run with -race. Afterwards, once everything is past TTL+grace, one sweep must leave no entries (no orphans).
func TestConcurrentResolveSetVsCleanup(t *testing.T) {
	c := &Cache{Resolver: echoResolver{}, MaxEntries: 100000, ServeStale: true, StaleDuration: 200 * time.Millisecond,
		CleanupInterval: time.Hour, PrefetchPercent: 1}
	defer c.Stop()
	fill(t, c, 1, "init")
	stop := make(chan struct{})
	var wg sync.WaitGroup
	var ops int64
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				q := new(dns.Msg)
				if i%4 == 0 {
					q.SetQuestion(fmt.Sprintf("hot%d.example.", i%7), dns.TypeA) // repeated: hits, stale, refresh
				} else {
					q.SetQuestion(fmt.Sprintf("w%d-%d.example.", w, i), dns.TypeA) // unique: misses
				}
				if w%2 == 0 && i%3 == 0 {
					r, _ := echoResolver{}.Resolve(q, 1)
					c.set(makeCacheKey(q), r)
				} else if _, err := c.Resolve(q, 8); err != nil {
					t.Error(err)
					return
				}
				atomic.AddInt64(&ops, 1)
			}
		}(w)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				c.cleanupExpired()
				time.Sleep(time.Millisecond)
			}
		}
	}()
	time.Sleep(1500 * time.Millisecond)
	close(stop)
	wg.Wait()
	time.Sleep(1500 * time.Millisecond) // past TTL 1s + grace 200ms for everything
	c.cleanupExpired()
	c.mutex.RLock()
	left, queued := len(c.entries), c.queue.Len()
	c.mutex.RUnlock()
	t.Logf("ops %d, entries left %d, queue %d", atomic.LoadInt64(&ops), left, queued)
	if left != 0 {
		t.Fatalf("%d entries left after all expired and a final sweep (orphans)", left)
	}
}

package cache

import (
	"testing"
	"time"
)

// TestExpirationHeapStaysBounded verifies that repeatedly re-caching keys does not grow
// the expiration heap without bound. Each re-cache pushes a fresh heap item without
// removing the prior one; pushExpiration rebuilds the heap once it exceeds ~2x the live
// entry count, so the heap stays bounded regardless of update frequency.
func TestExpirationHeapStaysBounded(t *testing.T) {
	mock := &mockResolver{response: aResponse("x.example.")}
	c := &Cache{Resolver: mock, MaxEntries: 1000, CleanupInterval: time.Hour}
	c.initOnce.Do(c.init)
	defer c.Stop()

	resp := aResponse("k.example.")

	// One key, updated many times: without bounding, the heap would hold ~2000 items.
	for i := 0; i < 2000; i++ {
		c.set("k", resp)
	}
	c.mutex.RLock()
	ql, el := c.queue.Len(), len(c.entries)
	c.mutex.RUnlock()
	if ql > 2*el+16 {
		t.Fatalf("single-key heap not bounded: queue=%d entries=%d", ql, el)
	}

	// Many distinct keys, each updated several times: heap stays within the bound of the
	// live entry count.
	for round := 0; round < 4; round++ {
		for i := 0; i < 300; i++ {
			c.set(string(rune('a'+i%26))+"-"+time.Duration(i).String(), resp)
		}
	}
	c.mutex.RLock()
	ql, el = c.queue.Len(), len(c.entries)
	c.mutex.RUnlock()
	if ql > 2*el+16 {
		t.Fatalf("multi-key heap not bounded: queue=%d entries=%d", ql, el)
	}
}

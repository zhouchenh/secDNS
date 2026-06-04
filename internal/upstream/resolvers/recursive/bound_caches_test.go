package recursive

import (
	"fmt"
	"testing"
	"time"
)

func TestPruneGlueCacheBounds(t *testing.T) {
	now := time.Now()
	m := make(map[string]glueCacheEntry)
	for i := 0; i < maxGlueCacheEntries+500; i++ {
		if len(m) >= maxGlueCacheEntries {
			pruneGlueCache(m, now)
		}
		m[fmt.Sprintf("ns%d.example.", i)] = glueCacheEntry{expires: now.Add(time.Hour)}
	}
	if len(m) > maxGlueCacheEntries {
		t.Fatalf("glue cache not bounded: %d > %d", len(m), maxGlueCacheEntries)
	}

	// Expired entries are dropped first, live ones kept.
	m2 := map[string]glueCacheEntry{
		"live": {expires: now.Add(time.Hour)},
		"dead": {expires: now.Add(-time.Hour)},
	}
	pruneGlueCache(m2, now)
	if _, ok := m2["dead"]; ok {
		t.Fatalf("expired glue entry was not pruned")
	}
	if _, ok := m2["live"]; !ok {
		t.Fatalf("live glue entry was wrongly pruned")
	}
}

func TestKeyCacheBounded(t *testing.T) {
	now := time.Now()
	v := newValidator()
	v.now = func() time.Time { return now }
	for i := 0; i < maxKeyCacheEntries+500; i++ {
		v.storeKeyState(fmt.Sprintf("zone%d.", i), &keyState{secure: false, expires: now.Add(time.Hour)})
	}
	v.cacheMu.Lock()
	n := len(v.keyCache)
	v.cacheMu.Unlock()
	if n > maxKeyCacheEntries {
		t.Fatalf("key cache not bounded: %d > %d", n, maxKeyCacheEntries)
	}
}

# secDNS Improvements Analysis

## Cache Resolver Improvements

### Critical Issues

#### 1. **Race Condition in `get()` Method** (CRITICAL)
**Location:** `internal/upstream/resolvers/cache/types.go:131-158`

**Issue:**
```go
c.mutex.RLock()
entry, exists := c.entries[key]
c.mutex.RUnlock()  // Lock released here

if !exists {
    return nil, false
}

remainingTTL := c.calculateRemainingTTL(entry)  // entry could be invalid!
```

Between releasing the RLock (line 135) and acquiring the Lock (line 156), another goroutine could delete the entry, making the `entry` pointer invalid. This could cause crashes or undefined behavior.

**Fix:** Hold the lock until we're done reading from the entry or copy the necessary fields while locked.

#### 2. **EDNS0 Client Subnet Not in Cache Key** (HIGH)
**Location:** `internal/upstream/resolvers/cache/types.go:220-227`

**Issue:**
Cache key only includes `qname:qtype:qclass`, ignoring EDNS0 options like Client Subnet. Two queries for the same domain but different ECS values would incorrectly share a cache entry, violating RFC 7871.

**Example:**
- Query 1: example.com from subnet 192.168.1.0/24 → cached
- Query 2: example.com from subnet 10.0.0.0/24 → returns wrong cached response

**Fix:** Include relevant EDNS0 options in cache key generation.

#### 3. **File Descriptor Leak in dnsmasqConf** (CRITICAL)
**Location:** `internal/rules/providers/dnsmasq/conf/types.go:38`

**Issue:**
```go
file, err := core.OpenFile(d.FilePath)
// ... file is used but never closed
```

The file is opened but never closed, causing a file descriptor leak.

**Fix:** Add `defer file.Close()` after opening.

### High Priority Improvements

#### 4. **No Request Coalescing**
**Impact:** Multiple concurrent requests for the same uncached key all hit upstream

When 10 clients simultaneously query an uncached domain, all 10 requests go upstream instead of coalescing into one.

**Benefit:** Reduces upstream load, improves latency for concurrent requests

#### 5. **Inefficient Cleanup Algorithm**
**Location:** `internal/upstream/resolvers/cache/types.go:384-406`

**Issue:**
```go
for key, entry := range c.entries {  // Iterates ALL entries
    elapsed := uint32(now.Sub(entry.CachedAt).Seconds())
    if elapsed >= entry.OriginalTTL {
        toDelete = append(toDelete, key)
    }
}
```

With maxEntries=50,000 and cleanupInterval=60s, this scans 50k entries every minute, most of which aren't expired.

**Fix:** Use a min-heap or timer wheel to only check entries that are actually expiring soon.

#### 6. **Hardcoded Default TTL Values**
**Location:** `internal/upstream/resolvers/cache/types.go:251, 277`

```go
minTTL := uint32(3600) // Default 1 hour if no records
// ...
return 300 // Default 5 minutes if no TTL found
```

These should be configurable fields.

### Medium Priority Enhancements

#### 7. **No Stale-While-Revalidate**
**Current behavior:** Expired entries are deleted, causing cache misses
**Better behavior:** Serve stale data while fetching fresh data in background

**Benefits:**
- Zero cache-miss latency for expired-but-still-usable entries
- Upstream failures don't immediately impact clients
- Better user experience during TTL transitions

#### 8. **No Auto-Update for Popular Expired Domains (Prefetching)**
For frequently accessed entries nearing expiration, proactively refresh them in the background before they expire.

**Current behavior:**
- Entry expires at TTL=0
- Next query causes cache miss
- Client waits for upstream query
- Popular domains constantly experience cache misses at TTL boundaries

**Proposed behavior:**
Track access frequency for each cache entry (simple counter). When popular domains (e.g., >10 accesses) reach 90% of their TTL:
- Trigger background refresh from upstream
- Update cache entry with fresh data
- Client always hits fresh cache, never waits

**Implementation approach:**
```go
type CacheEntry struct {
    Response    *dns.Msg
    OriginalTTL uint32
    CachedAt    time.Time
    lruNode     *LRUNode
    AccessCount uint32  // NEW: track popularity
}

// In cleanup goroutine, check for entries to prefetch:
if entry.AccessCount >= popularityThreshold {
    elapsed := time.Since(entry.CachedAt)
    percentExpired := float64(elapsed) / float64(entry.OriginalTTL * time.Second)
    if percentExpired >= 0.90 {  // 90% expired
        go c.refreshEntry(key, query)  // Background refresh
    }
}
```

**Benefits:**
- Zero cache-miss latency for popular domains
- Smooths upstream load distribution (no thundering herd at TTL expiration)
- Dramatically improves user experience for frequently accessed domains
- Upstream failures don't immediately impact popular domains

**Configuration:**
```json
{
  "popularityThreshold": 10,     // Domains accessed 10+ times are "popular"
  "prefetchThreshold": 0.90,     // Start refresh at 90% of TTL
  "maxConcurrentPrefetch": 100   // Limit concurrent background refreshes
}
```

#### 9. **No Cache Warming**
No ability to pre-populate the cache with common domains on startup.

**Use case:** Load top 1000 domains into cache on startup to avoid initial cold-start misses.

#### 10. **Memory Leak if `Stop()` Not Called**
**Location:** `internal/upstream/resolvers/cache/types.go:363-379`

The cleanup goroutine runs forever if `Stop()` is never called. For long-running processes, this is fine, but for testing or short-lived instances, it's a leak.

**Fix:** Consider using context for cancellation, or document that `Stop()` should be called.

### Low Priority / Nice-to-Have

#### 11. **No Per-Domain Statistics**
Currently only global stats (hits, misses, evictions). Per-domain stats would help identify:
- Which domains are most frequently queried
- Which domains have poor hit rates
- Which domains consume the most cache space

#### 12. **No TTL Jitter**
All entries expire exactly at their TTL, potentially causing thundering herd if many entries have the same TTL.

**Fix:** Add random jitter (±5%) to TTL to distribute expiration times.

#### 13. **No Negative Response Differentiation**
NXDOMAIN and NODATA are treated the same. In practice, NXDOMAIN is more stable and could be cached longer.

#### 14. **No Cache-Control Hints**
No way for upstream resolvers to hint cache behavior (e.g., "do-not-cache" for dynamic domains).

## Rule System Issues

### Critical Issues

#### 15. **File Descriptor Leak in dnsmasqConf** (CRITICAL - duplicate of #3)
Already mentioned above.

#### 16. **No Nil Check for Resolver**
**Location:** `internal/rules/providers/dnsmasq/conf/types.go:79`

```go
receive(common.EnsureFQDN(name), d.Resolver)
```

If `d.Resolver` is nil (configuration error), this passes nil to the receive function without warning.

**Fix:** Add validation during init or in Provide.

### Medium Priority Issues

#### 17. **Silent Duplicate Rule Handling**
**Location:** `internal/core/instance.go:54-56`

```go
if _, hasKey := i.nameResolverMap[name]; !hasKey {
    i.nameResolverMap[name] = r
}
```

If the same domain appears in multiple rules, only the first is used. Others are silently ignored.

**Suggestion:** Log a warning when duplicates are encountered, or make the behavior configurable (first-wins vs last-wins vs error).

#### 18. **Inefficient Regex in dnsmasqConf**
**Location:** `internal/rules/providers/dnsmasq/conf/types.go:65`

```go
line := commentRegEx.ReplaceAllString(d.fileContent[d.index], "")
```

This creates a new string for every line. Could optimize by:
- Finding comment position and using substring
- Or checking if line contains '#' before running regex

#### 19. **No Validation During Parse**
Files are only validated when iterated. Large files with errors at the end take longer to discover issues.

**Suggestion:** Add a `Validate()` method to parse and validate entire file upfront.

#### 20. **State Preserved Across Calls**
The `index` field persists across `Provide()` calls. While this works for the current usage pattern, it makes the provider non-reusable.

**Suggestion:** Consider making `Provide()` return an iterator instead of using internal state.

## Recommended Priority Order

### Phase 1: Critical Fixes (Must Fix)
1. Fix race condition in cache `get()` (#1)
2. Fix file descriptor leak (#3)
3. Add EDNS0 to cache key (#2)
4. Add nil resolver check (#16)

### Phase 2: High-Impact Improvements
5. Add request coalescing (#4)
6. Optimize cleanup algorithm (#5)
7. Make default TTLs configurable (#6)
8. Add stale-while-revalidate (#7)

### Phase 3: Quality of Life
9. Add duplicate rule warnings (#17)
10. Add auto-update for popular domains (#8)
11. Add cache warming support (#9)
12. Add per-domain statistics (#11)

### Phase 4: Polish
13. Add TTL jitter (#12)
14. Optimize dnsmasq parsing (#18)
15. Add cache-control hints (#14)

## Implementation Effort Estimates

- **#1 (Race condition):** 1 hour - straightforward fix
- **#2 (EDNS0 in key):** 2-3 hours - need to parse EDNS0 options
- **#3 (FD leak):** 5 minutes - add defer close
- **#4 (Request coalescing):** 4-6 hours - requires sync primitives and careful design
- **#5 (Cleanup optimization):** 3-4 hours - implement timer wheel or min-heap
- **#7 (Stale-while-revalidate):** 6-8 hours - complex feature, needs background refresh
- **#8 (Auto-update/Prefetching):** 6-8 hours - access tracking, background refresh goroutines, rate limiting

## Synergy: Auto-Update + Stale-While-Revalidate

**Best Practice:** Combine features #7 and #8 for optimal user experience:

**Tier 1 - Popular Domains (>10 accesses):**
- Auto-update at 90% TTL via prefetching
- Clients always get fresh data
- Zero cache misses

**Tier 2 - Regular Domains (1-10 accesses):**
- Serve stale data if expired
- Background refresh in progress
- Near-zero latency even on "miss"

**Tier 3 - Rare Domains (1 access):**
- Normal cache behavior
- Evict when expired or LRU

**Result:**
- Popular domains: Always fresh, zero latency
- Regular domains: Stale-but-fast while refreshing
- Rare domains: Don't waste resources
- Overall hit rate: >99% with near-zero latency

**Example metrics:**
```
Total queries: 100,000
Popular domains (google.com, facebook.com, etc): 60,000 queries
  - 100% prefetch hit rate, 0ms cache latency

Regular domains: 30,000 queries
  - 95% fresh hit, 5% stale-while-revalidate
  - Average 0.2ms cache latency

Rare domains: 10,000 queries
  - 70% hit rate, 30% miss
  - Cache misses: ~3000 (3% of total)

Overall effective hit rate: 97%
Overall average latency: <1ms (vs 20-50ms upstream)
```

## Testing Requirements

Each fix should include:
- Unit tests demonstrating the issue
- Unit tests verifying the fix
- Race detector tests (`go test -race`)
- Benchmark tests to verify performance improvements

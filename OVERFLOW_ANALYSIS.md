# AccessCount Overflow Analysis

## The Problem

`uint32` can hold 0 to 4,294,967,295 (≈4.3 billion).

### Overflow Scenarios

#### Scenario 1: Long-running popular domain
```
Domain: google.com (extremely popular)
Traffic: 1,000 queries/second (reasonable for busy server)
TTL: 7 days (604,800 seconds) - if maxTTL is very high
AccessCount per TTL cycle: 1,000 * 604,800 = 604,800,000 accesses

Result: Within range, but 14% of uint32 max in ONE cycle
```

#### Scenario 2: Prefetch keeps entry alive indefinitely
```
Domain: facebook.com
Traffic: 500 queries/second
TTL: 300s, but prefetching keeps refreshing it

If AccessCount NEVER resets:
- 500 queries/sec * 86,400 sec/day = 43,200,000 per day
- Overflow in: 4,294,967,295 / 43,200,000 = ~99 days

Result: OVERFLOW after 3 months of continuous operation!
```

#### Scenario 3: Very busy server
```
Corporate DNS server handling internal traffic
Domain: internal.company.com
Traffic: 10,000 queries/second (high but realistic)
TTL: 1 hour (3,600 seconds)

AccessCount per cycle: 10,000 * 3,600 = 36,000,000
After 100 cycles: 3,600,000,000 (approaching overflow)
If AccessCount persists: OVERFLOW in ~4-5 days
```

## Root Cause

The implementation proposal didn't specify what happens to `AccessCount` when:
1. Entry is refreshed via prefetch
2. Entry is updated with new upstream data
3. Entry has been in cache for extended periods

## Solutions

### Option 1: Use uint64 (RECOMMENDED)
```go
type CacheEntry struct {
    Response    *dns.Msg
    OriginalTTL uint32
    CachedAt    time.Time
    lruNode     *LRUNode
    AccessCount uint64  // 18 quintillion - effectively overflow-proof
}
```

**Pros:**
- Essentially eliminates overflow risk
- Simple, clean solution
- Minimal memory overhead (4 extra bytes per entry)

**Cons:**
- Atomic operations on uint64 require 64-bit alignment on some architectures

**Memory impact:**
- 10,000 entries * 4 bytes = 40KB extra
- Negligible compared to cached DNS responses

### Option 2: Reset AccessCount on Refresh
```go
// In refreshEntry() when updating existing entry:
func (c *Cache) refreshEntry(key string, entry *CacheEntry, newResponse *dns.Msg) {
    entry.Response = newResponse.Copy()
    entry.OriginalTTL = c.extractTTLWithOverrides(newResponse)
    entry.CachedAt = time.Now()
    atomic.StoreUint32(&entry.AccessCount, 0)  // RESET counter
}
```

**Pros:**
- Keeps uint32 size
- Counter represents "popularity within current TTL cycle"
- Overflow unlikely within single cycle

**Cons:**
- Loses historical popularity information
- Domain that was popular yesterday but quiet today loses prefetch benefit
- Edge cases with very long TTLs still risky

### Option 3: Decay/Cap AccessCount
```go
// On refresh, halve the count (exponential decay)
func (c *Cache) refreshEntry(key string, entry *CacheEntry, newResponse *dns.Msg) {
    entry.Response = newResponse.Copy()
    entry.OriginalTTL = c.extractTTLWithOverrides(newResponse)
    entry.CachedAt = time.Now()

    // Decay: keep some history, prevent overflow
    oldCount := atomic.LoadUint32(&entry.AccessCount)
    atomic.StoreUint32(&entry.AccessCount, oldCount/2)
}

// Or cap at a maximum:
const maxAccessCount = 1000000  // 1 million
atomic.CompareAndSwapUint32(&entry.AccessCount, current,
    min(current+1, maxAccessCount))
```

**Pros:**
- Preserves some popularity history
- Prevents overflow via cap
- Decay gives more weight to recent popularity

**Cons:**
- More complex logic
- Cap is somewhat arbitrary

### Option 4: Separate Popularity Metric
```go
type CacheEntry struct {
    Response       *dns.Msg
    OriginalTTL    uint32
    CachedAt       time.Time
    lruNode        *LRUNode

    // Popularity tracking
    LastAccessTime time.Time      // For LRU within popularity tier
    RecentAccess   uint32          // Accesses in current TTL cycle
    IsPopular      bool            // Cached popularity decision
}

// Update IsPopular flag periodically based on RecentAccess
func (c *Cache) updatePopularityFlags() {
    c.mutex.RLock()
    defer c.mutex.RUnlock()

    for _, entry := range c.entries {
        recent := atomic.LoadUint32(&entry.RecentAccess)
        entry.IsPopular = recent >= c.PopularityThreshold
        atomic.StoreUint32(&entry.RecentAccess, 0)  // Reset
    }
}
```

**Pros:**
- Simple boolean flag for prefetch decision
- Counter resets regularly
- No overflow risk

**Cons:**
- Requires periodic background task
- Less granular than continuous counting

## Recommendation

**Use uint64 for AccessCount (Option 1)**

**Rationale:**
1. **Simplest solution** - just change the type
2. **Future-proof** - handles any conceivable traffic pattern
3. **Minimal overhead** - 40KB for 10,000 entries
4. **No edge cases** - works correctly in all scenarios
5. **Standard practice** - most production cache systems use 64-bit counters

**Implementation:**
```go
type CacheEntry struct {
    Response    *dns.Msg
    OriginalTTL uint32
    CachedAt    time.Time
    lruNode     *LRUNode
    AccessCount uint64  // Changed from uint32
}

// In get() - increment with atomic operation
func (c *Cache) get(key string) (*dns.Msg, bool) {
    c.mutex.RLock()
    entry, exists := c.entries[key]
    c.mutex.RUnlock()

    if !exists {
        return nil, false
    }

    // Increment access counter (atomic)
    atomic.AddUint64(&entry.AccessCount, 1)

    // ... rest of get logic
}

// In cleanup/prefetch check
if atomic.LoadUint64(&entry.AccessCount) >= c.PopularityThreshold {
    // Prefetch logic
}
```

## Updated Improvements Analysis

Need to update IMPROVEMENTS_ANALYSIS.md to reflect uint64 instead of uint32 for AccessCount.

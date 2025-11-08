# DNS Cache Resolver - Production Design Specification

## Overview

A high-performance, thread-safe DNS caching resolver for secDNS with LRU eviction, TTL respect, negative caching, and comprehensive metrics.

---

## Design Requirements

### Functional Requirements
1. **Cache DNS responses** with respect to TTL from upstream servers
2. **LRU eviction** when cache reaches size limit
3. **Negative caching** for NXDOMAIN and NODATA responses
4. **TTL adjustment** - decrement TTL as time passes
5. **Configurable limits** - max entries, min/max TTL overrides
6. **Thread-safe** concurrent access from multiple goroutines
7. **Cache statistics** - hits, misses, evictions, size

### Performance Requirements
1. **Sub-millisecond cache lookups** for hits
2. **Lock-free reads** when possible (RWMutex)
3. **Minimal memory overhead** (~200 bytes per entry)
4. **Efficient eviction** - O(1) LRU operations
5. **No goroutine leaks** - clean background workers

### Integration Requirements
1. Follow **wrapper resolver pattern**
2. Implement **NameServerResolver() interface**
3. Support **descriptor-based configuration**
4. Respect **depth parameter** for loop detection
5. **Never modify original query**

---

## Architecture Design

### Component Structure

```
┌─────────────────────────────────────────────────────────────┐
│                    Cache Resolver                            │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌─────────────┐      ┌──────────────┐     ┌─────────────┐ │
│  │   Query     │─────▶│ Cache Lookup │────▶│   Return    │ │
│  │             │      │  (RWMutex)   │ HIT │  Response   │ │
│  └─────────────┘      └──────────────┘     └─────────────┘ │
│                              │                                │
│                              │ MISS                           │
│                              ▼                                │
│                       ┌──────────────┐                        │
│                       │   Upstream   │                        │
│                       │   Resolver   │                        │
│                       └──────────────┘                        │
│                              │                                │
│                              ▼                                │
│                       ┌──────────────┐                        │
│                       │ Cache Insert │                        │
│                       │ (RWMutex +   │                        │
│                       │  LRU Update) │                        │
│                       └──────────────┘                        │
│                                                               │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ Background: Cleanup expired entries every 60s          │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

---

## Data Structures

### 1. Cache Resolver
```go
type Cache struct {
    // Configuration (immutable after init)
    Resolver       resolver.Resolver  // Upstream resolver
    MaxEntries     int                // Max cache entries (0 = unlimited)
    MinTTL         time.Duration      // Min TTL override (0 = no override)
    MaxTTL         time.Duration      // Max TTL override (0 = no override)
    NegativeTTL    time.Duration      // TTL for negative responses
    CleanupInterval time.Duration     // How often to run cleanup

    // Cache state (protected by mutex)
    entries        map[string]*CacheEntry
    lru            *LRUList
    mutex          sync.RWMutex

    // Statistics (atomic counters)
    hits           uint64
    misses         uint64
    evictions      uint64

    // Lifecycle
    initOnce       sync.Once
    stopCleanup    chan struct{}
    cleanupDone    sync.WaitGroup
}
```

### 2. Cache Entry
```go
type CacheEntry struct {
    // Cached data
    Response      *dns.Msg      // Deep copy of DNS response
    OriginalTTL   uint32        // Original TTL from upstream
    CachedAt      time.Time     // When this was cached

    // LRU tracking
    lruNode       *LRUNode
}
```

### 3. LRU Doubly-Linked List
```go
type LRUList struct {
    head *LRUNode
    tail *LRUNode
    size int
}

type LRUNode struct {
    key  string
    prev *LRUNode
    next *LRUNode
}
```

### 4. Cache Key
```go
// Format: "qname:qtype:qclass"
// Example: "example.com.:1:1" (A record, IN class)
func makeCacheKey(query *dns.Msg) string {
    if len(query.Question) == 0 {
        return ""
    }
    q := query.Question[0]
    return fmt.Sprintf("%s:%d:%d", strings.ToLower(q.Name), q.Qtype, q.Qclass)
}
```

---

## Core Operations

### 1. Cache Lookup (Read-Heavy Path)
```go
func (c *Cache) get(key string) (*dns.Msg, bool) {
    // Fast read lock
    c.mutex.RLock()
    entry, exists := c.entries[key]
    c.mutex.RUnlock()

    if !exists {
        return nil, false
    }

    // Check expiration (outside lock)
    ttl := c.calculateRemainingTTL(entry)
    if ttl <= 0 {
        // Expired - remove it
        c.mutex.Lock()
        delete(c.entries, key)
        c.lru.remove(entry.lruNode)
        c.mutex.Unlock()
        return nil, false
    }

    // Update LRU (needs write lock)
    c.mutex.Lock()
    c.lru.moveToFront(entry.lruNode)
    c.mutex.Unlock()

    // Create response with adjusted TTL
    response := entry.Response.Copy()
    c.adjustTTL(response, ttl)

    return response, true
}
```

### 2. Cache Insert (Write Path)
```go
func (c *Cache) set(key string, response *dns.Msg) {
    c.mutex.Lock()
    defer c.mutex.Unlock()

    // Evict if at capacity
    if c.MaxEntries > 0 && len(c.entries) >= c.MaxEntries {
        // Remove LRU entry
        if oldest := c.lru.tail; oldest != nil {
            delete(c.entries, oldest.key)
            c.lru.remove(oldest)
            atomic.AddUint64(&c.evictions, 1)
        }
    }

    // Create entry
    ttl := c.extractTTL(response)
    entry := &CacheEntry{
        Response:    response.Copy(),  // CRITICAL: Deep copy
        OriginalTTL: ttl,
        CachedAt:    time.Now(),
        lruNode:     c.lru.addToFront(key),
    }

    c.entries[key] = entry
}
```

### 3. TTL Calculation
```go
func (c *Cache) calculateRemainingTTL(entry *CacheEntry) uint32 {
    elapsed := uint32(time.Since(entry.CachedAt).Seconds())

    if elapsed >= entry.OriginalTTL {
        return 0  // Expired
    }

    remaining := entry.OriginalTTL - elapsed

    // Apply min/max TTL overrides
    if c.MinTTL > 0 && remaining < uint32(c.MinTTL.Seconds()) {
        return uint32(c.MinTTL.Seconds())
    }
    if c.MaxTTL > 0 && remaining > uint32(c.MaxTTL.Seconds()) {
        return uint32(c.MaxTTL.Seconds())
    }

    return remaining
}
```

### 4. Background Cleanup
```go
func (c *Cache) startCleanup() {
    c.cleanupDone.Add(1)
    go func() {
        defer c.cleanupDone.Done()

        ticker := time.NewTicker(c.CleanupInterval)
        defer ticker.Stop()

        for {
            select {
            case <-ticker.C:
                c.cleanupExpired()
            case <-c.stopCleanup:
                return
            }
        }
    }()
}

func (c *Cache) cleanupExpired() {
    c.mutex.Lock()
    defer c.mutex.Unlock()

    now := time.Now()
    toDelete := make([]string, 0)

    for key, entry := range c.entries {
        elapsed := uint32(now.Sub(entry.CachedAt).Seconds())
        if elapsed >= entry.OriginalTTL {
            toDelete = append(toDelete, key)
        }
    }

    for _, key := range toDelete {
        if entry := c.entries[key]; entry != nil {
            delete(c.entries, key)
            c.lru.remove(entry.lruNode)
        }
    }
}
```

---

## Negative Caching

### Strategy
Cache NXDOMAIN and NODATA responses with configurable TTL:

```go
func (c *Cache) shouldCache(response *dns.Msg) bool {
    // Cache successful responses
    if response.Rcode == dns.RcodeSuccess && len(response.Answer) > 0 {
        return true
    }

    // Cache NXDOMAIN
    if response.Rcode == dns.RcodeNameError {
        return true
    }

    // Cache NODATA (NOERROR with no answers)
    if response.Rcode == dns.RcodeSuccess && len(response.Answer) == 0 {
        return true
    }

    // Don't cache errors (SERVFAIL, REFUSED, etc.)
    return false
}

func (c *Cache) getTTLForNegativeResponse(response *dns.Msg) uint32 {
    // Use configured negative TTL (default 300s / 5min)
    if c.NegativeTTL > 0 {
        return uint32(c.NegativeTTL.Seconds())
    }

    // Try to extract SOA minimum TTL
    for _, rr := range response.Ns {
        if soa, ok := rr.(*dns.SOA); ok {
            return soa.Minttl
        }
    }

    return 300  // Default 5 minutes
}
```

---

## Configuration

### JSON Configuration
```json
{
  "resolvers": {
    "cache": {
      "GoogleDNS-Cached": {
        "resolver": "GoogleDNS",
        "maxEntries": 10000,
        "minTTL": 60,
        "maxTTL": 86400,
        "negativeTTL": 300,
        "cleanupInterval": 60
      }
    },
    "nameServer": {
      "GoogleDNS": {
        "address": "8.8.8.8"
      }
    }
  }
}
```

### Descriptor Registration
```go
func init() {
    if err := resolver.RegisterResolver(&descriptor.Descriptor{
        Type: typeOfCache,
        Filler: descriptor.Fillers{
            // Upstream resolver (required)
            descriptor.ObjectFiller{
                ObjectPath: descriptor.Path{"Resolver"},
                ValueSource: descriptor.ObjectAtPath{
                    ObjectPath: descriptor.Path{"resolver"},
                    AssignableKind: descriptor.AssignmentFunction(
                        func(i interface{}) (object interface{}, ok bool) {
                            object, s, f := resolver.Descriptor().Describe(i)
                            ok = s > 0 && f < 1
                            return
                        }),
                },
            },
            // maxEntries (optional, default 10000)
            descriptor.ObjectFiller{
                ObjectPath: descriptor.Path{"MaxEntries"},
                ValueSource: descriptor.ValueSources{
                    descriptor.ObjectAtPath{
                        ObjectPath: descriptor.Path{"maxEntries"},
                        AssignableKind: descriptor.ConvertibleKind{
                            Kind: descriptor.KindFloat64,
                            ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
                                num, ok := original.(float64)
                                if !ok || num < 0 {
                                    return
                                }
                                return int(num), true
                            },
                        },
                    },
                    descriptor.DefaultValue{Value: 10000},
                },
            },
            // Similar for minTTL, maxTTL, negativeTTL, cleanupInterval...
        },
    }); err != nil {
        common.ErrOutput(err)
    }
}
```

---

## Performance Characteristics

### Time Complexity
- Cache lookup (hit): **O(1)** + lock overhead (~100-500ns)
- Cache insert: **O(1)** + potential eviction (~200ns-1μs)
- LRU update: **O(1)** pointer updates
- Cleanup: **O(n)** but runs every 60s, not on critical path

### Space Complexity
- Per entry: ~200 bytes (dns.Msg + metadata + LRU node)
- 10,000 entries ≈ **2 MB** memory
- 100,000 entries ≈ **20 MB** memory

### Lock Contention
- **Read-heavy workload** (typical DNS): RWMutex allows concurrent reads
- **Write lock only for**: insert, evict, LRU update
- **Separate cleanup goroutine**: doesn't block query path

---

## Statistics & Metrics

### Exported Metrics
```go
type CacheStats struct {
    Hits       uint64  // Cache hits
    Misses     uint64  // Cache misses
    Evictions  uint64  // LRU evictions
    Size       int     // Current entries
    HitRate    float64 // hits / (hits + misses)
}

func (c *Cache) Stats() CacheStats {
    hits := atomic.LoadUint64(&c.hits)
    misses := atomic.LoadUint64(&c.misses)
    evictions := atomic.LoadUint64(&c.evictions)

    c.mutex.RLock()
    size := len(c.entries)
    c.mutex.RUnlock()

    total := hits + misses
    hitRate := 0.0
    if total > 0 {
        hitRate = float64(hits) / float64(total)
    }

    return CacheStats{
        Hits:      hits,
        Misses:    misses,
        Evictions: evictions,
        Size:      size,
        HitRate:   hitRate,
    }
}
```

---

## Testing Strategy

### 1. Unit Tests
- Cache key generation (case insensitive, format)
- TTL calculation (elapsed, min/max override)
- LRU operations (add, remove, move, evict)
- Negative caching (NXDOMAIN, NODATA)
- Expiration cleanup

### 2. Integration Tests
- Cache hit/miss flow
- Upstream resolver integration
- Concurrent access (multiple goroutines)
- Eviction under pressure
- Background cleanup

### 3. Benchmarks
```go
BenchmarkCacheLookup_Hit     // Target: < 500ns
BenchmarkCacheLookup_Miss    // Target: < 200ns
BenchmarkCacheInsert         // Target: < 1μs
BenchmarkCacheConcurrent     // 100 goroutines
```

---

## Implementation Checklist

- [ ] Create `/home/user/secDNS/internal/upstream/resolvers/cache/types.go`
- [ ] Implement Cache struct with all fields
- [ ] Implement LRU doubly-linked list
- [ ] Implement cache key generation
- [ ] Implement Resolve() with depth check
- [ ] Implement get() with TTL check
- [ ] Implement set() with eviction
- [ ] Implement calculateRemainingTTL()
- [ ] Implement adjustTTL() for responses
- [ ] Implement background cleanup
- [ ] Implement negative caching
- [ ] Implement descriptor registration
- [ ] Add NameServerResolver() interface
- [ ] Create comprehensive tests
- [ ] Add benchmarks
- [ ] Update documentation
- [ ] Add example configuration

---

## Known Limitations & Future Improvements

### Current Limitations
1. **No persistence** - cache is in-memory only
2. **No distributed caching** - single process
3. **Simple LRU** - no adaptive algorithms
4. **No query coalescing** - concurrent identical queries go to upstream

### Future Improvements (v1.3+)
1. **Prefetching** - refresh popular entries before expiration
2. **Query coalescing** - deduplicate concurrent identical queries
3. **Smart eviction** - consider query frequency, not just recency
4. **Metrics export** - Prometheus integration
5. **Cache warming** - preload common domains
6. **DNSSEC validation** - cache DNSSEC status

---

## References

- RFC 1035: Domain Names - Implementation and Specification
- RFC 2181: Clarifications to the DNS Specification (TTL, negative caching)
- RFC 2308: Negative Caching of DNS Queries (NXDOMAIN caching)
- RFC 8767: Serving Stale Data to Improve DNS Resiliency

---

**End of Design Specification**

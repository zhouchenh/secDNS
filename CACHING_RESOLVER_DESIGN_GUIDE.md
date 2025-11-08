# Caching Resolver Design Guide

## Overview
This document provides specific design guidance for implementing a caching resolver in the secDNS architecture, based on comprehensive analysis of existing resolver patterns.

---

## 1. BASIC STRUCTURE

### 1.1 Resolver Definition
**File Location:** Should be at `/home/user/secDNS/internal/upstream/resolvers/cache/types.go`

**Minimal Structure:**
```go
package cache

import (
    "github.com/miekg/dns"
    "github.com/zhouchenh/go-descriptor"
    "github.com/zhouchenh/secDNS/internal/common"
    "github.com/zhouchenh/secDNS/pkg/upstream/resolver"
    "sync"
    "time"
)

type Cache struct {
    Resolver resolver.Resolver
    TTL      time.Duration  // Cache entry lifetime
    MaxSize  int           // Maximum cache entries
    
    // Thread-safe cache storage
    cache map[string]*CacheEntry
    mutex sync.RWMutex
}

type CacheEntry struct {
    Response  *dns.Msg
    ExpiresAt time.Time
}

var typeOfCache = descriptor.TypeOfNew(new(*Cache))

func (c *Cache) Type() descriptor.Type {
    return typeOfCache
}

func (c *Cache) TypeName() string {
    return "cache"
}

func (c *Cache) Resolve(query *dns.Msg, depth int) (*dns.Msg, error) {
    if depth < 0 {
        return nil, resolver.ErrLoopDetected
    }
    
    // Implementation details below...
    return nil, nil
}

func (c *Cache) NameServerResolver() {}

func init() {
    // Registration code below...
}
```

---

## 2. IMPLEMENTATION DETAILS

### 2.1 Depth Parameter Usage
**CRITICAL:** Always check depth and decrement!

```go
func (c *Cache) Resolve(query *dns.Msg, depth int) (*dns.Msg, error) {
    if depth < 0 {
        return nil, resolver.ErrLoopDetected
    }
    
    // ... cache logic ...
    
    // When calling upstream resolver:
    reply, err := c.Resolver.Resolve(query, depth-1)
    // ↑ MUST be depth-1, never depth
    
    return reply, err
}
```

### 2.2 Query Validation
**Use the provided validation function:**

```go
func (c *Cache) Resolve(query *dns.Msg, depth int) (*dns.Msg, error) {
    if depth < 0 {
        return nil, resolver.ErrLoopDetected
    }
    
    // Validate query (NOT REQUIRED - done by listener, but good practice)
    if err := resolver.QueryCheck(query); err != nil {
        return nil, err
    }
    
    // ... rest of implementation ...
}
```

**What QueryCheck validates:**
- Query is not nil
- Exactly 1 question (most DNS queries)
- Question class is INET

### 2.3 Cache Key Generation
**Pattern: Use query name + question type**

```go
func (c *Cache) getCacheKey(query *dns.Msg) string {
    if len(query.Question) == 0 {
        return ""
    }
    q := query.Question[0]
    // Format: "name:type" or use go-descriptor pattern
    return q.Name + ":" + dns.TypeToString[q.Qtype]
}
```

**Alternative: Use full DNS wire format**
```go
func (c *Cache) getCacheKey(query *dns.Msg) string {
    packed, err := query.Pack()
    if err != nil {
        return ""
    }
    return string(packed)  // Binary key
}
```

### 2.4 Thread-Safe Cache Access

#### Read (Fast Path - Common Case)
```go
func (c *Cache) getCachedResponse(query *dns.Msg) (*dns.Msg, bool) {
    key := c.getCacheKey(query)
    
    c.mutex.RLock()
    entry, exists := c.cache[key]
    c.mutex.RUnlock()
    
    if !exists {
        return nil, false
    }
    
    // Check expiration
    if time.Now().After(entry.ExpiresAt) {
        // Remove expired entry (separate write)
        c.mutex.Lock()
        delete(c.cache, key)
        c.mutex.Unlock()
        return nil, false
    }
    
    return entry.Response, true
}
```

#### Write (Slow Path - Less Common)
```go
func (c *Cache) cacheResponse(query *dns.Msg, response *dns.Msg) {
    key := c.getCacheKey(query)
    
    // Calculate TTL (use minimum from all RRs)
    ttl := c.calculateTTL(response)
    
    c.mutex.Lock()
    defer c.mutex.Unlock()
    
    // Check size limit
    if len(c.cache) >= c.MaxSize && _, exists := c.cache[key]; !exists {
        // Cache is full - evict something
        c.evictOne()
    }
    
    c.cache[key] = &CacheEntry{
        Response:  response,
        ExpiresAt: time.Now().Add(ttl),
    }
}
```

### 2.5 Query Handling - DO NOT Modify Original Query

**CORRECT Pattern:**
```go
func (c *Cache) Resolve(query *dns.Msg, depth int) (*dns.Msg, error) {
    if depth < 0 {
        return nil, resolver.ErrLoopDetected
    }
    
    // Check cache using ORIGINAL query
    if cached, ok := c.getCachedResponse(query); ok {
        return cached, nil
    }
    
    // Call upstream with ORIGINAL query
    reply, err := c.Resolver.Resolve(query, depth-1)
    
    // Cache the response
    if err == nil && reply != nil {
        c.cacheResponse(query, reply)
    }
    
    return reply, err
}
```

**NEVER do this:**
```go
// WRONG - modifies original query
query.Question[0].Qtype = dns.TypeA
reply, err := c.Resolver.Resolve(query, depth-1)
// Original caller's query is now modified!
```

**If you need to modify for checking:**
```go
// CORRECT - use save/restore pattern
originalType := query.Question[0].Qtype
query.Question[0].Qtype = dns.TypeA
reply, err := c.Resolver.Resolve(query, depth-1)
query.Question[0].Qtype = originalType  // RESTORE
```

**Or use copy (more memory but safer):**
```go
// Create copy if needed for side checks
queryCopy := query.Copy()
queryCopy.Question[0].Qtype = dns.TypeA
// ... work with queryCopy ...
// Original query untouched
```

### 2.6 Response Handling - Copy Before Caching

**CRITICAL:** Cache stores the response object. You MUST copy it!

```go
func (c *Cache) cacheResponse(query *dns.Msg, response *dns.Msg) {
    key := c.getCacheKey(query)
    
    c.mutex.Lock()
    defer c.mutex.Unlock()
    
    // IMPORTANT: Copy response before storing
    responseCopy := response.Copy()
    
    c.cache[key] = &CacheEntry{
        Response:  responseCopy,  // Store COPY, not original
        ExpiresAt: time.Now().Add(c.calculateTTL(response)),
    }
}
```

**Why:** The upstream response object could be reused/modified by other code. Storing a copy prevents corruption of cached data.

### 2.7 TTL Calculation Pattern

**Option 1: Use resolver's configured TTL (simplest)**
```go
func (c *Cache) calculateTTL(response *dns.Msg) time.Duration {
    return c.TTL  // Use configured TTL
}
```

**Option 2: Use minimum TTL from response (more accurate)**
```go
func (c *Cache) calculateTTL(response *dns.Msg) time.Duration {
    if response == nil {
        return c.TTL
    }
    
    minTTL := c.TTL
    
    // Check Answer section
    for _, rr := range response.Answer {
        if rr.Header().Ttl > 0 && time.Duration(rr.Header().Ttl)*time.Second < minTTL {
            minTTL = time.Duration(rr.Header().Ttl) * time.Second
        }
    }
    
    // Cap at configured maximum
    if minTTL > c.TTL {
        minTTL = c.TTL
    }
    
    return minTTL
}
```

**Option 3: Hybrid (recommended)**
```go
func (c *Cache) calculateTTL(response *dns.Msg) time.Duration {
    if response == nil || response.Rcode != dns.RcodeSuccess {
        // Don't cache errors (or use shorter TTL)
        return 0
    }
    
    // Find minimum TTL from response
    minTTL := c.TTL
    hasAnswers := false
    
    for _, rr := range response.Answer {
        hasAnswers = true
        ttl := time.Duration(rr.Header().Ttl) * time.Second
        if ttl > 0 && ttl < minTTL {
            minTTL = ttl
        }
    }
    
    // If no answers, use configured TTL but possibly shorter
    if !hasAnswers {
        return c.TTL
    }
    
    return minTTL
}
```

### 2.8 Initialization Pattern

**Use sync.Once for lazy cache initialization:**
```go
type Cache struct {
    Resolver resolver.Resolver
    TTL      time.Duration
    MaxSize  int
    
    cache    map[string]*CacheEntry
    mutex    sync.RWMutex
    initOnce sync.Once  // Add this
}

func (c *Cache) Resolve(query *dns.Msg, depth int) (*dns.Msg, error) {
    if depth < 0 {
        return nil, resolver.ErrLoopDetected
    }
    
    // Lazy initialization (thread-safe)
    c.initOnce.Do(func() {
        if c.cache == nil {
            c.cache = make(map[string]*CacheEntry)
        }
        if c.TTL == 0 {
            c.TTL = 60 * time.Second  // Default TTL
        }
        if c.MaxSize == 0 {
            c.MaxSize = 1000  // Default size
        }
    })
    
    // ... rest of resolve logic ...
}
```

---

## 3. REGISTRATION AND CONFIGURATION

### 3.1 Registration Pattern (init function)

**See:** `/home/user/secDNS/internal/upstream/resolvers/dns64/types.go` (Lines 99-172)

**Minimal Registration:**
```go
func init() {
    if err := resolver.RegisterResolver(&descriptor.Descriptor{
        Type: typeOfCache,
        Filler: descriptor.ObjectFiller{
            ObjectPath: descriptor.Path{"Resolver"},
            ValueSource: descriptor.ObjectAtPath{
                ObjectPath: descriptor.Root,
                AssignableKind: descriptor.AssignmentFunction(func(i interface{}) (object interface{}, ok bool) {
                    object, s, f := resolver.Descriptor().Describe(i)
                    ok = s > 0 && f < 1
                    return
                }),
            },
        },
        // Add configuration for TTL and MaxSize here
    }); err != nil {
        common.ErrOutput(err)
    }
}
```

**Full Registration with Configuration:**
```go
func init() {
    convertibleKindDuration := descriptor.ConvertibleKind{
        Kind: descriptor.KindFloat64,
        ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
            num, ok := original.(float64)
            if !ok {
                return
            }
            return time.Duration(num * float64(time.Second)), true
        },
    }
    
    if err := resolver.RegisterResolver(&descriptor.Descriptor{
        Type: typeOfCache,
        Filler: descriptor.Fillers{
            descriptor.ObjectFiller{
                ObjectPath: descriptor.Path{"Resolver"},
                ValueSource: descriptor.ObjectAtPath{
                    ObjectPath: descriptor.Root,
                    AssignableKind: descriptor.AssignmentFunction(func(i interface{}) (object interface{}, ok bool) {
                        object, s, f := resolver.Descriptor().Describe(i)
                        ok = s > 0 && f < 1
                        return
                    }),
                },
            },
            descriptor.ObjectFiller{
                ObjectPath: descriptor.Path{"TTL"},
                ValueSource: descriptor.ValueSources{
                    descriptor.ObjectAtPath{
                        ObjectPath: descriptor.Path{"ttl"},
                        AssignableKind: convertibleKindDuration,
                    },
                    descriptor.DefaultValue{Value: 60 * time.Second},
                },
            },
            descriptor.ObjectFiller{
                ObjectPath: descriptor.Path{"MaxSize"},
                ValueSource: descriptor.ValueSources{
                    descriptor.ObjectAtPath{
                        ObjectPath: descriptor.Path{"maxSize"},
                        AssignableKind: descriptor.ConvertibleKind{
                            Kind: descriptor.KindFloat64,
                            ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
                                num, ok := original.(float64)
                                if !ok {
                                    return
                                }
                                return int(num), true
                            },
                        },
                    },
                    descriptor.DefaultValue{Value: 1000},
                },
            },
        },
    }); err != nil {
        common.ErrOutput(err)
    }
}
```

### 3.2 Configuration Example

**JSON Configuration:**
```json
{
  "resolvers": {
    "cache": {
      "CachedCloudflare": {
        "resolver": {
          "type": "nameServer",
          "config": "Cloudflare-DNS"
        },
        "ttl": 300,
        "maxSize": 5000
      }
    },
    "nameServer": {
      "Cloudflare-DNS": {
        "address": "1.1.1.1",
        "port": 53
      }
    }
  },
  "defaultResolver": "CachedCloudflare"
}
```

---

## 4. CONCURRENCY AND SYNCHRONIZATION

### 4.1 When to Use sync.RWMutex

**Use read lock for cache hits (common case):**
```go
c.mutex.RLock()
entry, exists := c.cache[key]
c.mutex.RUnlock()
```

**Use write lock for cache updates (uncommon case):**
```go
c.mutex.Lock()
c.cache[key] = entry
c.mutex.Unlock()
```

**Benefits:**
- Multiple goroutines can read simultaneously
- Only exclusive access for writes
- Better performance than Mutex for read-heavy workloads

### 4.2 Avoid Common Mistakes

**WRONG: Hold lock too long**
```go
c.mutex.RLock()
entry, exists := c.cache[key]
if exists {
    reply, err := c.Resolver.Resolve(query, depth-1)  // SLOW!
    // Lock held during upstream query
}
c.mutex.RUnlock()
```

**CORRECT: Release lock early**
```go
c.mutex.RLock()
entry, exists := c.cache[key]
c.mutex.RUnlock()  // Release BEFORE slow operations

if exists {
    return entry.Response, nil
}

// Upstream query without lock
reply, err := c.Resolver.Resolve(query, depth-1)
```

### 4.3 Race Condition: Double-Check Pattern

**PROBLEM:** Two goroutines might both miss cache, both query upstream

**Solution: Accept the race (simpler)**
```go
// Both goroutines hit upstream, but results are cached
// Not ideal but acceptable (duplicate work)
```

**Solution: Use sync.Once per key (complex)**
```go
type Cache struct {
    cache   map[string]*CacheEntry
    inFlight map[string]*sync.Once  // Track in-flight requests
    mutex   sync.RWMutex
}

func (c *Cache) Resolve(query *dns.Msg, depth int) (*dns.Msg, error) {
    key := c.getCacheKey(query)
    
    // Check cache
    c.mutex.RLock()
    entry, exists := c.cache[key]
    c.mutex.RUnlock()
    if exists && !isExpired(entry) {
        return entry.Response, nil
    }
    
    // Check if already in-flight
    c.mutex.Lock()
    once, inFlight := c.inFlight[key]
    if !inFlight {
        once = new(sync.Once)
        c.inFlight[key] = once
    }
    c.mutex.Unlock()
    
    var reply *dns.Msg
    var err error
    
    once.Do(func() {
        reply, err = c.Resolver.Resolve(query, depth-1)
        if err == nil && reply != nil {
            c.cacheResponse(query, reply)
        }
        
        // Clean up
        c.mutex.Lock()
        delete(c.inFlight, key)
        c.mutex.Unlock()
    })
    
    // Wait for result
    <-once.Done  // Not actually available on sync.Once
    
    return reply, err
}
```

**Recommendation:** Start simple (accept duplicate work), optimize later if needed.

---

## 5. EVICTION POLICIES

### 5.1 Simple Eviction (LRU-like)

**Remove oldest entry when cache is full:**
```go
func (c *Cache) evictOne() {
    var oldestKey string
    var oldestTime time.Time = time.Now()
    
    for key, entry := range c.cache {
        if entry.ExpiresAt.Before(oldestTime) {
            oldestKey = key
            oldestTime = entry.ExpiresAt
        }
    }
    
    if oldestKey != "" {
        delete(c.cache, oldestKey)
    }
}
```

### 5.2 Periodic Cleanup

**Option 1: Clean on every write**
```go
func (c *Cache) cacheResponse(query *dns.Msg, response *dns.Msg) {
    key := c.getCacheKey(query)
    
    c.mutex.Lock()
    defer c.mutex.Unlock()
    
    // Remove all expired entries
    now := time.Now()
    for k, entry := range c.cache {
        if now.After(entry.ExpiresAt) {
            delete(c.cache, k)
        }
    }
    
    // ... cache new entry ...
}
```

**Option 2: Background cleanup (more efficient)**
```go
type Cache struct {
    // ... other fields ...
    cleanupTicker *time.Ticker
    cleanupOnce   sync.Once
}

func (c *Cache) Resolve(query *dns.Msg, depth int) (*dns.Msg, error) {
    c.cleanupOnce.Do(func() {
        c.cleanupTicker = time.NewTicker(5 * time.Minute)
        go c.backgroundCleanup()
    })
    
    // ... normal resolve logic ...
}

func (c *Cache) backgroundCleanup() {
    for range c.cleanupTicker.C {
        c.mutex.Lock()
        now := time.Now()
        for k, entry := range c.cache {
            if now.After(entry.ExpiresAt) {
                delete(c.cache, k)
            }
        }
        c.mutex.Unlock()
    }
}
```

---

## 6. ERROR HANDLING

### 6.1 Should You Cache Error Responses?

**Option 1: Never cache errors (safer)**
```go
reply, err := c.Resolver.Resolve(query, depth-1)
if err != nil {
    return reply, err  // Don't cache
}

// Only cache success
if reply != nil {
    c.cacheResponse(query, reply)
}

return reply, nil
```

**Option 2: Cache errors with shorter TTL**
```go
reply, err := c.Resolver.Resolve(query, depth-1)

if err == nil && reply != nil && reply.Rcode == dns.RcodeSuccess {
    // Cache successful responses for full TTL
    c.cacheResponse(query, reply)
} else if reply != nil {
    // Cache negative responses (NXDOMAIN, NODATA) with shorter TTL
    c.cache[key] = &CacheEntry{
        Response:  reply.Copy(),
        ExpiresAt: time.Now().Add(10 * time.Second),
    }
}

return reply, err
```

### 6.2 Error Propagation

**Always propagate upstream errors:**
```go
func (c *Cache) Resolve(query *dns.Msg, depth int) (*dns.Msg, error) {
    // Check cache
    if cached, ok := c.getCachedResponse(query); ok {
        return cached, nil
    }
    
    // Query upstream
    reply, err := c.Resolver.Resolve(query, depth-1)
    
    // If error, return immediately
    if err != nil {
        return nil, err  // Don't cache errors
    }
    
    // Only cache success
    if reply != nil {
        c.cacheResponse(query, reply)
    }
    
    return reply, nil
}
```

---

## 7. TESTING PATTERNS

### 7.1 Mock Resolver for Testing

```go
type MockResolver struct {
    responses map[string]*dns.Msg
    callCount int
}

func (m *MockResolver) Type() descriptor.Type {
    return nil
}

func (m *MockResolver) TypeName() string {
    return "mock"
}

func (m *MockResolver) Resolve(query *dns.Msg, depth int) (*dns.Msg, error) {
    m.callCount++
    key := query.Question[0].Name
    if resp, ok := m.responses[key]; ok {
        return resp, nil
    }
    return nil, fmt.Errorf("not found")
}
```

### 7.2 Testing Cache Hit

```go
func TestCacheHit(t *testing.T) {
    mock := &MockResolver{
        responses: map[string]*dns.Msg{
            "example.com.": createTestResponse("example.com.", "1.2.3.4"),
        },
    }
    
    cache := &Cache{
        Resolver: mock,
        TTL:      60 * time.Second,
        MaxSize:  100,
    }
    
    query := createTestQuery("example.com.", dns.TypeA)
    
    // First call - hits upstream
    resp1, _ := cache.Resolve(query, 64)
    if mock.callCount != 1 {
        t.Fatalf("Expected 1 upstream call, got %d", mock.callCount)
    }
    
    // Second call - hits cache
    resp2, _ := cache.Resolve(query, 64)
    if mock.callCount != 1 {
        t.Fatalf("Expected 1 upstream call (cached), got %d", mock.callCount)
    }
    
    // Responses should be equal
    if resp1.String() != resp2.String() {
        t.Fatalf("Responses differ")
    }
}
```

---

## 8. PERFORMANCE CONSIDERATIONS

### 8.1 Memory Usage

**Estimate:** Each cached DNS response ~500 bytes average
- Default 1000 entries = ~500 KB
- Can grow to GB with misconfiguration

**Mitigations:**
1. Set reasonable MaxSize
2. Implement periodic cleanup
3. Monitor cache hit ratio
4. Consider eviction policy

### 8.2 Cache Key Performance

**Option 1: String concatenation (fast)**
```go
return q.Name + ":" + dns.TypeToString[q.Qtype]
```

**Option 2: Query packing (slower but unique)**
```go
packed, _ := query.Pack()
return string(packed)
```

**Recommendation:** Use string concatenation (Name:Type format)

### 8.3 Lock Contention

**High contention if:**
- Many concurrent queries
- Slow upstream resolver
- Long cache hit path

**Solutions:**
1. Use RWMutex (already recommended)
2. Use smaller granularity locks per bucket (advanced)
3. Ensure cache misses are fast

---

## 9. INTEGRATION POINTS

### 9.1 Files to Create/Modify

**New files:**
- `/home/user/secDNS/internal/upstream/resolvers/cache/types.go` - Main implementation
- `/home/user/secDNS/internal/upstream/resolvers/cache/errors.go` - Error types (optional)

**Modify:**
- `/home/user/secDNS/internal/features/features.go` - Import cache package for registration
- Config files - Add cache resolver examples

### 9.2 Feature Registration

**In `/home/user/secDNS/internal/features/features.go`:**
```go
import (
    _ "github.com/zhouchenh/secDNS/internal/upstream/resolvers/cache"
)
```

The blank import (`_`) ensures the `init()` function in types.go runs.

---

## 10. RECOMMENDED IMPLEMENTATION ORDER

1. **Basic structure** - Implement resolver interface, depth checking
2. **Simple cache** - In-memory map with RWMutex
3. **Query handling** - Cache key generation, cache hits/misses
4. **Response handling** - Copy responses before caching, TTL calculation
5. **Registration** - Add descriptor for configuration
6. **Error handling** - Proper error propagation
7. **Eviction** - Add size limit and cleanup
8. **Optimization** - Performance tuning, metrics (optional)

---

## 11. KEY ARCHITECTURAL PATTERNS TO FOLLOW

**From existing codebase:**

1. **Depth parameter check** - ALWAYS check depth < 0 first
2. **Never modify original query** - Copy if needed, restore if modified
3. **Copy responses before caching** - Use `response.Copy()`
4. **Use sync.Once for initialization** - Thread-safe lazy init
5. **Use sync.RWMutex for cache** - Multiple readers, single writer
6. **Implement NameServerResolver marker** - Empty method for type checking
7. **Register in init()** - Use descriptor system
8. **Error handling** - Propagate upstream errors immediately
9. **TTL respect** - Honor upstream TTLs when possible
10. **Configuration flexibility** - Allow TTL and size customization


# secDNS Architecture Analysis - Index

## Quick Reference Guide

This directory now contains comprehensive analysis documents for understanding and extending the secDNS resolver architecture.

### Documents

1. **ARCHITECTURE_ANALYSIS.md** (1303 lines)
   - Complete codebase architecture analysis
   - Resolver interfaces and patterns
   - Configuration system details
   - Thread safety and performance patterns
   - Location: `/home/user/secDNS/ARCHITECTURE_ANALYSIS.md`

2. **CACHING_RESOLVER_DESIGN_GUIDE.md** 
   - Practical guide for implementing a caching resolver
   - Specific code patterns and examples
   - Thread safety considerations
   - Configuration and registration patterns
   - Location: `/home/user/secDNS/CACHING_RESOLVER_DESIGN_GUIDE.md`

---

## Key File Locations

### Core Resolver Interface
- **Package:** `github.com/zhouchenh/secDNS/pkg/upstream/resolver`
- **File:** `/home/user/secDNS/pkg/upstream/resolver/types.go` (Lines 8-12)
- **Interface:** `Resolver` with 3 methods:
  - `Type() descriptor.Type`
  - `TypeName() string`
  - `Resolve(query *dns.Msg, depth int) (*dns.Msg, error)`

### Resolver Registration
- **File:** `/home/user/secDNS/pkg/upstream/resolver/registration.go`
- **Mechanism:** Global map with `RegisterResolver(describable descriptor.Describable)`

### Resolver Implementations
- **Location:** `/home/user/secDNS/internal/upstream/resolvers/`
- **Structure:**
  ```
  resolvers/
  ├── nameserver/       - TCP/UDP/DoT queries
  ├── doh/              - DNS over HTTPS
  ├── address/          - Direct IP responses
  ├── dns64/            - IPv6 synthesis
  ├── filter/           - Response filtering
  ├── sequence/         - Fallback resolver
  ├── concurrent/       - Parallel queries
  └── alias/            - CNAME aliasing
  ```

### Configuration System
- **Loader:** `/home/user/secDNS/internal/config/loader.go`
- **Config Types:** `/home/user/secDNS/internal/config/types.go`
- **Descriptor Pattern:** Uses `go-descriptor` for declarative config parsing

### ECS (EDNS Client Subnet)
- **Location:** `/home/user/secDNS/internal/edns/ecs/ecs.go`
- **Modes:** passthrough, add, override
- **Integration:** NameServer and DoH resolvers support ECS

---

## Design Patterns Summary

### 1. Depth Parameter Usage
```go
if depth < 0 {
    return nil, resolver.ErrLoopDetected
}
// ... resolver logic ...
reply, err := upstream.Resolve(query, depth-1)  // DECREMENT!
```

### 2. Query Handling
- **Never modify original query** (affects caller)
- Use `query.Copy()` if modifications needed
- Or save/restore pattern for temporary changes

### 3. Response Handling
- Always copy before caching: `response.Copy()`
- Preserve upstream TTLs when possible
- Filter records via `common.FilterResourceRecords()`

### 4. Thread Safety
- **Initialization:** Use `sync.Once` for lazy init
- **Cache Access:** Use `sync.RWMutex` (multiple readers, single writer)
- **Concurrency:** Use `sync.Once` + `sync.WaitGroup` for racing

### 5. Configuration
- Each resolver type registers descriptor in `init()`
- Supports nested resolver references by name
- Validation via `descriptor.ConvertibleKind`

### 6. Error Handling
- Check `depth < 0` first (loop detection)
- Propagate upstream errors immediately
- Don't suppress resolver errors

---

## Key Existing Resolvers by Pattern

### Wrapper Resolvers (Transform Responses)
- **DNS64:** `/home/user/secDNS/internal/upstream/resolvers/dns64/types.go`
  - Converts A responses to AAAA
  - Modifies query type, calls upstream, restores query type

- **FilterOutA/AAAA:** `/home/user/secDNS/internal/upstream/resolvers/filter/out/`
  - Filters records from all DNS sections
  - Returns empty response for blocked types

### Sequential Resolver (Fallback)
- **Sequence:** `/home/user/secDNS/internal/upstream/resolvers/sequence/types.go`
  - Tries each resolver in order
  - Returns first success or last error

### Concurrent Resolver (Racing)
- **ConcurrentNameServerList:** `/home/user/secDNS/internal/upstream/resolvers/concurrent/nameserver/list/types.go`
  - Launches all requests in parallel
  - Uses `sync.Once` to return first success
  - Uses `sync.WaitGroup` for synchronization

### Base Resolvers (Direct Response)
- **NameServer:** `/home/user/secDNS/internal/upstream/resolvers/nameserver/types.go`
  - TCP/UDP/DoT to upstream nameserver
  - Supports ECS, SOCKS5, custom timeout
  - Lazy initializes clients via `sync.Once`
  - TCP fallback for truncated UDP responses

- **DoH:** `/home/user/secDNS/internal/upstream/resolvers/doh/types.go`
  - HTTPS transport for DNS queries
  - Concurrent requests to multiple resolved URLs
  - Dynamic URL resolution with retries
  - Supports ECS, SOCKS5

- **Address:** `/home/user/secDNS/internal/upstream/resolvers/address/types.go`
  - Direct hardcoded IP responses
  - 60 second TTL

---

## Caching Resolver Implementation Checklist

```
MUST DO:
[ ] Check depth < 0 at start
[ ] Decrement depth when calling upstream
[ ] Copy responses before caching: response.Copy()
[ ] Use sync.RWMutex for cache (RLock for reads, Lock for writes)
[ ] Use sync.Once for initialization
[ ] Implement NameServerResolver marker method
[ ] Register in init() with descriptor system
[ ] Never modify original query parameter
[ ] Propagate upstream errors immediately
[ ] Return cached response with nil error

SHOULD DO:
[ ] Calculate TTL from response RRs
[ ] Implement eviction when cache full
[ ] Periodic cleanup of expired entries
[ ] Configuration for TTL and max size
[ ] Error caching with shorter TTL (optional)
[ ] Release locks before slow operations
[ ] Handle concurrency properly (RWMutex)

EXAMPLES TO FOLLOW:
[ ] DNS64 for response transformation pattern
[ ] NameServer for thread-safe client initialization
[ ] DoH for concurrent queries
[ ] Sequence for simple delegation
[ ] FilterOutA for record filtering
```

---

## Critical Patterns to Remember

### 1. Query Handling
```go
// CORRECT: Use original query as-is
reply, err := upstream.Resolve(query, depth-1)

// If need to check alternate type:
originalType := query.Question[0].Qtype
query.Question[0].Qtype = dns.TypeAAAA
reply, err := upstream.Resolve(query, depth-1)
query.Question[0].Qtype = originalType  // RESTORE!
```

### 2. Response Caching
```go
// CORRECT: Copy before storing
cached := response.Copy()
c.cache[key] = cached

// WRONG: Direct storage
c.cache[key] = response  // Response might be modified by upstream
```

### 3. Thread Safety
```go
// CORRECT: Release lock early
c.mutex.RLock()
entry, exists := c.cache[key]
c.mutex.RUnlock()  // Release NOW

if exists {
    return entry, nil
}

// Upstream query without lock
reply, err := c.upstream.Resolve(query, depth-1)

// WRONG: Lock held during slow operation
c.mutex.RLock()
entry, exists := c.cache[key]
if exists {
    // Long operation here with lock held!
}
c.mutex.RUnlock()
```

### 4. Configuration
```go
// Resolver type in JSON:
"resolvers": {
    "cache": {
        "MyCached": {
            "resolver": "SomeResolver",  // By name
            "ttl": 300,
            "maxSize": 5000
        }
    }
}
```

---

## Testing Files to Study

- **NameServer ECS config:** `/home/user/secDNS/examples/ecs-config.json`
- **Main config:** `/home/user/secDNS/config.json`
- **ECS implementation:** `/home/user/secDNS/internal/edns/ecs/ecs.go`
- **ECS tests:** `/home/user/secDNS/internal/edns/ecs/ecs_test.go`

---

## Common Gotchas and Solutions

### Gotcha 1: Modifying Original Query
```go
// WRONG - affects caller
query.Question[0].Qtype = dns.TypeAAAA
reply, err := upstream.Resolve(query, depth-1)
// Caller's query is now AAAA instead of A!

// FIX 1: Restore after
originalType := query.Question[0].Qtype
query.Question[0].Qtype = dns.TypeAAAA
reply, err := upstream.Resolve(query, depth-1)
query.Question[0].Qtype = originalType

// FIX 2: Use copy
queryCopy := query.Copy()
queryCopy.Question[0].Qtype = dns.TypeAAAA
reply, err := upstream.Resolve(queryCopy, depth-1)
```

### Gotcha 2: Not Copying Cached Response
```go
// WRONG - upstream might reuse/modify this object
c.cache[key] = response

// CORRECT - store copy
c.cache[key] = response.Copy()
```

### Gotcha 3: Forgetting Depth Check
```go
// WRONG - allows infinite loops
func (c *Cache) Resolve(query *dns.Msg, depth int) (*dns.Msg, error) {
    // ... logic ... 
    reply, err := c.upstream.Resolve(query, depth-1)  // Forgot check!
}

// CORRECT
func (c *Cache) Resolve(query *dns.Msg, depth int) (*dns.Msg, error) {
    if depth < 0 {
        return nil, resolver.ErrLoopDetected
    }
    reply, err := c.upstream.Resolve(query, depth-1)
}
```

### Gotcha 4: Not Decrementing Depth
```go
// WRONG - depth never decreases
reply, err := c.upstream.Resolve(query, depth)  // Same depth!

// CORRECT
reply, err := c.upstream.Resolve(query, depth-1)  // Decremented
```

### Gotcha 5: Holding Lock During Slow Operation
```go
// WRONG - lock held during upstream query
c.mutex.RLock()
cached, _ := c.cache[key]
if !cached {
    upstream.Resolve(query, depth-1)  // Slow! Lock still held!
}
c.mutex.RUnlock()

// CORRECT - release lock early
c.mutex.RLock()
cached, _ := c.cache[key]
c.mutex.RUnlock()  // Release before slow op

if !cached {
    upstream.Resolve(query, depth-1)  // No lock
}
```

---

## Next Steps for Implementation

1. Read **CACHING_RESOLVER_DESIGN_GUIDE.md** for implementation details
2. Study DNS64 resolver pattern in `/home/user/secDNS/internal/upstream/resolvers/dns64/types.go`
3. Review NameServer concurrent patterns in `/home/user/secDNS/internal/upstream/resolvers/nameserver/types.go`
4. Check ECS integration in `/home/user/secDNS/internal/edns/ecs/ecs.go`
5. Create `/home/user/secDNS/internal/upstream/resolvers/cache/types.go`
6. Add blank import to `/home/user/secDNS/internal/features/features.go`
7. Test with config examples


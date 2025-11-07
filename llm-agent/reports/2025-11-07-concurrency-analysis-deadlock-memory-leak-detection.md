# Concurrency Analysis Report: Deadlock and Memory Leak Detection

**Date:** 2025-11-07
**Analysis Scope:** secDNS codebase focusing on concurrency patterns
**Files Analyzed:** 3 core files with goroutines and synchronization

---

## Executive Summary

Found **5 critical issues** and **2 moderate issues** related to race conditions, potential deadlocks, resource leaks, and goroutine leaks.

### Critical Issues
1. Race condition in DoH resolver initialization
2. Race condition in DoH resolver URL list modification
3. Race condition in core instance nameResolverMap access
4. HTTP response body not using defer Close()
5. Unbounded goroutine spawning in error handlers

### Moderate Issues
1. Channel operation could block in errCollector draining
2. Potential recursive call depth issue in DoH resolver

---

## Issue #1: Race Condition in DoH Initialization (CRITICAL)

**File:** `internal/upstream/resolvers/doh/types.go:52-59`

### Description
The `initializing` flag is not protected by a mutex, causing a race condition when multiple goroutines call `Resolve()` simultaneously.

```go
if d.initializing {
    return nil, ErrResolverNotReady
}
if d.queryClient == nil {
    d.initializing = true  // ⚠️ Race: Multiple goroutines can reach here
    d.initClient()
    d.initializing = false
}
```

### Impact
- Multiple goroutines can simultaneously call `initClient()`
- Data race when reading/writing `d.initializing`
- Potential double initialization of `d.queryClient`
- Crashes or unpredictable behavior

### Race Scenario
```
Time    Goroutine 1              Goroutine 2
----    ----------------------   ----------------------
T1      Check: initializing=false
T2                                Check: initializing=false
T3      Check: queryClient=nil
T4                                Check: queryClient=nil
T5      Set: initializing=true
T6                                Set: initializing=true  ← Race!
T7      initClient()
T8                                initClient()  ← Double init!
```

### Fix Recommendation
Use `sync.Once` or `sync.Mutex`:

```go
type DoH struct {
    // ... existing fields
    initOnce sync.Once
}

func (d *DoH) Resolve(query *dns.Msg, depth int) (*dns.Msg, error) {
    // ...
    d.initOnce.Do(func() {
        d.initClient()
    })
    // ...
}
```

---

## Issue #2: Race Condition in DoH URL List Modification (CRITICAL)

**File:** `internal/upstream/resolvers/doh/types.go:115`

### Description
The `resolvedURLs` slice is modified concurrently without synchronization.

```go
go func() {
    wg.Wait()
    once.Do(func() {
        resolvedURLs := d.resolveURL(depth - 1)
        if len(resolvedURLs) >= 1 {
            d.queryClient.resolvedURLs = resolvedURLs  // ⚠️ Race: Concurrent write
        }
    })
}()
```

Meanwhile, on line 101, the same slice is being iterated:
```go
for _, urlString := range d.queryClient.resolvedURLs {  // ⚠️ Race: Concurrent read
    go sendRequest(urlString)
}
```

### Impact
- Data race when modifying `resolvedURLs` while another `Resolve()` call is iterating it
- Slice corruption possible
- Runtime panic: concurrent map read and write
- Incorrect DNS resolution results

### Fix Recommendation
Use atomic operations or mutex to protect access:

```go
type client struct {
    httpClient   *http.Client
    serverName   string
    resolvedURLs []string
    urlMutex     sync.RWMutex  // Add mutex
}

// Reading:
d.queryClient.urlMutex.RLock()
urls := d.queryClient.resolvedURLs
d.queryClient.urlMutex.RUnlock()

// Writing:
d.queryClient.urlMutex.Lock()
d.queryClient.resolvedURLs = resolvedURLs
d.queryClient.urlMutex.Unlock()
```

---

## Issue #3: Race Condition in Core Instance Map Access (CRITICAL)

**File:** `internal/core/instance.go`

### Description
The `nameResolverMap` is accessed without synchronization in multiple goroutines.

**Writes (lines 52-55):**
```go
func (i *instance) AcceptProvider(...) {
    // ...
    i.nameResolverMap[name] = r  // ⚠️ Write without lock
}
```

**Reads (lines 134-148):**
```go
func (i *instance) Resolve(...) {
    if r, ok := i.nameResolverMap["\""+name+"\""]; ok {  // ⚠️ Read without lock
        // ...
    }
    for level := 0; level < len(labels)-1; level++ {
        if r, ok := i.nameResolverMap[domainName]; ok {  // ⚠️ Read without lock
```

### Impact
- Map corruption and runtime panic
- Go's map implementation is not thread-safe
- Fatal error: concurrent map read and map write
- Server crash under concurrent DNS queries

### Race Scenario
```
Goroutine 1 (AcceptProvider):     Goroutine 2 (Resolve):
i.nameResolverMap[name] = r   →   if r, ok := i.nameResolverMap[name]
                                   ↑ PANIC: concurrent map access
```

### Fix Recommendation
Use `sync.RWMutex`:

```go
type instance struct {
    listeners       []server.Server
    nameResolverMap map[string]resolver.Resolver
    mapMutex        sync.RWMutex  // Add this
    defaultResolver resolver.Resolver
    resolutionDepth int
}

// In AcceptProvider:
i.mapMutex.Lock()
i.nameResolverMap[name] = r
i.mapMutex.Unlock()

// In Resolve:
i.mapMutex.RLock()
r, ok := i.nameResolverMap[name]
i.mapMutex.RUnlock()
```

---

## Issue #4: HTTP Response Body Not Using defer Close() (CRITICAL)

**File:** `internal/upstream/resolvers/doh/types.go:86-87`

### Description
HTTP response body is closed immediately without defer, risking resource leak.

```go
response, e := d.queryClient.httpClient.Do(request)
if e != nil {
    errCollector <- e
    wg.Done()
    return
}
wireFormattedMsg, e := ioutil.ReadAll(response.Body)
response.Body.Close()  // ⚠️ Not deferred - leak if panic occurs
```

### Impact
- If `ioutil.ReadAll()` panics, body never closes
- HTTP connection leak (connections stay open)
- Eventually exhausts file descriptors
- Server degrades over time under load

### Fix Recommendation
```go
response, e := d.queryClient.httpClient.Do(request)
if e != nil {
    errCollector <- e
    wg.Done()
    return
}
defer response.Body.Close()  // ✓ Safe even on panic
wireFormattedMsg, e := ioutil.ReadAll(response.Body)
```

---

## Issue #5: Unbounded Goroutine Spawning in Error Handlers (CRITICAL)

**File:** `internal/core/instance.go`

### Description
Error handlers spawn goroutines without any limit or tracking.

**Lines 57, 104, 109:**
```go
go handleIfError(err, errorHandler)  // ⚠️ No limit on goroutines
```

### Impact
- Under high error rates, thousands of goroutines could spawn
- Goroutine leak - they're never tracked or reaped
- Memory exhaustion
- Scheduler overhead degrades performance

### Calculation
If errors occur at 1000/sec:
- 1000 goroutines/sec spawned
- Each goroutine takes ~5KB stack
- In 1 minute: 60,000 goroutines = ~300MB
- If error handler is slow, memory grows indefinitely

### Fix Recommendation
Use a worker pool or rate limiter:

```go
type instance struct {
    // ...
    errorChan chan error
    errorPool *sync.Pool  // Or use a fixed worker pool
}

func (i *instance) startErrorHandlerPool(errorHandler func(error)) {
    // Fixed number of workers
    for w := 0; w < 10; w++ {
        go func() {
            for err := range i.errorChan {
                errorHandler(err)
            }
        }()
    }
}

// Instead of: go handleIfError(err, errorHandler)
// Use: i.errorChan <- err
```

Or simpler, just call directly:
```go
handleIfError(err, errorHandler)  // No goroutine needed
```

---

## Issue #6: Potential Blocking in errCollector Drain (MODERATE)

**File:** `internal/upstream/resolvers/doh/types.go:124-127`

### Description
The code drains `errCollector` assuming at least one error exists, but this may not be guaranteed.

```go
once.Do(func() {
    // ...
    msg <- nil
    for len(errCollector) > 1 {  // ⚠️ What if len(errCollector) == 0?
        <-errCollector
    }
    err <- <-errCollector  // ⚠️ Blocks if channel is empty
})
```

### Impact
- If logic error leads to empty `errCollector`, this blocks forever
- Goroutine leak (goroutine never exits)
- DNS query never completes
- Client timeout

### Scenario
If all requests fail but don't send to `errCollector` due to a bug, the final `<-errCollector` blocks forever.

### Fix Recommendation
```go
msg <- nil
if len(errCollector) > 0 {
    for len(errCollector) > 1 {
        <-errCollector
    }
    err <- <-errCollector
} else {
    err <- ErrNoResponsesReceived
}
```

---

## Issue #7: Deep Recursion in DoH Resolver (MODERATE)

**File:** `internal/upstream/resolvers/doh/types.go:117`

### Description
The DoH resolver can recursively call itself within the goroutine, potentially bypassing depth checks.

```go
once.Do(func() {
    resolvedURLs := d.resolveURL(depth - 1)
    // ...
    m, e := d.Resolve(query, depth-1)  // ⚠️ Recursive call in goroutine
```

### Impact
- Depth check on line 49 may not properly limit recursion when calls are async
- Stack overflow possible in pathological cases
- Resource exhaustion

### Fix Recommendation
Ensure depth is checked before recursive call, or restructure to avoid recursion in the goroutine.

---

## Summary Table

| Issue | Severity | File | Lines | Type | Fix Complexity |
|-------|----------|------|-------|------|----------------|
| DoH init race | Critical | doh/types.go | 52-59 | Race condition | Low (use sync.Once) |
| DoH URL race | Critical | doh/types.go | 115 | Race condition | Medium (add mutex) |
| Map access race | Critical | instance.go | 52-55, 134-148 | Race condition | Medium (add RWMutex) |
| Body not deferred | Critical | doh/types.go | 87 | Resource leak | Low (add defer) |
| Unbounded goroutines | Critical | instance.go | 57, 104, 109 | Goroutine leak | Medium (worker pool) |
| errCollector drain | Moderate | doh/types.go | 127 | Potential deadlock | Low (add check) |
| Deep recursion | Moderate | doh/types.go | 117 | Stack overflow | Medium (refactor) |

---

## Detection Methods

These issues can be detected using:

1. **Go Race Detector:**
   ```bash
   go build -race
   go test -race ./...
   ```

2. **Static Analysis:**
   ```bash
   go vet ./...
   staticcheck ./...
   ```

3. **Load Testing:**
   - Send concurrent DNS queries
   - Monitor goroutine count: `runtime.NumGoroutine()`
   - Monitor memory: `runtime.ReadMemStats()`

4. **Manual Code Review:**
   - Look for shared mutable state without locks
   - Check all map accesses
   - Verify defer on all resource cleanup

---

## Reproduction Steps

### Issue #1 & #2 (DoH Races):
```bash
# Build with race detector
go build -race -o bin/secDNS main.go

# Configure with DoH resolver
# Send concurrent queries
for i in {1..100}; do
    dig @localhost -p 5353 www.google.com &
done
wait

# Race detector will report data races
```

### Issue #3 (Map Race):
```bash
# Start server with rules provider that modifies map
# Send concurrent DNS queries from multiple clients
ab -n 10000 -c 100 http://localhost/dns-query

# Or use DNS benchmark tools
dnsperf -s localhost -p 5353 -d queries.txt
```

### Issue #5 (Goroutine Leak):
```go
// Monitor goroutine count
go func() {
    for {
        fmt.Println("Goroutines:", runtime.NumGoroutine())
        time.Sleep(1 * time.Second)
    }
}()

// Send queries with errors
// Watch goroutine count grow unbounded
```

---

## Recommendations

### Immediate Fixes (Critical Priority)
1. Add `sync.Once` for DoH initialization
2. Add `sync.RWMutex` for nameResolverMap access
3. Change `response.Body.Close()` to `defer response.Body.Close()`
4. Remove `go` keyword from error handler calls or implement worker pool

### Medium Priority
1. Add mutex protection for DoH resolvedURLs access
2. Add safety check before draining errCollector
3. Review recursion logic in DoH resolver

### Long-term Improvements
1. Add comprehensive race detector testing to CI/CD
2. Add goroutine leak detection tests
3. Implement metrics for goroutine count monitoring
4. Add load testing to detect concurrency issues
5. Consider using atomic operations where appropriate

---

## Testing Strategy

```go
// Add to test suite
func TestConcurrentDNSQueries(t *testing.T) {
    // Test with race detector enabled
    instance := core.NewInstance()
    // Configure instance...

    var wg sync.WaitGroup
    for i := 0; i < 100; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            query := new(dns.Msg)
            query.SetQuestion("example.com.", dns.TypeA)
            _, err := instance.Resolve(query, 64)
            if err != nil {
                t.Error(err)
            }
        }()
    }
    wg.Wait()
}
```

---

**End of Report**

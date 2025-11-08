# secDNS Codebase Architecture Analysis

## 1. RESOLVER ARCHITECTURE

### 1.1 Core Resolver Interface
**Location:** `/home/user/secDNS/pkg/upstream/resolver/types.go` (Lines 8-12)

```go
type Resolver interface {
    Type() descriptor.Type
    TypeName() string
    Resolve(query *dns.Msg, depth int) (*dns.Msg, error)
}
```

**Key Characteristics:**
- Simple, clean interface with 3 methods
- `Resolve(query, depth)` is the main contract
- `depth` parameter is used for loop detection (decremented on each recursive call)
- All resolvers must return `ErrLoopDetected` when `depth < 0`

**Query Flow Pattern:**
```
Client Query → Listener → Instance.Resolve(query, initialDepth)
    → DefaultResolver or NamedResolver
    → Each resolver: Resolve(query, depth-1)
    → Returns *dns.Msg or error
    → Response back to client
```

### 1.2 Loop Detection & Depth Parameter
**Location:** Throughout all resolver implementations

**Pattern Used:**
```go
func (r *Resolver) Resolve(query *dns.Msg, depth int) (*dns.Msg, error) {
    if depth < 0 {
        return nil, resolver.ErrLoopDetected  // Line checked in all resolvers
    }
    // ... resolver logic ...
    reply, err := r.UpstreamResolver.Resolve(query, depth-1)  // Decrement on each call
    return reply, err
}
```

**Default Depth:** 64 (configurable in config)
- Set in `/home/user/secDNS/internal/config/types.go` Line 206
- Can be overridden via config `resolutionDepth` field

### 1.3 Resolver Registration System
**Location:** `/home/user/secDNS/pkg/upstream/resolver/registration.go`

**Registration Pattern:**
- Global map: `registeredResolver = make(map[string]descriptor.Describable)`
- Each resolver type registers itself in `init()` function
- Uses the `go-descriptor` package for configuration parsing
- Resolver names must be unique

**Example Registration (dns64):**
```
/home/user/secDNS/internal/upstream/resolvers/dns64/types.go (Lines 99-172)
```

---

## 2. EXISTING RESOLVER PATTERNS

### 2.1 Wrapper Resolvers (Composition Pattern)

#### DNS64 Resolver
**File:** `/home/user/secDNS/internal/upstream/resolvers/dns64/types.go`
**Lines:** 11-63

```go
type DNS64 struct {
    Resolver           resolver.Resolver
    Prefix             net.IP
    IgnoreExistingAAAA bool
}
```

**Key Pattern:**
- Wraps an upstream resolver
- Modifies behavior based on query type
- For AAAA queries: converts A responses to AAAA using configured prefix
- Delegates to upstream for other query types

**Response Modification Pattern:**
```go
// Line 48-50: Modify query, call upstream, restore query
query.Question[0].Qtype = dns.TypeA
reply, err := d.Resolver.Resolve(query, depth-1)
query.Question[0].Qtype = dns.TypeAAAA

// Lines 54-61: Modify response records
if isNoErrorReply(reply) {
    for i := range reply.Answer {
        if a, ok := reply.Answer[i].(*dns.A); ok {
            reply.Answer[i] = d.aToAAAA(a)  // Type conversion
        }
    }
}
```

#### Filter Resolvers
**Files:**
- `/home/user/secDNS/internal/upstream/resolvers/filter/out/a/types.go`
- `/home/user/secDNS/internal/upstream/resolvers/filter/out/aaaa/types.go`
- `/home/user/secDNS/internal/upstream/resolvers/filter/out/a/if/aaaa/presents/types.go`

**Pattern: Response Filtering**
```go
type FilterOutA struct {
    Resolver resolver.Resolver
}

func (fa *FilterOutA) Resolve(query *dns.Msg, depth int) (*dns.Msg, error) {
    if depth < 0 {
        return nil, resolver.ErrLoopDetected
    }
    
    switch query.Question[0].Qtype {
    case dns.TypeA:
        // For A queries, return empty response
        msg := new(dns.Msg)
        msg.SetReply(query)
        return msg, nil
    default:
        // For other types, call upstream and filter
        reply, err := fa.Resolver.Resolve(query, depth-1)
        if err != nil {
            return nil, err
        }
        
        // Filter A records from all sections
        notA := func(rr dns.RR) bool {
            _, isA := rr.(*dns.A)
            return !isA
        }
        reply.Answer = common.FilterResourceRecords(reply.Answer, notA)
        reply.Ns = common.FilterResourceRecords(reply.Ns, notA)
        reply.Extra = common.FilterResourceRecords(reply.Extra, notA)
        return reply, nil
    }
}
```

**Critical Pattern: Filtering Helper**
`/home/user/secDNS/internal/common/common.go` (Lines 106-113)
```go
func FilterResourceRecords(records []dns.RR, predicate func(rr dns.RR) bool) (result []dns.RR) {
    for _, record := range records {
        if predicate(record) {
            result = append(result, record)
        }
    }
    return
}
```

#### Conditional Filter Resolver
**File:** `/home/user/secDNS/internal/upstream/resolvers/filter/out/a/if/aaaa/presents/types.go`
**Lines:** 24-54

**Pattern: Two-Phase Resolution**
```go
// Phase 1: Check if AAAA exists
canResolveToAAAA, err := fa.canResolveToAAAA(query, depth)
if err != nil {
    return nil, err
}

// Phase 2: Modify behavior based on result
if !canResolveToAAAA {
    return fa.Resolver.Resolve(query, depth-1)  // Normal resolution
}

// Filter A records if AAAA exists
switch query.Question[0].Qtype {
case dns.TypeA:
    msg := new(dns.Msg)
    msg.SetReply(query)  // Empty response
    return msg, nil
}
```

**Important:** Note how the original query is temporarily modified and restored:
```go
originalQuestionType := query.Question[0].Qtype
query.Question[0].Qtype = dns.TypeAAAA
reply, err := fa.Resolver.Resolve(query, depth-1)
query.Question[0].Qtype = originalQuestionType  // RESTORE!
```

#### Alias Resolver
**File:** `/home/user/secDNS/internal/upstream/resolvers/alias/types.go`

**Pattern: Query Modification and Delegation**
```go
func (alias *Alias) Resolve(query *dns.Msg, depth int) (*dns.Msg, error) {
    if depth < 0 {
        return nil, resolver.ErrLoopDetected
    }
    
    msg := new(dns.Msg)
    msg.SetReply(query)
    
    // Add CNAME record
    msg.Answer = append(msg.Answer, &dns.CNAME{
        Hdr:    dns.RR_Header{Name: query.Question[0].Name, ...},
        Target: alias.Alias,
    })
    
    // For A/AAAA queries, resolve the alias target
    if qType == dns.TypeA || qType == dns.TypeAAAA {
        q := new(dns.Msg)
        q.SetQuestion(alias.Alias, qType)
        r, err := alias.Resolver.Resolve(q, depth-1)
        if err != nil {
            return nil, err
        }
        msg.Answer = append(msg.Answer, r.Answer...)  // Append results
    }
    return msg, nil
}
```

### 2.2 Sequence Resolver (Fallback Pattern)
**File:** `/home/user/secDNS/internal/upstream/resolvers/sequence/types.go`

```go
type Sequence []resolver.Resolver

func (seq *Sequence) Resolve(query *dns.Msg, depth int) (*dns.Msg, error) {
    if depth < 0 {
        return nil, resolver.ErrLoopDetected
    }
    
    if len(*seq) < 1 {
        return nil, ErrNoAvailableResolver
    }
    
    var msg *dns.Msg
    var err error
    for _, r := range *seq {
        if r == nil {
            err = ErrNilResolver
            continue  // Skip nil resolvers
        }
        msg, err = r.Resolve(query, depth-1)
        if err != nil {
            continue  // Try next on error
        }
        break  // Success - stop iteration
    }
    return msg, err  // Last error or last result
}
```

**Key Pattern:** Tries each resolver in order, returns first successful result

### 2.3 Concurrent Resolver (Race Pattern)
**File:** `/home/user/secDNS/internal/upstream/resolvers/concurrent/nameserver/list/types.go`

**Thread Safety Pattern using sync.Once and sync.WaitGroup:**
```go
func (nsl *ConcurrentNameServerList) Resolve(query *dns.Msg, depth int) (*dns.Msg, error) {
    if depth < 0 {
        return nil, resolver.ErrLoopDetected
    }
    
    once := new(sync.Once)              // Ensures only first goroutine wins
    msg := make(chan *dns.Msg)          // Single value channel
    err := make(chan error)             // Single value channel
    errCollector := make(chan error, len(*nsl))  // Buffered for all
    wg := new(sync.WaitGroup)
    wg.Add(len(*nsl))
    
    request := func(r resolver.Resolver) {
        defer wg.Done()
        
        if r != nil {
            m, e := r.Resolve(query, depth-1)
            if e == nil {
                once.Do(func() {
                    msg <- m
                    err <- nil  // First success wins
                })
            } else {
                errCollector <- e
            }
        }
    }
    
    for _, nameServerResolver := range *nsl {
        go request(nameServerResolver)  // All run in parallel
    }
    
    go func() {
        wg.Wait()
        once.Do(func() {  // Called if no success
            msg <- nil
            if len(errCollector) > 0 {
                err <- <-errCollector
            }
        })
    }()
    
    return <-msg, <-err
}
```

**Critical Patterns:**
- `sync.Once` ensures only one response is returned
- `sync.WaitGroup` synchronizes all goroutines
- Buffered error channel for collecting all failures
- First successful result wins the race

### 2.4 Simple Resolvers

#### Address Resolver
**File:** `/home/user/secDNS/internal/upstream/resolvers/address/types.go`

**Pattern: Direct Response Generation**
```go
func (addr *Address) Resolve(query *dns.Msg, depth int) (*dns.Msg, error) {
    if depth < 0 {
        return nil, resolver.ErrLoopDetected
    }
    
    msg := new(dns.Msg)
    msg.SetReply(query)  // Set response flag and ID
    
    switch query.Question[0].Qtype {
    case dns.TypeA:
        for _, ip := range addr[v4] {
            msg.Answer = append(msg.Answer, &dns.A{
                Hdr: dns.RR_Header{
                    Name:   query.Question[0].Name,
                    Rrtype: dns.TypeA,
                    Class:  dns.ClassINET,
                    Ttl:    60,
                },
                A: ip,
            })
        }
    case dns.TypeAAAA:
        for _, ip := range addr[v6] {
            msg.Answer = append(msg.Answer, &dns.AAAA{
                Hdr:  dns.RR_Header{...},
                AAAA: ip,
            })
        }
    }
    return msg, nil
}
```

**TTL Pattern:** Hard-coded to 60 seconds

#### NoAnswer Resolver
**File:** `/home/user/secDNS/internal/upstream/resolvers/no/answer/resolver/types.go`

```go
func (na *NoAnswerResolver) Resolve(query *dns.Msg, depth int) (*dns.Msg, error) {
    if depth < 0 {
        return nil, resolver.ErrLoopDetected
    }
    
    msg := new(dns.Msg)
    msg.SetReply(query)  // Response with no answers (NODATA)
    return msg, nil
}
```

---

## 3. NAMESERVER RESOLVER (Base Resolver)

**File:** `/home/user/secDNS/internal/upstream/resolvers/nameserver/types.go`

### 3.1 Structure and Thread Safety
```go
type NameServer struct {
    Address           net.IP
    Port              uint16
    Protocol          string
    QueryTimeout      time.Duration
    TlsServerName     string
    SendThrough       net.IP
    Socks5Proxy       string
    Socks5Username    string
    Socks5Password    string
    EcsMode           string
    EcsClientSubnet   string
    ecsConfig         *ecs.Config
    queryClient       *client
    tcpFallbackClient *client
    initOnce          sync.Once                    // Line 33
    tcpFallbackOnce   sync.Once                    // Line 34
}
```

**Thread Safety Pattern:**
- Uses `sync.Once` for lazy initialization of clients
- Primary client created once in `initOnce.Do()`
- TCP fallback client created once in `tcpFallbackOnce.Do()`

### 3.2 Query Handling with ECS
**Lines:** 54-90

```go
func (ns *NameServer) Resolve(query *dns.Msg, depth int) (*dns.Msg, error) {
    if depth < 0 {
        return nil, resolver.ErrLoopDetected
    }
    
    ns.initOnce.Do(func() {
        ns.initClient()  // Lazy init
    })

    // Apply ECS configuration to query if configured
    if ns.ecsConfig != nil {
        // Create a copy of the query to avoid modifying the original
        queryCopy := query.Copy()  // IMPORTANT: Copy pattern
        if err := ns.ecsConfig.ApplyToQuery(queryCopy); err != nil {
            return nil, err
        }
        query = queryCopy  // Use copy for rest of function
    }

    address := net.JoinHostPort(ns.Address.String(), strconv.Itoa(int(ns.Port)))

    // Try with the configured protocol
    msg, err := ns.queryWithProtocol(query, address, ns.Protocol)
    if err != nil {
        return nil, err
    }

    // If UDP response is truncated, retry with TCP
    if msg.Truncated && ns.Protocol == "udp" {
        tcpMsg, tcpErr := ns.queryWithProtocol(query, address, "tcp")
        if tcpErr != nil {
            return msg, nil  // Return truncated response if TCP fails
        }
        return tcpMsg, nil
    }

    return msg, nil
}
```

**Critical Pattern: Query Copying**
- Original query is never modified
- `query.Copy()` creates deep copy
- ECS is applied to copy
- Original query passed to upstream as fallback

### 3.3 Protocol Handling
**Lines:** 93-124

```go
func (ns *NameServer) queryWithProtocol(query *dns.Msg, address string, protocol string) (*dns.Msg, error) {
    var clientToUse *client

    // Select appropriate client based on protocol
    if protocol == ns.Protocol {
        clientToUse = ns.queryClient
    } else if protocol == "tcp" && ns.Protocol == "udp" {
        ns.tcpFallbackOnce.Do(func() {
            ns.tcpFallbackClient = ns.createClientForProtocol("tcp")
        })
        clientToUse = ns.tcpFallbackClient  // Reuse TCP client
    } else {
        clientToUse = ns.createClientForProtocol(protocol)  // Create new
    }

    connection, err := clientToUse.Dial(address)
    if err != nil {
        return nil, err
    }
    defer connection.Close()
    _ = connection.SetDeadline(time.Now().Add(ns.QueryTimeout))
    if err := connection.WriteMsg(query); err != nil {
        return nil, err
    }
    msg, err := connection.ReadMsg()
    if err != nil {
        return nil, err
    }
    return msg, nil
}
```

**Client Reuse Pattern:**
- Primary client: created once and reused (via sync.Once)
- TCP fallback client: created once when needed, then reused
- Other protocol combinations: create temporary client (not cached)
- All respect QueryTimeout

---

## 4. DOH RESOLVER (DNS over HTTPS)

**File:** `/home/user/secDNS/internal/upstream/resolvers/doh/types.go`

### 4.1 Structure and Concurrency
```go
type DoH struct {
    URL             *url.URL
    QueryTimeout    time.Duration
    TlsServerName   string
    SendThrough     net.IP
    Resolver        resolver.Resolver  // For resolving URL hostname
    Socks5Proxy     string
    Socks5Username  string
    Socks5Password  string
    EcsMode         string
    EcsClientSubnet string
    ecsConfig       *ecs.Config
    queryClient     *client
    initOnce        sync.Once
}

type client struct {
    httpClient   *http.Client
    serverName   string
    resolvedURLs []string
    urlMutex     sync.RWMutex  // Protects resolvedURLs
}
```

**Thread Safety Patterns:**
- `sync.Once` for client initialization
- `sync.RWMutex` for protecting URL list that can be dynamically updated

### 4.2 Concurrent Query Pattern
**Lines:** 53-159

**Critical Pattern: Race-based First Success**
```go
func (d *DoH) Resolve(query *dns.Msg, depth int) (*dns.Msg, error) {
    if depth < 0 {
        return nil, resolver.ErrLoopDetected
    }
    
    d.initOnce.Do(func() {
        d.initClient()
    })

    // Apply ECS configuration (copy pattern like NameServer)
    if d.ecsConfig != nil {
        queryCopy := query.Copy()
        if err := d.ecsConfig.ApplyToQuery(queryCopy); err != nil {
            return nil, err
        }
        query = queryCopy
    }

    wireFormattedQuery, e := query.Pack()
    if e != nil {
        return nil, e
    }

    // Get a snapshot of URLs with read lock
    d.queryClient.urlMutex.RLock()
    urls := make([]string, len(d.queryClient.resolvedURLs))
    copy(urls, d.queryClient.resolvedURLs)
    d.queryClient.urlMutex.RUnlock()

    once := new(sync.Once)
    msg := make(chan *dns.Msg)
    err := make(chan error)
    errCollector := make(chan error, len(urls))
    wg := new(sync.WaitGroup)
    wg.Add(len(urls))
    
    sendRequest := func(urlString string) {
        defer wg.Done()
        request, e := http.NewRequest(http.MethodPost, urlString, bytes.NewReader(wireFormattedQuery))
        if e != nil {
            errCollector <- e
            return
        }
        request.Host = d.queryClient.serverName
        request.Header.Set("Accept", "application/dns-message")
        request.Header.Set("Content-Type", "application/dns-message")
        response, e := d.queryClient.httpClient.Do(request)
        if e != nil {
            errCollector <- e
            return
        }
        defer response.Body.Close()
        wireFormattedMsg, e := ioutil.ReadAll(response.Body)
        if e != nil {
            errCollector <- e
            return
        }
        m := new(dns.Msg)
        e = m.Unpack(wireFormattedMsg)
        if e != nil {
            errCollector <- e
            return
        }
        once.Do(func() {
            msg <- m
            err <- nil  // First success wins
        })
    }
    
    // Launch concurrent requests
    for _, urlString := range urls {
        go sendRequest(urlString)
    }
    
    // Wait for all, then handle results
    go func() {
        wg.Wait()
        once.Do(func() {
            // All failed or no URLs - try resolution
            resolvedURLs := d.resolveURL(depth - 1)
            if len(resolvedURLs) < 1 {
                if len(errCollector) < 1 {
                    msg <- nil
                    err <- UnknownHostError(d.URL.Hostname())
                    return
                }
            } else {
                // Update URL list with write lock
                d.queryClient.urlMutex.Lock()
                d.queryClient.resolvedURLs = resolvedURLs
                d.queryClient.urlMutex.Unlock()

                if len(errCollector) < 1 {
                    // Retry with new URLs
                    m, e := d.Resolve(query, depth-1)
                    msg <- m
                    err <- e
                    return
                }
            }
            msg <- nil
            if len(errCollector) > 0 {
                for len(errCollector) > 1 {
                    <-errCollector
                }
                err <- <-errCollector
            } else {
                err <- UnknownHostError(d.URL.Hostname())
            }
        })
    }()
    
    return <-msg, <-err
}
```

**Concurrent Patterns:**
- Multiple HTTP requests sent in parallel to resolved URLs
- `sync.Once` ensures only first response is used
- `sync.RWMutex` protects dynamic URL list
- URL resolution with fallback if all requests fail
- Recursive retry with newly resolved URLs

---

## 5. CONFIGURATION SYSTEM

### 5.1 Configuration Loading Flow
**File:** `/home/user/secDNS/internal/config/loader.go`

```go
func LoadConfig(r io.Reader) (core.Instance, error) {
    // 1. Read raw JSON
    rawData, err := ioutil.ReadAll(r)
    
    // 2. Parse JSON
    var data interface{}
    err = json.Unmarshal(rawData, &data)
    
    // 3. Use descriptor system to validate and populate
    rawConfig, s, f := Descriptor().Describe(data)
    ok := s > 0 && f < 1  // s: success count, f: fail count
    
    if !ok {
        return nil, ErrBadConfig
    }
    
    config, ok := rawConfig.(*Config)
    
    // 4. Create instance and populate
    instance := core.NewInstance()
    instance.AddListener(config.Listeners...)
    instance.SetDefaultResolver(config.DefaultResolver)
    instance.SetResolutionDepth(config.ResolutionDepth)
    
    // 5. Register named resolvers
    err = config.Resolvers.NameResolver("", instanceResolver)
    
    return instance, nil
}
```

### 5.2 Descriptor System
**File:** `/home/user/secDNS/internal/config/types.go`

**Pattern: Declarative Configuration**
```go
Descriptor() descriptor.Describable {
    return &descriptor.Descriptor{
        Type: typeOfConfig,
        Filler: descriptor.Fillers{
            // For each field, define how to extract and convert from raw data
            descriptor.ObjectFiller{
                ObjectPath: descriptor.Path{"Listeners"},
                ValueSource: descriptor.ObjectAtPath{
                    ObjectPath: descriptor.Path{"listeners"},  // JSON path
                    AssignableKind: descriptor.ConvertibleKind{
                        Kind: descriptor.KindSlice,
                        ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
                            arr, ok := original.([]interface{})
                            if !ok {
                                return
                            }
                            var listeners []server.Server
                            errorCount := 0
                            for _, i := range arr {
                                rawListener, s, f := server.Descriptor().Describe(i)
                                if s < 1 || f > 0 {
                                    errorCount++
                                    continue
                                }
                                listener, ok := rawListener.(server.Server)
                                if !ok {
                                    errorCount++
                                    continue
                                }
                                listeners = append(listeners, listener)
                            }
                            converted = listeners
                            ok = errorCount < 1
                            return
                        },
                    },
                },
            },
            // ... More fillers for other fields ...
            descriptor.ObjectFiller{
                ObjectPath: descriptor.Path{"ResolutionDepth"},
                ValueSource: descriptor.ValueSources{
                    descriptor.ObjectAtPath{
                        ObjectPath: descriptor.Path{"resolutionDepth"},
                        AssignableKind: descriptor.AssignableKinds{
                            descriptor.ConvertibleKind{
                                Kind: descriptor.KindFloat64,
                                ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
                                    f, ok := original.(float64)
                                    if !ok {
                                        return
                                    }
                                    converted = int(f)
                                    return
                                },
                            },
                            // ... String conversion ...
                        },
                    },
                    descriptor.DefaultValue{Value: 64},  // Default
                },
            },
        },
    }
}
```

### 5.3 Resolver Configuration
**Key Pattern:** Nested resolver configurations

```json
{
  "resolvers": {
    "nameServer": {
      "Resolver1": {
        "address": "1.1.1.1",
        "port": 53,
        "protocol": "udp",
        "queryTimeout": 2,
        "ecsMode": "add",
        "ecsClientSubnet": "192.168.1.0/24"
      }
    },
    "sequence": {
      "SequenceResolver": [
        "Resolver1",
        "Resolver2"
      ]
    }
  },
  "defaultResolver": "SequenceResolver"
}
```

**Resolution Process:**
1. Config maps resolver type (e.g., "nameServer") to its descriptor
2. Descriptor parses each named resolver instance
3. Nested resolvers resolved by name from registry
4. Final resolver graph assembled

### 5.4 Resolution Depth Configuration
**Location:** `/home/user/secDNS/internal/config/types.go` Line 174-208

- Default: 64
- Configurable via JSON: `"resolutionDepth": 100`
- Applied to all queries
- Shared across all resolvers

---

## 6. DNS MESSAGE HANDLING

### 6.1 Message Creation
**Pattern: SetReply() for Responses**
```go
msg := new(dns.Msg)
msg.SetReply(query)  // Copies ID, sets Response flag
```

**Pattern: SetQuestion() for New Queries**
```go
q := new(dns.Msg)
q.SetQuestion(hostname, dns.TypeA)
```

### 6.2 Query Modification and Restoration
**File:** `/home/user/secDNS/internal/upstream/resolvers/filter/out/a/if/aaaa/presents/types.go` (Lines 56-65)

**Critical Pattern:**
```go
func (fa *FilterOutAIfAAAAPresents) canResolveToAAAA(query *dns.Msg, depth int) (bool, error) {
    originalQuestionType := query.Question[0].Qtype  // SAVE original
    query.Question[0].Qtype = dns.TypeAAAA           // MODIFY
    reply, err := fa.Resolver.Resolve(query, depth-1)
    query.Question[0].Qtype = originalQuestionType   // RESTORE!
    if err != nil {
        return false, err
    }
    return isNoErrorReply(reply) && hasAAAA(reply), nil
}
```

**Why:** The query object is not copied - modifying it and restoring prevents affecting other code paths.

### 6.3 Query Copying
**Files:**
- `/home/user/secDNS/internal/upstream/resolvers/nameserver/types.go` Line 65
- `/home/user/secDNS/internal/upstream/resolvers/doh/types.go` Line 64

**Pattern: Deep Copy for ECS**
```go
if d.ecsConfig != nil {
    // Create a copy of the query to avoid modifying the original
    queryCopy := query.Copy()  // dns.Msg method
    if err := d.ecsConfig.ApplyToQuery(queryCopy); err != nil {
        return nil, err
    }
    query = queryCopy  // Use copy for rest of function
}
```

### 6.4 Response Record Handling

#### Answer Section
```go
msg.Answer = append(msg.Answer, &dns.A{
    Hdr: dns.RR_Header{
        Name:   query.Question[0].Name,
        Rrtype: dns.TypeA,
        Class:  dns.ClassINET,
        Ttl:    60,  // Fixed or from upstream
    },
    A: ipAddress,
})
```

#### Authority Section
```go
reply.Ns = common.FilterResourceRecords(reply.Ns, predicate)
```

#### Additional Section
```go
reply.Extra = common.FilterResourceRecords(reply.Extra, predicate)
```

### 6.5 TTL Handling
**Current Pattern:** Hard-coded values
- Address resolver: 60 seconds (Line 47, 54)
- Alias resolver: 60 seconds (Line 37)

**When preserving upstream:** TTL from upstream is preserved
- DNS64: `reply.Answer[i] = d.aToAAAA(a)` copies TTL via `a.Hdr.Ttl`
- Filters: Keep original records with original TTLs
- DoH/NameServer: Preserve upstream response as-is

---

## 7. PERFORMANCE PATTERNS

### 7.1 Concurrency Patterns

#### sync.Once for Lazy Initialization
**Pattern 1: Simple Lazy Init**
```go
type NameServer struct {
    queryClient  *client
    initOnce     sync.Once
}

func (ns *NameServer) Resolve(query *dns.Msg, depth int) (*dns.Msg, error) {
    ns.initOnce.Do(func() {
        ns.initClient()  // Called exactly once
    })
    // Use ns.queryClient
}
```

**Pattern 2: Conditional Lazy Init**
```go
type NameServer struct {
    tcpFallbackClient *client
    tcpFallbackOnce   sync.Once
}

ns.tcpFallbackOnce.Do(func() {
    ns.tcpFallbackClient = ns.createClientForProtocol("tcp")
})
```

**Benefits:**
- Thread-safe initialization
- No lock overhead after first call
- Simple, efficient pattern

#### sync.RWMutex for Reader-Heavy Access
**Pattern: Dynamic URL List Updates**
```go
type client struct {
    resolvedURLs []string
    urlMutex     sync.RWMutex
}

// Read lock (common case)
d.queryClient.urlMutex.RLock()
urls := make([]string, len(d.queryClient.resolvedURLs))
copy(urls, d.queryClient.resolvedURLs)
d.queryClient.urlMutex.RUnlock()

// Write lock (rare case)
d.queryClient.urlMutex.Lock()
d.queryClient.resolvedURLs = resolvedURLs
d.queryClient.urlMutex.Unlock()
```

#### sync.WaitGroup and sync.Once for Racing
**Pattern: First Success Wins**
```go
once := new(sync.Once)
wg := new(sync.WaitGroup)
errCollector := make(chan error, len(items))

wg.Add(len(items))
for _, item := range items {
    go func(i) {
        defer wg.Done()
        result, err := process(i)
        if err == nil {
            once.Do(func() {
                msg <- result  // Only first succeeds
                err <- nil
            })
        } else {
            errCollector <- err
        }
    }()
}

go func() {
    wg.Wait()
    once.Do(func() {
        // Called if all failed
        msg <- nil
        // Collect last error
    })
}()
```

### 7.2 Memory Management

#### Message Copying
```go
queryCopy := query.Copy()  // Deep copy via miekg/dns
```

**Usage:** Only when modifications needed that shouldn't affect original

#### Buffered Channels for Error Collection
```go
errCollector := make(chan error, len(urls))  // Buffered
```

**Pattern:** Prevents goroutines from blocking on error channel

#### URL Snapshot Pattern
```go
// Take snapshot with read lock
d.queryClient.urlMutex.RLock()
urls := make([]string, len(d.queryClient.resolvedURLs))
copy(urls, d.queryClient.resolvedURLs)
d.queryClient.urlMutex.RUnlock()

// Use snapshot (no lock needed)
for _, urlString := range urls {
    go sendRequest(urlString)
}
```

### 7.3 Client Reuse

#### NameServer: TCP Fallback Reuse
```go
// Primary client
ns.queryClient = ns.createClientForProtocol(ns.Protocol)

// TCP fallback client (reused)
ns.tcpFallbackOnce.Do(func() {
    ns.tcpFallbackClient = ns.createClientForProtocol("tcp")
})

// Use appropriate client
if protocol == "tcp" && ns.Protocol == "udp" {
    clientToUse = ns.tcpFallbackClient  // Reuse
} else {
    clientToUse = ns.createClientForProtocol(protocol)  // New
}
```

#### DoH: HTTP Client Reuse
```go
d.queryClient = &client{
    httpClient: &http.Client{
        Transport: &http.Transport{...},
        Timeout: d.QueryTimeout,
    },
    // ...
}
```

### 7.4 Error Handling

#### Graceful Degradation
```go
// If UDP response is truncated, retry with TCP
if msg.Truncated && ns.Protocol == "udp" {
    tcpMsg, tcpErr := ns.queryWithProtocol(query, address, "tcp")
    if tcpErr != nil {
        return msg, nil  // Return truncated response if TCP fails
    }
    return tcpMsg, nil
}
```

#### Concurrent Failure Handling
```go
// All requests failed - try URL resolution
once.Do(func() {
    resolvedURLs := d.resolveURL(depth - 1)
    if len(resolvedURLs) < 1 {
        // No new URLs - return error
        msg <- nil
        err <- UnknownHostError(d.URL.Hostname())
        return
    } else {
        // Update and retry
        d.queryClient.urlMutex.Lock()
        d.queryClient.resolvedURLs = resolvedURLs
        d.queryClient.urlMutex.Unlock()
        m, e := d.Resolve(query, depth-1)
        msg <- m
        err <- e
        return
    }
})
```

---

## 8. EDNS CLIENT SUBNET (ECS) INTEGRATION

**File:** `/home/user/secDNS/internal/edns/ecs/ecs.go`

### 8.1 ECS Configuration
```go
type Config struct {
    Mode         Mode       // "passthrough", "add", or "override"
    ClientSubnet string     // CIDR notation: "192.168.1.0/24"
    subnet       *net.IPNet
    family       uint16     // 1=IPv4, 2=IPv6
    netmask      uint8      // Prefix length
}
```

### 8.2 Configuration Modes
- **Passthrough:** Do not modify ECS (default)
- **Add:** Add ECS only if not present
- **Override:** Always replace ECS with configured value

### 8.3 Application Pattern
```go
func (c *Config) ApplyToQuery(query *dns.Msg) error {
    if c == nil || c.Mode == ModePassthrough {
        return nil
    }

    // Get or create OPT record
    opt := query.IsEdns0()
    if opt == nil {
        query.SetEdns0(4096, false)
        opt = query.IsEdns0()
    }

    // Find existing ECS option
    var existingECS *dns.EDNS0_SUBNET
    var ecsIndex int = -1
    for i, option := range opt.Option {
        if ecs, ok := option.(*dns.EDNS0_SUBNET); ok {
            existingECS = ecs
            ecsIndex = i
            break
        }
    }

    // Determine if we should add/replace ECS
    shouldSetECS := false
    switch c.Mode {
    case ModeAdd:
        if existingECS == nil {
            shouldSetECS = true
        }
    case ModeOverride:
        shouldSetECS = true
    }

    if !shouldSetECS {
        return nil
    }

    // Create new ECS option
    newECS := &dns.EDNS0_SUBNET{
        Code:          dns.EDNS0SUBNET,
        Family:        c.family,
        SourceNetmask: c.netmask,
        SourceScope:   0,
        Address:       c.subnet.IP,
    }

    // Replace or add
    if ecsIndex >= 0 {
        opt.Option[ecsIndex] = newECS
    } else {
        opt.Option = append(opt.Option, newECS)
    }

    return nil
}
```

### 8.4 Integration in NameServer
```go
// In Resolve()
if ns.ecsConfig != nil {
    queryCopy := query.Copy()
    if err := ns.ecsConfig.ApplyToQuery(queryCopy); err != nil {
        return nil, err
    }
    query = queryCopy
}
```

### 8.5 Integration in DoH
```go
// Same pattern as NameServer
if d.ecsConfig != nil {
    queryCopy := query.Copy()
    if err := d.ecsConfig.ApplyToQuery(queryCopy); err != nil {
        return nil, err
    }
    query = queryCopy
}
```

---

## 9. ERROR TYPES AND PATTERNS

### 9.1 Package-level Errors
**File:** `/home/user/secDNS/pkg/upstream/resolver/errors.go`

```go
var (
    ErrNilQuery             = errors.New("upstream/resolver: Nil query")
    ErrTooManyQuestions     = errors.New("upstream/resolver: Too many questions")
    ErrNotSupportedQuestion = errors.New("upstream/resolver: Not supported question")
    ErrLoopDetected         = errors.New("upstream/resolver: Possible endless loop detected")
)

type NotRegistrableError string
type AlreadyRegisteredError string
```

### 9.2 Custom Error Types
**Pattern: Type-specific errors**

```go
// Sequence errors
var (
    ErrNilResolver         = NilPointerError("resolver")
    ErrNoAvailableResolver = errors.New("upstream/resolvers/sequence: No available resolver")
)

// DoH errors
var ErrResolverNotReady = errors.New("upstream/resolvers/doh: Resolver not ready")

type UnknownHostError string

func (e UnknownHostError) Error() string {
    return "upstream/resolvers/doh: Cannot resolve " + string(e)
}
```

### 9.3 Query Validation
**File:** `/home/user/secDNS/pkg/upstream/resolver/check.go`

```go
func QueryCheck(query *dns.Msg) error {
    if query == nil {
        return ErrNilQuery
    }
    if len(query.Question) != 1 {
        return ErrTooManyQuestions
    }
    if query.Question[0].Qclass != dns.ClassINET {
        return ErrNotSupportedQuestion
    }
    return nil
}
```

**Called in:** Instance.Listen() before delegating to resolver

---

## 10. KEY ARCHITECTURAL INSIGHTS FOR CACHING RESOLVER

### 10.1 Interface Contract
- Must implement 3 methods: Type(), TypeName(), Resolve(query, depth)
- Must check `depth < 0` and return `ErrLoopDetected`
- Must decrement depth when calling upstream: `depth-1`
- Should never modify original query (or restore it)

### 10.2 Query Handling
- For modifications: `query.Copy()` if changing will affect upstream
- For temporary changes: Save/restore pattern (less common)
- For responses: Never modify in-place if reusing; create new Msg with SetReply()

### 10.3 Thread Safety
- `sync.Once` for lazy initialization of expensive resources
- `sync.RWMutex` for data that's read frequently, written rarely
- Protect shared state accessed from multiple goroutines
- No synchronization needed if resolver is stateless or immutable

### 10.4 Performance Considerations
- Reuse clients and connections where possible
- Use buffered channels when collecting errors from goroutines
- Take snapshots of shared state to minimize lock duration
- Copy only when necessary (deep copy is expensive)

### 10.5 Registration Pattern
- Each resolver type must call `resolver.RegisterResolver()` in init()
- Descriptor system handles configuration parsing
- Nested resolvers resolved by name from global registry

### 10.6 Response Handling
- Always use `msg.SetReply(query)` for new responses
- Only modify Answer/Ns/Extra sections; don't touch question
- TTL: preserve from upstream, or use reasonable default
- Filter records using predicate functions and helper

### 10.7 Error Handling
- Propagate errors up the chain
- Only continue on error in sequential/fallback patterns
- Concurrent resolvers: collect errors, return last or specific one
- ECS and other setup errors: return immediately


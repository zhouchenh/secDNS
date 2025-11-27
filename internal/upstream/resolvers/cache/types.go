package cache

import (
	"container/heap"
	"fmt"
	"github.com/miekg/dns"
	"github.com/zhouchenh/go-descriptor"
	"github.com/zhouchenh/secDNS/internal/common"
	"github.com/zhouchenh/secDNS/pkg/upstream/resolver"
	"golang.org/x/sync/singleflight"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Cache implements a high-performance, thread-safe DNS caching resolver with LRU eviction.
type Cache struct {
	// Configuration (immutable after init)
	Resolver           resolver.Resolver // Upstream resolver
	MaxEntries         int               // Maximum cache entries (0 = unlimited)
	MinTTL             time.Duration     // Minimum TTL override (0 = no override)
	MaxTTL             time.Duration     // Maximum TTL override (0 = no override)
	NegativeTTL        time.Duration     // TTL for negative responses (NXDOMAIN, NODATA)
	NXDomainTTL        time.Duration     // Override TTL for NXDOMAIN
	NoDataTTL          time.Duration     // Override TTL for NODATA
	CleanupInterval    time.Duration     // How often to run cleanup (default 60s)
	ServeStale         bool              // Serve stale responses while refreshing
	StaleDuration      time.Duration     // How long stale responses are valid
	DefaultPositiveTTL time.Duration     // Default TTL for positive responses lacking TTLs
	DefaultFallbackTTL time.Duration     // Fallback TTL when no records contain TTL

	// Cache state (protected by mutex)
	entries map[string]*CacheEntry
	lru     *LRUList
	mutex   sync.RWMutex
	queue   expirationHeap

	// Statistics (atomic counters)
	hits      uint64
	misses    uint64
	evictions uint64

	// Lifecycle management
	initOnce    sync.Once
	stopCleanup chan struct{}
	cleanupDone sync.WaitGroup
	requests    singleflight.Group
}

// CacheEntry represents a single cached DNS response.
type CacheEntry struct {
	Response    *dns.Msg  // Deep copy of DNS response
	OriginalTTL uint32    // Original TTL from upstream (in seconds)
	CachedAt    time.Time // When this entry was cached
	ExpiresAt   time.Time // When entry expires
	lruNode     *LRUNode  // Pointer to LRU list node
}

// CacheStats represents cache statistics.
type CacheStats struct {
	Hits      uint64  // Total cache hits
	Misses    uint64  // Total cache misses
	Evictions uint64  // Total LRU evictions
	Size      int     // Current number of cached entries
	HitRate   float64 // Cache hit rate (hits / total requests)
}

var typeOfCache = descriptor.TypeOfNew(new(*Cache))

// Type returns the descriptor type for the Cache resolver.
func (c *Cache) Type() descriptor.Type {
	return typeOfCache
}

// TypeName returns the type name for configuration.
func (c *Cache) TypeName() string {
	return "cache"
}

// NameServerResolver marks this resolver as compatible with nameserver resolver lists.
func (c *Cache) NameServerResolver() {}

// Resolve resolves a DNS query, checking the cache first and querying upstream on miss.
func (c *Cache) Resolve(query *dns.Msg, depth int) (*dns.Msg, error) {
	// CRITICAL: Check depth to prevent infinite loops
	if depth < 0 {
		return nil, resolver.ErrLoopDetected
	}

	// Initialize on first use
	c.initOnce.Do(func() {
		c.init()
	})

	// Generate cache key
	key := makeCacheKey(query)
	if key == "" {
		// Invalid query (no questions) - pass through to upstream
		return c.Resolver.Resolve(query, depth-1)
	}

	// Try cache lookup
	if response, stale, found := c.get(key); found {
		atomic.AddUint64(&c.hits, 1)
		// Set the query ID to match the incoming query
		response.Id = query.Id
		if stale {
			go c.triggerRefresh(key, query.Copy(), depth-1)
		}
		return response, nil
	}

	// Cache miss - query upstream
	atomic.AddUint64(&c.misses, 1)
	value, err, _ := c.requests.Do(key, func() (interface{}, error) {
		return c.fetchAndStore(query.Copy(), depth-1, key)
	})
	if err != nil {
		return nil, err
	}

	response := value.(*dns.Msg).Copy()
	response.Id = query.Id
	return response, nil
}

// get retrieves a cached entry and returns a copy with adjusted TTL.
// Returns (response, stale, true) on hit, (nil, false, false) on miss.
func (c *Cache) get(key string) (*dns.Msg, bool, bool) {
	// Fast read lock for lookup and creating a response snapshot
	c.mutex.RLock()
	entry, exists := c.entries[key]
	if !exists {
		c.mutex.RUnlock()
		return nil, false, false
	}

	// Check expiration while the entry is guaranteed to exist
	remainingTTL := c.calculateRemainingTTL(entry)
	stale := false
	if remainingTTL <= 0 {
		if c.ServeStale && time.Since(entry.ExpiresAt) <= c.StaleDuration {
			stale = true
		} else {
			c.mutex.RUnlock()
			c.removeEntryIfCurrent(key, entry)
			return nil, false, false
		}
	}

	// Copy the response while read lock is held so mutations can't race
	response := entry.Response.Copy()
	c.mutex.RUnlock()

	// Update LRU (move to front = most recently used) if entry still current
	c.mutex.Lock()
	if current, ok := c.entries[key]; ok && current == entry {
		c.lru.MoveToFront(entry.lruNode)
	}
	c.mutex.Unlock()

	if stale {
		c.adjustTTL(response, 0)
	} else {
		c.adjustTTL(response, remainingTTL)
	}

	return response, stale, true
}

// removeEntryIfCurrent deletes the cache entry if it still matches the provided pointer.
func (c *Cache) removeEntryIfCurrent(key string, entry *CacheEntry) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if current, ok := c.entries[key]; ok && current == entry {
		delete(c.entries, key)
		c.lru.Remove(entry.lruNode)
	}
}

// set stores a DNS response in the cache.
func (c *Cache) set(key string, response *dns.Msg) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Check if entry already exists (update case)
	if existing, exists := c.entries[key]; exists {
		// Update existing entry
		existing.Response = response.Copy()
		existing.OriginalTTL = c.extractTTLWithOverrides(response)
		existing.CachedAt = time.Now()
		existing.ExpiresAt = existing.CachedAt.Add(time.Duration(existing.OriginalTTL) * time.Second)
		c.lru.MoveToFront(existing.lruNode)
		heap.Push(&c.queue, expirationItem{key: key, expiresAt: existing.ExpiresAt})
		return
	}

	// New entry - check if we need to evict (LRU)
	if c.MaxEntries > 0 && len(c.entries) >= c.MaxEntries {
		// Need to evict - remove least recently used
		if oldest := c.lru.RemoveTail(); oldest != nil {
			delete(c.entries, oldest.key)
			atomic.AddUint64(&c.evictions, 1)
		}
	}

	// Create new entry with TTL overrides applied
	entry := &CacheEntry{
		Response:    response.Copy(), // CRITICAL: Deep copy to avoid mutation
		OriginalTTL: c.extractTTLWithOverrides(response),
		CachedAt:    time.Now(),
		lruNode:     c.lru.AddToFront(key),
	}
	entry.ExpiresAt = entry.CachedAt.Add(time.Duration(entry.OriginalTTL) * time.Second)

	c.entries[key] = entry
	heap.Push(&c.queue, expirationItem{key: key, expiresAt: entry.ExpiresAt})
}

func (c *Cache) fetchAndStore(query *dns.Msg, depth int, key string) (*dns.Msg, error) {
	if depth < 0 {
		return nil, resolver.ErrLoopDetected
	}
	response, err := c.Resolver.Resolve(query, depth)
	if err != nil {
		return nil, err
	}
	if c.shouldCache(response) {
		c.set(key, response)
	}
	resp := response.Copy()
	c.applyTTLOverrides(resp)
	return resp, nil
}

func (c *Cache) triggerRefresh(key string, query *dns.Msg, depth int) {
	if query == nil {
		return
	}
	go func() {
		_, _, _ = c.requests.Do(key, func() (interface{}, error) {
			return c.fetchAndStore(query, depth, key)
		})
	}()
}

// extractTTLWithOverrides extracts TTL and applies min/max overrides.
func (c *Cache) extractTTLWithOverrides(response *dns.Msg) uint32 {
	ttl := c.extractTTL(response)

	// Apply min/max TTL overrides
	if c.MinTTL > 0 && ttl < uint32(c.MinTTL.Seconds()) {
		ttl = uint32(c.MinTTL.Seconds())
	}
	if c.MaxTTL > 0 && ttl > uint32(c.MaxTTL.Seconds()) {
		ttl = uint32(c.MaxTTL.Seconds())
	}

	return ttl
}

// makeCacheKey generates a cache key from a DNS query.
// Format: "qname:qtype:qclass" (case-insensitive)
// Example: "example.com.:1:1" (A record, IN class)
func makeCacheKey(query *dns.Msg) string {
	if len(query.Question) == 0 {
		return ""
	}
	q := query.Question[0]
	// Lowercase the name for case-insensitive matching (RFC 4343)
	key := fmt.Sprintf("%s:%d:%d", strings.ToLower(q.Name), q.Qtype, q.Qclass)

	if ecsKey := extractECSKey(query); ecsKey != "" {
		key = key + ":" + ecsKey
	}
	return key
}

// extractECSKey produces a stable text representation of the ECS option for cache keys.
func extractECSKey(query *dns.Msg) string {
	opt := query.IsEdns0()
	if opt == nil {
		return ""
	}
	for _, option := range opt.Option {
		if ecsOption, ok := option.(*dns.EDNS0_SUBNET); ok {
			return formatECSCacheKey(ecsOption)
		}
	}
	return ""
}

func formatECSCacheKey(opt *dns.EDNS0_SUBNET) string {
	if opt == nil {
		return ""
	}
	family := opt.Family
	mask := opt.SourceNetmask
	if mask == 0 {
		return fmt.Sprintf("ecs:%d:%d", family, mask)
	}

	var ip net.IP
	if family == 1 {
		ip = opt.Address.To4()
	} else {
		ip = opt.Address.To16()
	}
	if ip == nil {
		return fmt.Sprintf("ecs:%d:%d", family, mask)
	}

	maskBytes := net.CIDRMask(int(mask), len(ip)*8)
	network := ip.Mask(maskBytes)
	return fmt.Sprintf("ecs:%d:%d:%s", family, mask, network.String())
}

// calculateRemainingTTL calculates how much TTL remains for a cache entry.
// Returns 0 if expired.
func (c *Cache) calculateRemainingTTL(entry *CacheEntry) uint32 {
	remaining := entry.ExpiresAt.Sub(time.Now()).Seconds()
	if remaining <= 0 {
		return 0
	}
	return uint32(remaining)
}

// extractTTL extracts the minimum TTL from a DNS response.
// For negative responses, uses NegativeTTL or SOA minimum.
func (c *Cache) extractTTL(response *dns.Msg) uint32 {
	// For negative responses (NXDOMAIN or NODATA)
	if response.Rcode == dns.RcodeNameError ||
		(response.Rcode == dns.RcodeSuccess && len(response.Answer) == 0) {
		return c.getTTLForNegativeResponse(response)
	}

	// For positive responses, find minimum TTL in answer section
	defaultTTL := c.DefaultPositiveTTL
	if defaultTTL == 0 {
		defaultTTL = time.Hour
	}
	minTTL := uint32(defaultTTL.Seconds())
	found := false

	for _, rr := range response.Answer {
		if rr.Header().Ttl < minTTL {
			minTTL = rr.Header().Ttl
			found = true
		}
	}

	// Also check authority and additional sections
	for _, rr := range response.Ns {
		if rr.Header().Ttl < minTTL {
			minTTL = rr.Header().Ttl
			found = true
		}
	}
	for _, rr := range response.Extra {
		// Skip OPT records (they don't have real TTL)
		if rr.Header().Rrtype != dns.TypeOPT && rr.Header().Ttl < minTTL {
			minTTL = rr.Header().Ttl
			found = true
		}
	}

	if !found {
		fallback := c.DefaultFallbackTTL
		if fallback == 0 {
			fallback = 5 * time.Minute
		}
		return uint32(fallback.Seconds())
	}

	return minTTL
}

// getTTLForNegativeResponse determines TTL for negative responses (NXDOMAIN/NODATA).
func (c *Cache) getTTLForNegativeResponse(response *dns.Msg) uint32 {
	if response.Rcode == dns.RcodeNameError && c.NXDomainTTL > 0 {
		return uint32(c.NXDomainTTL.Seconds())
	}
	if response.Rcode == dns.RcodeSuccess && len(response.Answer) == 0 && c.NoDataTTL > 0 {
		return uint32(c.NoDataTTL.Seconds())
	}
	// Use configured negative TTL if set
	if c.NegativeTTL > 0 {
		return uint32(c.NegativeTTL.Seconds())
	}

	// Try to extract SOA minimum TTL from authority section (RFC 2308)
	for _, rr := range response.Ns {
		if soa, ok := rr.(*dns.SOA); ok {
			return soa.Minttl
		}
	}

	// Default to 5 minutes
	return 300
}

// adjustTTL adjusts all TTL values in a DNS response to the remaining TTL.
func (c *Cache) adjustTTL(response *dns.Msg, remainingTTL uint32) {
	for _, rr := range response.Answer {
		rr.Header().Ttl = remainingTTL
	}
	for _, rr := range response.Ns {
		rr.Header().Ttl = remainingTTL
	}
	for _, rr := range response.Extra {
		// Don't modify OPT record TTL (it's not a real TTL)
		if rr.Header().Rrtype != dns.TypeOPT {
			rr.Header().Ttl = remainingTTL
		}
	}
}

// shouldCache determines if a DNS response should be cached.
func (c *Cache) shouldCache(response *dns.Msg) bool {
	if response == nil {
		return false
	}

	// Cache successful responses with answers
	if response.Rcode == dns.RcodeSuccess && len(response.Answer) > 0 {
		return true
	}

	// Cache NXDOMAIN (RFC 2308)
	if response.Rcode == dns.RcodeNameError {
		return true
	}

	// Cache NODATA (NOERROR with no answers, RFC 2308)
	if response.Rcode == dns.RcodeSuccess && len(response.Answer) == 0 {
		return true
	}

	// Don't cache errors (SERVFAIL, REFUSED, FORMERR, etc.)
	return false
}

func (c *Cache) applyTTLOverrides(response *dns.Msg) {
	if c.MinTTL == 0 && c.MaxTTL == 0 {
		return
	}
	ttl := c.extractTTL(response)
	if c.MinTTL > 0 && ttl < uint32(c.MinTTL.Seconds()) {
		ttl = uint32(c.MinTTL.Seconds())
	}
	if c.MaxTTL > 0 && ttl > uint32(c.MaxTTL.Seconds()) {
		ttl = uint32(c.MaxTTL.Seconds())
	}
	c.adjustTTL(response, ttl)
}

// init initializes the cache and starts background cleanup.
func (c *Cache) init() {
	c.entries = make(map[string]*CacheEntry)
	c.lru = NewLRUList()
	c.queue = expirationHeap{}
	heap.Init(&c.queue)
	c.stopCleanup = make(chan struct{})

	// Set default cleanup interval if not configured
	if c.CleanupInterval == 0 {
		c.CleanupInterval = 60 * time.Second
	}

	// Set default negative TTL if not configured
	if c.NegativeTTL == 0 {
		c.NegativeTTL = 5 * time.Minute
	}

	if c.DefaultPositiveTTL == 0 {
		c.DefaultPositiveTTL = time.Hour
	}
	if c.DefaultFallbackTTL == 0 {
		c.DefaultFallbackTTL = 5 * time.Minute
	}
	if c.StaleDuration == 0 {
		c.StaleDuration = 30 * time.Second
	}

	// Start background cleanup goroutine
	c.startCleanup()
}

// startCleanup starts a background goroutine that periodically removes expired entries.
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

// cleanupExpired removes all expired entries from the cache.
// This runs in the background and doesn't block query processing.
func (c *Cache) cleanupExpired() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	now := time.Now()
	for c.queue.Len() > 0 {
		item := c.queue[0]
		if item.expiresAt.After(now) {
			break
		}
		heap.Pop(&c.queue)
		entry, ok := c.entries[item.key]
		if !ok {
			continue
		}
		if c.ServeStale && time.Since(entry.ExpiresAt) <= c.StaleDuration {
			continue
		}
		delete(c.entries, item.key)
		c.lru.Remove(entry.lruNode)
	}
}

// Stop stops the background cleanup goroutine and waits for it to finish.
// This should be called when shutting down the resolver.
func (c *Cache) Stop() {
	c.initOnce.Do(func() {}) // Ensure init was called

	close(c.stopCleanup)
	c.cleanupDone.Wait()
}

// Stats returns current cache statistics.
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

// Clear removes all entries from the cache.
func (c *Cache) Clear() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.entries = make(map[string]*CacheEntry)
	c.lru.Clear()
	c.queue = expirationHeap{}
}

type expirationItem struct {
	key       string
	expiresAt time.Time
}

type expirationHeap []expirationItem

func (h expirationHeap) Len() int           { return len(h) }
func (h expirationHeap) Less(i, j int) bool { return h[i].expiresAt.Before(h[j].expiresAt) }
func (h expirationHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

func (h *expirationHeap) Push(x interface{}) {
	item := x.(expirationItem)
	*h = append(*h, item)
}

func (h *expirationHeap) Pop() interface{} {
	old := *h
	n := len(old)
	if n == 0 {
		return expirationItem{}
	}
	item := old[n-1]
	*h = old[0 : n-1]
	return item
}

func init() {
	// Register the cache resolver with the descriptor system
	if err := resolver.RegisterResolver(&descriptor.Descriptor{
		Type: typeOfCache,
		Filler: descriptor.Fillers{
			// Upstream resolver (required)
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"Resolver"},
				ValueSource: descriptor.ObjectAtPath{
					ObjectPath: descriptor.Path{"resolver"},
					AssignableKind: descriptor.AssignmentFunction(func(i interface{}) (object interface{}, ok bool) {
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
									return nil, false
								}
								return int(num), true
							},
						},
					},
					descriptor.DefaultValue{Value: 10000},
				},
			},
			// minTTL (optional, default 0 = no override)
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"MinTTL"},
				ValueSource: descriptor.ValueSources{
					descriptor.ObjectAtPath{
						ObjectPath: descriptor.Path{"minTTL"},
						AssignableKind: descriptor.ConvertibleKind{
							Kind: descriptor.KindFloat64,
							ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
								num, ok := original.(float64)
								if !ok || num < 0 {
									return nil, false
								}
								return time.Duration(num * float64(time.Second)), true
							},
						},
					},
					descriptor.DefaultValue{Value: time.Duration(0)},
				},
			},
			// maxTTL (optional, default 0 = no override)
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"MaxTTL"},
				ValueSource: descriptor.ValueSources{
					descriptor.ObjectAtPath{
						ObjectPath: descriptor.Path{"maxTTL"},
						AssignableKind: descriptor.ConvertibleKind{
							Kind: descriptor.KindFloat64,
							ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
								num, ok := original.(float64)
								if !ok || num < 0 {
									return nil, false
								}
								return time.Duration(num * float64(time.Second)), true
							},
						},
					},
					descriptor.DefaultValue{Value: time.Duration(0)},
				},
			},
			// negativeTTL (optional, default 300s)
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"NegativeTTL"},
				ValueSource: descriptor.ValueSources{
					descriptor.ObjectAtPath{
						ObjectPath: descriptor.Path{"negativeTTL"},
						AssignableKind: descriptor.ConvertibleKind{
							Kind: descriptor.KindFloat64,
							ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
								num, ok := original.(float64)
								if !ok || num < 0 {
									return nil, false
								}
								return time.Duration(num * float64(time.Second)), true
							},
						},
					},
					descriptor.DefaultValue{Value: 5 * time.Minute},
				},
			},
			// cleanupInterval (optional, default 60s)
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"CleanupInterval"},
				ValueSource: descriptor.ValueSources{
					descriptor.ObjectAtPath{
						ObjectPath: descriptor.Path{"cleanupInterval"},
						AssignableKind: descriptor.ConvertibleKind{
							Kind: descriptor.KindFloat64,
							ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
								num, ok := original.(float64)
								if !ok || num < 0 {
									return nil, false
								}
								return time.Duration(num * float64(time.Second)), true
							},
						},
					},
					descriptor.DefaultValue{Value: 60 * time.Second},
				},
			},
			// Also support string format for durations
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"MinTTL"},
				ValueSource: descriptor.ObjectAtPath{
					ObjectPath: descriptor.Path{"minTTL"},
					AssignableKind: descriptor.ConvertibleKind{
						Kind: descriptor.KindString,
						ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
							str, ok := original.(string)
							if !ok {
								return nil, false
							}
							num, err := strconv.ParseFloat(str, 64)
							if err != nil || num < 0 {
								return nil, false
							}
							return time.Duration(num * float64(time.Second)), true
						},
					},
				},
			},
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"MaxTTL"},
				ValueSource: descriptor.ObjectAtPath{
					ObjectPath: descriptor.Path{"maxTTL"},
					AssignableKind: descriptor.ConvertibleKind{
						Kind: descriptor.KindString,
						ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
							str, ok := original.(string)
							if !ok {
								return nil, false
							}
							num, err := strconv.ParseFloat(str, 64)
							if err != nil || num < 0 {
								return nil, false
							}
							return time.Duration(num * float64(time.Second)), true
						},
					},
				},
			},
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"NegativeTTL"},
				ValueSource: descriptor.ObjectAtPath{
					ObjectPath: descriptor.Path{"negativeTTL"},
					AssignableKind: descriptor.ConvertibleKind{
						Kind: descriptor.KindString,
						ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
							str, ok := original.(string)
							if !ok {
								return nil, false
							}
							num, err := strconv.ParseFloat(str, 64)
							if err != nil || num < 0 {
								return nil, false
							}
							return time.Duration(num * float64(time.Second)), true
						},
					},
				},
			},
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"ServeStale"},
				ValueSource: descriptor.ObjectAtPath{
					ObjectPath:     descriptor.Path{"serveStale"},
					AssignableKind: descriptor.KindBool,
				},
			},
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"StaleDuration"},
				ValueSource: descriptor.ValueSources{
					descriptor.ObjectAtPath{
						ObjectPath: descriptor.Path{"staleDuration"},
						AssignableKind: descriptor.ConvertibleKind{
							Kind: descriptor.KindFloat64,
							ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
								num, ok := original.(float64)
								if !ok || num < 0 {
									return nil, false
								}
								return time.Duration(num * float64(time.Second)), true
							},
						},
					},
					descriptor.ObjectAtPath{
						ObjectPath: descriptor.Path{"staleDuration"},
						AssignableKind: descriptor.ConvertibleKind{
							Kind: descriptor.KindString,
							ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
								str, ok := original.(string)
								if !ok {
									return nil, false
								}
								num, err := strconv.ParseFloat(str, 64)
								if err != nil || num < 0 {
									return nil, false
								}
								return time.Duration(num * float64(time.Second)), true
							},
						},
					},
				},
			},
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"DefaultPositiveTTL"},
				ValueSource: descriptor.ValueSources{
					descriptor.ObjectAtPath{
						ObjectPath: descriptor.Path{"defaultPositiveTTL"},
						AssignableKind: descriptor.ConvertibleKind{
							Kind: descriptor.KindFloat64,
							ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
								num, ok := original.(float64)
								if !ok || num < 0 {
									return nil, false
								}
								return time.Duration(num * float64(time.Second)), true
							},
						},
					},
					descriptor.ObjectAtPath{
						ObjectPath: descriptor.Path{"defaultPositiveTTL"},
						AssignableKind: descriptor.ConvertibleKind{
							Kind: descriptor.KindString,
							ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
								str, ok := original.(string)
								if !ok {
									return nil, false
								}
								num, err := strconv.ParseFloat(str, 64)
								if err != nil || num < 0 {
									return nil, false
								}
								return time.Duration(num * float64(time.Second)), true
							},
						},
					},
				},
			},
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"DefaultFallbackTTL"},
				ValueSource: descriptor.ValueSources{
					descriptor.ObjectAtPath{
						ObjectPath: descriptor.Path{"defaultFallbackTTL"},
						AssignableKind: descriptor.ConvertibleKind{
							Kind: descriptor.KindFloat64,
							ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
								num, ok := original.(float64)
								if !ok || num < 0 {
									return nil, false
								}
								return time.Duration(num * float64(time.Second)), true
							},
						},
					},
					descriptor.ObjectAtPath{
						ObjectPath: descriptor.Path{"defaultFallbackTTL"},
						AssignableKind: descriptor.ConvertibleKind{
							Kind: descriptor.KindString,
							ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
								str, ok := original.(string)
								if !ok {
									return nil, false
								}
								num, err := strconv.ParseFloat(str, 64)
								if err != nil || num < 0 {
									return nil, false
								}
								return time.Duration(num * float64(time.Second)), true
							},
						},
					},
				},
			},
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"NXDomainTTL"},
				ValueSource: descriptor.ValueSources{
					descriptor.ObjectAtPath{
						ObjectPath: descriptor.Path{"nxDomainTTL"},
						AssignableKind: descriptor.ConvertibleKind{
							Kind: descriptor.KindFloat64,
							ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
								num, ok := original.(float64)
								if !ok || num < 0 {
									return nil, false
								}
								return time.Duration(num * float64(time.Second)), true
							},
						},
					},
					descriptor.ObjectAtPath{
						ObjectPath: descriptor.Path{"nxDomainTTL"},
						AssignableKind: descriptor.ConvertibleKind{
							Kind: descriptor.KindString,
							ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
								str, ok := original.(string)
								if !ok {
									return nil, false
								}
								num, err := strconv.ParseFloat(str, 64)
								if err != nil || num < 0 {
									return nil, false
								}
								return time.Duration(num * float64(time.Second)), true
							},
						},
					},
				},
			},
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"NoDataTTL"},
				ValueSource: descriptor.ValueSources{
					descriptor.ObjectAtPath{
						ObjectPath: descriptor.Path{"noDataTTL"},
						AssignableKind: descriptor.ConvertibleKind{
							Kind: descriptor.KindFloat64,
							ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
								num, ok := original.(float64)
								if !ok || num < 0 {
									return nil, false
								}
								return time.Duration(num * float64(time.Second)), true
							},
						},
					},
					descriptor.ObjectAtPath{
						ObjectPath: descriptor.Path{"noDataTTL"},
						AssignableKind: descriptor.ConvertibleKind{
							Kind: descriptor.KindString,
							ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
								str, ok := original.(string)
								if !ok {
									return nil, false
								}
								num, err := strconv.ParseFloat(str, 64)
								if err != nil || num < 0 {
									return nil, false
								}
								return time.Duration(num * float64(time.Second)), true
							},
						},
					},
				},
			},
		},
	}); err != nil {
		common.ErrOutput(err)
	}
}

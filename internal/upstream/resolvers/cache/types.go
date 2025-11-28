package cache

import (
	"container/heap"
	"fmt"
	"github.com/miekg/dns"
	"github.com/zhouchenh/go-descriptor"
	"github.com/zhouchenh/secDNS/internal/common"
	"github.com/zhouchenh/secDNS/pkg/upstream/resolver"
	"golang.org/x/sync/singleflight"
	"math/rand"
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
	Resolver            resolver.Resolver // Upstream resolver
	MaxEntries          int               // Maximum cache entries (0 = unlimited)
	MinTTL              time.Duration     // Minimum TTL override (0 = no override)
	MaxTTL              time.Duration     // Maximum TTL override (0 = no override)
	NegativeTTL         time.Duration     // TTL for negative responses (NXDOMAIN, NODATA)
	NXDomainTTL         time.Duration     // Override TTL for NXDOMAIN
	NoDataTTL           time.Duration     // Override TTL for NODATA
	CleanupInterval     time.Duration     // How often to run cleanup (default 60s)
	ServeStale          bool              // Serve stale responses while refreshing
	StaleDuration       time.Duration     // How long stale responses are valid
	DefaultPositiveTTL  time.Duration     // Default TTL for positive responses lacking TTLs
	DefaultFallbackTTL  time.Duration     // Fallback TTL when no records contain TTL
	TTLJitterPercent    float64           // Randomize expirations to avoid thundering herd
	PrefetchThreshold   uint64            // Access count threshold for background refresh
	PrefetchPercent     float64           // Fraction of TTL elapsed before prefetching
	WarmupQueries       []WarmupQuery     // Optional warmup queries to load on start
	CacheControlEnabled bool              // Honor cache-control hints from upstream

	// Cache state (protected by mutex)
	entries map[string]*Entry
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
	rng         *rand.Rand
	rngMutex    sync.Mutex

	domainStats sync.Map
}

// Entry represents a single cached DNS response.
type Entry struct {
	Response        *dns.Msg  // Deep copy of DNS response
	OriginalTTL     uint32    // Original TTL from upstream (in seconds)
	CachedAt        time.Time // When this entry was cached
	ExpiresAt       time.Time // When entry expires
	lruNode         *LRUNode  // Pointer to LRU list node
	AccessCount     uint64
	prefetching     uint32
	DisablePrefetch bool
	DisableStale    bool
}

// Stats represents cache statistics.
type Stats struct {
	Hits      uint64  // Total cache hits
	Misses    uint64  // Total cache misses
	Evictions uint64  // Total LRU evictions
	Size      int     // Current number of cached entries
	HitRate   float64 // Cache hit rate (hits / total requests)
}

// DomainStats captures per-domain cache behavior.
type DomainStats struct {
	Hits        uint64
	Misses      uint64
	Prefetches  uint64
	StaleServed uint64
}

// WarmupQuery describes a query to prime during startup.
type WarmupQuery struct {
	Name  string
	Type  uint16
	Class uint16
}

var typeOfCache = descriptor.TypeOfNew(new(*Cache))

const cacheControlOptionCode = 0xFDE9

type domainStatsCounters struct {
	hits        uint64
	misses      uint64
	prefetches  uint64
	staleServed uint64
}

type cacheControlDirectives struct {
	skipCache       bool
	disablePrefetch bool
	disableStale    bool
	ttlOverride     *uint32
}

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

	qName := strings.ToLower(query.Question[0].Name)

	// Try cache lookup
	if response, entry, _, stale, found := c.get(key); found {
		atomic.AddUint64(&c.hits, 1)
		c.recordDomainHit(qName, stale)
		// Set the query ID to match the incoming query
		response.Id = query.Id
		if stale {
			go c.triggerRefresh(key, query.Copy(), depth-1)
		} else {
			c.maybePrefetch(key, entry, query.Copy(), depth-1)
		}
		return response, nil
	}

	// Cache miss - query upstream
	atomic.AddUint64(&c.misses, 1)
	c.recordDomainMiss(qName)
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
// Returns (response, entry, remainingTTL, stale, true) on hit, (nil, nil, 0, false, false) on miss.
func (c *Cache) get(key string) (*dns.Msg, *Entry, uint32, bool, bool) {
	// Fast read lock for lookup and creating a response snapshot
	c.mutex.RLock()
	entry, exists := c.entries[key]
	if !exists {
		c.mutex.RUnlock()
		return nil, nil, 0, false, false
	}

	// Check expiration while the entry is guaranteed to exist
	remainingTTL := c.calculateRemainingTTL(entry)
	stale := false
	if remainingTTL <= 0 {
		if c.ServeStale && !entry.DisableStale && time.Since(entry.ExpiresAt) <= c.StaleDuration {
			stale = true
		} else {
			c.mutex.RUnlock()
			c.removeEntryIfCurrent(key, entry)
			return nil, nil, 0, false, false
		}
	}

	// Copy the response while read lock is held so mutations can't race
	response := entry.Response.Copy()
	atomic.AddUint64(&entry.AccessCount, 1)
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

	return response, entry, remainingTTL, stale, true
}

// removeEntryIfCurrent deletes the cache entry if it still matches the provided pointer.
func (c *Cache) removeEntryIfCurrent(key string, entry *Entry) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if current, ok := c.entries[key]; ok && current == entry {
		delete(c.entries, key)
		c.lru.Remove(entry.lruNode)
	}
}

// set stores a DNS response in the cache.
func (c *Cache) set(key string, response *dns.Msg) {
	c.setWithDirectives(key, response, cacheControlDirectives{})
}

func (c *Cache) setWithDirectives(key string, response *dns.Msg, directives cacheControlDirectives) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Check if entry already exists (update case)
	if existing, exists := c.entries[key]; exists {
		// Update existing entry
		existing.Response = response.Copy()
		newTTL := c.applyTTLJitter(c.extractTTLWithOverrides(response))
		if directives.ttlOverride != nil && *directives.ttlOverride > 0 && *directives.ttlOverride < newTTL {
			newTTL = *directives.ttlOverride
		}
		existing.OriginalTTL = newTTL
		existing.CachedAt = time.Now()
		existing.ExpiresAt = existing.CachedAt.Add(time.Duration(existing.OriginalTTL) * time.Second)
		existing.AccessCount = 0
		existing.prefetching = 0
		existing.DisablePrefetch = directives.disablePrefetch
		existing.DisableStale = directives.disableStale
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
	entry := &Entry{
		Response:        response.Copy(), // CRITICAL: Deep copy to avoid mutation
		OriginalTTL:     c.applyTTLJitter(c.extractTTLWithOverrides(response)),
		CachedAt:        time.Now(),
		lruNode:         c.lru.AddToFront(key),
		DisablePrefetch: directives.disablePrefetch,
		DisableStale:    directives.disableStale,
	}
	if directives.ttlOverride != nil && *directives.ttlOverride > 0 && *directives.ttlOverride < entry.OriginalTTL {
		entry.OriginalTTL = *directives.ttlOverride
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
	control := cacheControlDirectives{}
	if c.CacheControlEnabled {
		control = c.parseCacheControl(response)
	}
	if !control.skipCache && c.shouldCache(response) {
		c.setWithDirectives(key, response, control)
	}
	resp := response.Copy()
	c.applyTTLOverrides(resp, control.ttlOverride)
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

func (c *Cache) applyTTLJitter(ttl uint32) uint32 {
	if ttl == 0 || c.TTLJitterPercent <= 0 || c.rng == nil {
		return ttl
	}
	jitterRange := int(float64(ttl) * c.TTLJitterPercent)
	if jitterRange <= 0 {
		return ttl
	}
	c.rngMutex.Lock()
	defer c.rngMutex.Unlock()
	delta := c.rng.Intn(2*jitterRange+1) - jitterRange
	adjusted := int(ttl) + delta
	if adjusted < 1 {
		adjusted = 1
	}
	return uint32(adjusted)
}

// calculateRemainingTTL calculates how much TTL remains for a cache entry.
// Returns 0 if expired.
func (c *Cache) calculateRemainingTTL(entry *Entry) uint32 {
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

func (c *Cache) parseCacheControl(response *dns.Msg) cacheControlDirectives {
	d := cacheControlDirectives{}
	opt := response.IsEdns0()
	if opt == nil {
		return d
	}
	for _, option := range opt.Option {
		local, ok := option.(*dns.EDNS0_LOCAL)
		if !ok || local.Code != cacheControlOptionCode {
			continue
		}
		directive := strings.ToLower(string(local.Data))
		switch {
		case directive == "nocache":
			d.skipCache = true
		case directive == "noprefetch":
			d.disablePrefetch = true
		case directive == "nostale":
			d.disableStale = true
		case strings.HasPrefix(directive, "ttl="):
			value := strings.TrimPrefix(directive, "ttl=")
			if secs, err := strconv.Atoi(value); err == nil && secs > 0 {
				v := uint32(secs)
				d.ttlOverride = &v
			}
		}
	}
	return d
}

func (c *Cache) applyTTLOverrides(response *dns.Msg, override *uint32) {
	ttl := c.extractTTL(response)
	if override != nil && *override > 0 && *override < ttl {
		ttl = *override
	}
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
	c.entries = make(map[string]*Entry)
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
	if c.TTLJitterPercent == 0 {
		c.TTLJitterPercent = 0.05
	}
	if c.PrefetchPercent == 0 {
		c.PrefetchPercent = 0.9
	}
	if c.StaleDuration == 0 {
		c.StaleDuration = 30 * time.Second
	}
	if c.PrefetchThreshold == 0 {
		c.PrefetchThreshold = 10
	}
	if c.rng == nil {
		c.rng = rand.New(rand.NewSource(time.Now().UnixNano()))
	}

	// Start background cleanup goroutine
	c.startCleanup()
	c.startWarmup()
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

func (c *Cache) startWarmup() {
	if len(c.WarmupQueries) == 0 {
		return
	}
	go func() {
		for _, q := range c.WarmupQueries {
			msg := new(dns.Msg)
			name := common.EnsureFQDN(q.Name)
			msg.SetQuestion(name, q.Type)
			if q.Class != 0 {
				msg.Question[0].Qclass = q.Class
			}
			_, _ = c.Resolve(msg, 64)
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
func (c *Cache) Stats() Stats {
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

	return Stats{
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

	c.entries = make(map[string]*Entry)
	c.lru.Clear()
	c.queue = expirationHeap{}
}

// DomainStatsFor returns statistics for a specific domain.
func (c *Cache) DomainStatsFor(name string) DomainStats {
	entry, ok := c.domainStats.Load(strings.ToLower(name))
	if !ok {
		return DomainStats{}
	}
	stats := entry.(*domainStatsCounters)
	return DomainStats{
		Hits:        atomic.LoadUint64(&stats.hits),
		Misses:      atomic.LoadUint64(&stats.misses),
		Prefetches:  atomic.LoadUint64(&stats.prefetches),
		StaleServed: atomic.LoadUint64(&stats.staleServed),
	}
}

// AllDomainStats returns a snapshot of every tracked domain.
func (c *Cache) AllDomainStats() map[string]DomainStats {
	snapshot := make(map[string]DomainStats)
	c.domainStats.Range(func(key, value interface{}) bool {
		stats := value.(*domainStatsCounters)
		snapshot[key.(string)] = DomainStats{
			Hits:        atomic.LoadUint64(&stats.hits),
			Misses:      atomic.LoadUint64(&stats.misses),
			Prefetches:  atomic.LoadUint64(&stats.prefetches),
			StaleServed: atomic.LoadUint64(&stats.staleServed),
		}
		return true
	})
	return snapshot
}

func (c *Cache) recordDomainHit(name string, stale bool) {
	stats := c.domainStatsEntry(name)
	atomic.AddUint64(&stats.hits, 1)
	if stale {
		atomic.AddUint64(&stats.staleServed, 1)
	}
}

func (c *Cache) recordDomainMiss(name string) {
	stats := c.domainStatsEntry(name)
	atomic.AddUint64(&stats.misses, 1)
}

func (c *Cache) recordPrefetch(name string) {
	stats := c.domainStatsEntry(name)
	atomic.AddUint64(&stats.prefetches, 1)
}

func (c *Cache) domainStatsEntry(name string) *domainStatsCounters {
	key := strings.ToLower(name)
	if entry, ok := c.domainStats.Load(key); ok {
		return entry.(*domainStatsCounters)
	}
	stats := &domainStatsCounters{}
	actual, _ := c.domainStats.LoadOrStore(key, stats)
	return actual.(*domainStatsCounters)
}

func (c *Cache) maybePrefetch(key string, entry *Entry, query *dns.Msg, depth int) {
	if entry == nil || query == nil {
		return
	}
	if entry.DisablePrefetch || c.PrefetchThreshold == 0 || c.PrefetchPercent <= 0 {
		return
	}
	totalTTL := time.Duration(entry.OriginalTTL) * time.Second
	if totalTTL <= 0 {
		return
	}
	if atomic.LoadUint64(&entry.AccessCount) < c.PrefetchThreshold {
		return
	}
	elapsed := time.Since(entry.CachedAt)
	if elapsed <= 0 {
		return
	}
	fraction := elapsed.Seconds() / totalTTL.Seconds()
	if fraction < c.PrefetchPercent {
		return
	}
	if !atomic.CompareAndSwapUint32(&entry.prefetching, 0, 1) {
		return
	}
	go func(name, cacheKey string, e *Entry) {
		defer atomic.StoreUint32(&e.prefetching, 0)
		_, err, _ := c.requests.Do(cacheKey, func() (interface{}, error) {
			return c.fetchAndStore(query, depth, cacheKey)
		})
		if err == nil {
			c.recordPrefetch(name)
		}
	}(strings.ToLower(query.Question[0].Name), key, entry)
}

type expirationItem struct {
	key       string
	expiresAt time.Time
}

type expirationHeap []expirationItem

func (h *expirationHeap) Len() int { return len(*h) }
func (h *expirationHeap) Less(i, j int) bool {
	return (*h)[i].expiresAt.Before((*h)[j].expiresAt)
}
func (h *expirationHeap) Swap(i, j int) { (*h)[i], (*h)[j] = (*h)[j], (*h)[i] }

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
				descriptor.ObjectAtPath{
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
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"TTLJitterPercent"},
				ValueSource: descriptor.ValueSources{
					descriptor.ObjectAtPath{
						ObjectPath: descriptor.Path{"ttlJitterPercent"},
						AssignableKind: descriptor.ConvertibleKind{
							Kind: descriptor.KindFloat64,
							ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
								num, ok := original.(float64)
								if !ok || num < 0 {
									return nil, false
								}
								return num, true
							},
						},
					},
					descriptor.ObjectAtPath{
						ObjectPath: descriptor.Path{"ttlJitterPercent"},
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
								return num, true
							},
						},
					},
				},
			},
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"PrefetchThreshold"},
				ValueSource: descriptor.ValueSources{
					descriptor.ObjectAtPath{
						ObjectPath: descriptor.Path{"prefetchThreshold"},
						AssignableKind: descriptor.ConvertibleKind{
							Kind: descriptor.KindFloat64,
							ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
								num, ok := original.(float64)
								if !ok || num < 0 {
									return nil, false
								}
								return uint64(num), true
							},
						},
					},
					descriptor.ObjectAtPath{
						ObjectPath: descriptor.Path{"prefetchThreshold"},
						AssignableKind: descriptor.ConvertibleKind{
							Kind: descriptor.KindString,
							ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
								str, ok := original.(string)
								if !ok {
									return nil, false
								}
								num, err := strconv.ParseUint(str, 10, 64)
								if err != nil {
									return nil, false
								}
								return num, true
							},
						},
					},
				},
			},
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"PrefetchPercent"},
				ValueSource: descriptor.ValueSources{
					descriptor.ObjectAtPath{
						ObjectPath: descriptor.Path{"prefetchPercent"},
						AssignableKind: descriptor.ConvertibleKind{
							Kind: descriptor.KindFloat64,
							ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
								num, ok := original.(float64)
								if !ok || num < 0 || num > 1 {
									return nil, false
								}
								return num, true
							},
						},
					},
					descriptor.ObjectAtPath{
						ObjectPath: descriptor.Path{"prefetchPercent"},
						AssignableKind: descriptor.ConvertibleKind{
							Kind: descriptor.KindString,
							ConvertFunction: func(original interface{}) (converted interface{}, ok bool) {
								str, ok := original.(string)
								if !ok {
									return nil, false
								}
								num, err := strconv.ParseFloat(str, 64)
								if err != nil || num < 0 || num > 1 {
									return nil, false
								}
								return num, true
							},
						},
					},
				},
			},
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"WarmupQueries"},
				ValueSource: descriptor.ObjectAtPath{
					ObjectPath: descriptor.Path{"warmupQueries"},
					AssignableKind: descriptor.AssignmentFunction(func(i interface{}) (object interface{}, ok bool) {
						raw, ok := i.([]interface{})
						if !ok {
							return nil, false
						}
						queries := make([]WarmupQuery, 0, len(raw))
						for _, elem := range raw {
							entry, ok := elem.(map[string]interface{})
							if !ok {
								continue
							}
							name, _ := entry["name"].(string)
							if name == "" {
								continue
							}
							var qType uint16 = dns.TypeA
							if v, ok := entry["type"].(float64); ok {
								qType = uint16(v)
							} else if v, ok := entry["type"].(string); ok {
								if parsed, err := strconv.Atoi(v); err == nil {
									qType = uint16(parsed)
								}
							}
							var qClass uint16 = dns.ClassINET
							if v, ok := entry["class"].(float64); ok {
								qClass = uint16(v)
							} else if v, ok := entry["class"].(string); ok {
								if parsed, err := strconv.Atoi(v); err == nil {
									qClass = uint16(parsed)
								}
							}
							queries = append(queries, WarmupQuery{Name: name, Type: qType, Class: qClass})
						}
						return queries, true
					}),
				},
			},
			descriptor.ObjectFiller{
				ObjectPath: descriptor.Path{"CacheControlEnabled"},
				ValueSource: descriptor.ObjectAtPath{
					ObjectPath:     descriptor.Path{"cacheControlEnabled"},
					AssignableKind: descriptor.KindBool,
				},
			},
		},
	}); err != nil {
		common.ErrOutput(err)
	}
}

# cache

_Available in secDNS v1.2.0 and later._

* Type: `cache`

The `cache` resolver provides high-performance DNS response caching with LRU (Least Recently Used) eviction, TTL management, and negative caching support. It caches responses from an upstream resolver to reduce latency and upstream load.

## ResolverConfigObject

```json
{
  "type": "cache",
  "resolver": {
    "type": "nameServer",
    "address": "8.8.8.8"
  },
  "maxEntries": 10000,
  "minTTL": 60,
  "maxTTL": 3600,
  "negativeTTL": 300,
  "nxDomainTTL": 900,
  "noDataTTL": 300,
  "serveStale": true,
  "staleDuration": 30,
  "prefetchThreshold": 20,
  "prefetchPercent": 0.85,
  "ttlJitterPercent": 0.05,
  "cleanupInterval": 60,
  "cacheControlEnabled": true
}
```

> `resolver`: [ResolverObject](../configuration.md#resolverobject)

The upstream resolver to query when there is a cache miss. This is required and can be any resolver type (nameServer, doh, sequence, etc.).

> `maxEntries`: Number | String _(Optional)_

The maximum number of cache entries to store. When this limit is reached, the least recently used (LRU) entry will be evicted to make room for new entries. Set to 0 for unlimited cache size (not recommended for production).

Acceptable formats:
* Number: e.g., `10000`
* String: Numeric string e.g., `"10000"`

Default: `10000`

> `minTTL`: Number | String _(Optional)_

The minimum TTL (Time To Live) in seconds to enforce for cached responses. If an upstream response has a lower TTL, it will be overridden to this value. This prevents excessively short TTLs that would cause frequent cache invalidation. Set to 0 to disable.

Acceptable formats:
* Number: The number of seconds (e.g., `60` for 1 minute)
* String: A numeric string value (e.g., `"60"`)

Default: `0` (no minimum TTL enforcement)

> `maxTTL`: Number | String _(Optional)_

The maximum TTL (Time To Live) in seconds to enforce for cached responses. If an upstream response has a higher TTL, it will be capped to this value. This prevents excessively long caching that could serve stale data. Set to 0 to disable.

Acceptable formats:
* Number: The number of seconds (e.g., `3600` for 1 hour)
* String: A numeric string value (e.g., `"3600"`)

Default: `0` (no maximum TTL enforcement)

> `negativeTTL`: Number | String _(Optional)_

The TTL in seconds for negative responses (NXDOMAIN and NODATA). Negative caching helps reduce load on upstream resolvers for non-existent domains. If you want to honor the minimum TTL from an SOA record in the authority section, explicitly set this field to `0`; otherwise the configured value (default 300s) takes precedence.

Acceptable formats:
* Number: The number of seconds (e.g., `300` for 5 minutes)
* String: A numeric string value (e.g., `"300"`)

Default: `300` (5 minutes)

> `cleanupInterval`: Number | String _(Optional)_

How often (in seconds) the cache runs a background cleanup task to remove expired entries. More frequent cleanup uses slightly more CPU but keeps memory usage lower. Less frequent cleanup is more efficient but may retain expired entries longer.

Acceptable formats:
* Number: The number of seconds (e.g., `60` for 1 minute)
* String: A numeric string value (e.g., `"60"`)

Default: `60` (1 minute)

> `serveStale`: Boolean _(Optional)_

Serve expired responses for a short period while the cache refreshes them in the background. This prevents latency spikes when many entries expire simultaneously.

Default: `true`

> `staleDuration`: Number | String _(Optional)_

How long (seconds) stale entries remain eligible to be served while a refresh is in flight. Only applies when `serveStale` is true.

Acceptable formats:
* Number: e.g., `30`
* String: `"30"`

Default: `30`

> `defaultPositiveTTL`: Number | String _(Optional)_

Fallback TTL used when positive answers do not contain any TTLs. Helpful when upstream resolvers omit TTLs.

Acceptable formats:
* Number: e.g., `3600`
* String: `"3600"`

Default: `3600` (1 hour)

> `defaultFallbackTTL`: Number | String _(Optional)_

TTL used when no records contain TTL information at all (e.g., empty authority sections).

Acceptable formats:
* Number: e.g., `300`
* String: `"300"`

Default: `300` (5 minutes)

> `nxDomainTTL`: Number | String _(Optional)_

Override TTL for NXDOMAIN answers.

Acceptable formats:
* Number: e.g., `900`
* String: `"900"`

> `noDataTTL`: Number | String _(Optional)_

Override TTL for NOERROR/NODATA answers.

Acceptable formats:
* Number: e.g., `300`
* String: `"300"`

Defaults: `0` (use `negativeTTL`)

> `ttlJitterPercent`: Number | String _(Optional)_

Adds ±percentage jitter to cached TTLs to avoid the thundering herd problem when many entries expire simultaneously.

Acceptable formats:
* Number: e.g., `0.05`
* String: `"0.05"`

Default: `0.05` (±5%)

> `prefetchThreshold`: Number | String _(Optional)_

Minimum access count before the cache prefetches an entry in the background. Set to `0` to disable.

Acceptable formats:
* Number: e.g., `20`
* String: `"20"`

Default: `10`

> `prefetchPercent`: Number | String _(Optional)_

Fraction of the TTL that must elapse before prefetching begins. Example: `0.9` starts refreshing when 90% of the TTL has passed.

Acceptable formats:
* Number: e.g., `0.85`
* String: `"0.85"`

Default: `0.9`

> `cacheControlEnabled`: Boolean _(Optional)_

Enable support for EDNS0 local options that instruct the cache to skip caching (`nocache`), skip prefetch (`noprefetch`), disable stale serving (`nostale`), or override TTL values (`ttl=NNN`).

Default: `false`

## Features

### LRU Eviction

The cache uses a Least Recently Used (LRU) eviction policy. When the cache reaches `maxEntries`, the least recently accessed entry is automatically removed to make room for new entries. This ensures frequently accessed domains remain cached while infrequently used ones are evicted.

### TTL Management

The cache respects upstream TTL values but can enforce minimum and maximum bounds:
- Responses are cached for their original TTL (or overridden min/max TTL)
- TTL decrements over time as the entry ages
- Expired entries are automatically removed on access or during cleanup
- Clients receive responses with the remaining TTL

### Negative Caching

The cache supports negative caching per RFC 2308:
- NXDOMAIN responses (domain does not exist) are cached
- NODATA responses (domain exists but has no records of the requested type) are cached
- Negative responses use `negativeTTL` or SOA minimum TTL if present

### Thread Safety

The cache is fully thread-safe and optimized for concurrent access:
- Read operations use RWMutex for high concurrency
- O(1) cache lookups and LRU operations
- Atomic counters for statistics

### Statistics

The cache tracks operational statistics accessible via the `Stats()` method:
- Hits: Number of cache hits
- Misses: Number of cache misses
- Evictions: Number of LRU evictions
- Size: Current number of cached entries
- Hit Rate: Percentage of requests served from cache

## Examples

### Basic Configuration

Cache responses from Google Public DNS:

```json
{
  "type": "cache",
  "resolver": {
    "type": "nameServer",
    "address": "8.8.8.8"
  }
}
```

### Production Configuration

High-performance caching with TTL bounds:

```json
{
  "type": "cache",
  "resolver": {
    "type": "doh",
    "url": "https://dns.google/dns-query"
  },
  "maxEntries": 50000,
  "minTTL": 30,
  "maxTTL": 7200,
  "negativeTTL": 600,
  "cleanupInterval": 120
}
```

### Caching with Fallback

Cache responses with automatic fallback to secondary resolver:

```json
{
  "type": "cache",
  "resolver": {
    "type": "sequence",
    "resolvers": [
      {
        "type": "nameServer",
        "address": "1.1.1.1"
      },
      {
        "type": "nameServer",
        "address": "8.8.8.8"
      }
    ]
  },
  "maxEntries": 20000
}
```

### Prefetching Hot Domains

Aggressively cache popular domains and prefetch them before expiration while allowing short-term stale answers:

```json
{
  "type": "cache",
  "resolver": { "type": "doh", "url": "https://cloudflare-dns.com/dns-query" },
  "prefetchThreshold": 15,
  "prefetchPercent": 0.9,
  "serveStale": true,
  "staleDuration": 45,
  "ttlJitterPercent": 0.05,
  "cacheControlEnabled": true
}
```

This configuration refreshes any entry that has been hit 15+ times once 90% of its TTL has passed, serves stale data for up to 45 seconds while refreshing, and honors upstream cache-control hints.

### Warmup Queries

Preload the cache during startup to avoid cold-start misses for critical domains:

```json
{
  "type": "cache",
  "resolver": { "type": "nameServer", "address": "9.9.9.9" }
}
```

## Performance Characteristics

- **Cache Hit**: ~585 ns/op (0.0006 ms)
- **Cache Miss**: Upstream resolver latency + caching overhead (~1-2 μs)
- **LRU Operations**: O(1) constant time
- **Memory Usage**: ~500-1000 bytes per cached entry (varies by response size)
- **Concurrency**: Optimized for high read concurrency with minimal lock contention

## Best Practices

1. **Set Appropriate maxEntries**: Calculate based on expected query diversity and available memory. Each entry uses ~500-1000 bytes.

2. **Use minTTL Carefully**: Setting minTTL too high may cache stale data. Good range: 30-300 seconds.

3. **Set Reasonable maxTTL**: Prevents caching responses too long. Good range: 3600-86400 seconds (1-24 hours).

4. **Monitor Statistics**: Track hit rate to ensure cache is effective. >70% hit rate is ideal.

5. **Combine with Other Resolvers**: Cache works well wrapping sequence, dns64, or filter resolvers.
6. **Monitor Per-Domain Stats**: Identify domains with low hit rates and adjust `prefetchThreshold`/`prefetchPercent`.
7. **Leverage Cache-Control**: Allow upstream resolvers to hint which responses should not be cached (dynamic content, etc.).

## Notes

- The cache uses case-insensitive domain name matching per RFC 4343
- Cache keys include query name, type, and class for precise matching
- The cache is transparent to clients - they receive standard DNS responses
- Response IDs are always matched to the incoming query ID
- Compatible with `concurrentNameServerList` via the NameServerResolver interface
In addition to global stats, the resolver now tracks per-domain counters (hits, misses, stale-served counts, and prefetch counts). Call `DomainStatsFor(name)` or `AllDomainStats()` to inspect them and tune `prefetchThreshold`.

### Stale-While-Revalidate

When `serveStale` is enabled the cache returns an expired response immediately while refreshing it in the background. This prevents spikes when popular entries expire together and keeps clients from observing upstream latency.

### Cache-Control Hints

When `cacheControlEnabled` is `true` upstream resolvers can send EDNS0 local options to influence caching:

* `nocache` – do not store this response
* `noprefetch` – skip prefetch logic for this entry
* `nostale` – do not serve stale copies of this entry
* `ttl=<seconds>` – clamp the TTL to a specific value

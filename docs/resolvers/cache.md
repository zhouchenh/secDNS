# cache

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
  "cleanupInterval": 60
}
```

> `resolver`: [ResolverObject](../configuration.md#resolverobject)

The upstream resolver to query when there is a cache miss. This is required and can be any resolver type (nameServer, doh, sequence, etc.).

> `maxEntries`: Number _(Optional)_

The maximum number of cache entries to store. When this limit is reached, the least recently used (LRU) entry will be evicted to make room for new entries. Set to 0 for unlimited cache size (not recommended for production).

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

The TTL in seconds for negative responses (NXDOMAIN and NODATA). Negative caching helps reduce load on upstream resolvers for non-existent domains. If the upstream response contains an SOA record with a minimum TTL, that value is used instead.

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

## Notes

- The cache uses case-insensitive domain name matching per RFC 4343
- Cache keys include query name, type, and class for precise matching
- The cache is transparent to clients - they receive standard DNS responses
- Response IDs are always matched to the incoming query ID
- Compatible with `concurrentNameServerList` via the NameServerResolver interface

# Version History

### v1.3.0 - 2025.11.30

New Features

* Add [recursive](resolvers/recursive.md) resolver (DNSSEC-validating recursive mode with root hints, adaptive NS ranking, singleflight, loop/referral/CNAME limits, and ECS passthrough/add/override/strip propagation).
* Add [ecs](resolvers/ecs.md) resolver to apply EDNS Client Subnet policy (passthrough/add/override/strip) before delegating to another resolver, enabling ECS control without duplicating caches.

Enhancements

* Recursive resolver hardening: authoritative NODATA handling (SOA/no-referral short-circuit), SOCKS5/bind support, built-in root hints + probes, and DNSSEC validation (RRSIG time checks, DS→DNSKEY chain, NSEC/NSEC3 proof coverage, AD gating).
* ECS core now supports `strip` mode; resolver docs list ECS capabilities and resolver list is alphabetized.

### v1.2.1 - 2025.11.27

New Features

* Add [httpAPIServer](listeners/http_api_server.md), an HTTP listener that exposes DNS resolution via `/resolve` endpoints accepting GET/POST (form or JSON) requests and responding with structured JSON payloads.
* Extend [cache](resolvers/cache.md) resolver with TTL jitter, per-domain statistics, warmup queries, EDNS cache-control hints, and configurable prefetch/stale-serving controls.

Enhancements

* Added descriptor options for cache warmup/prefetch, documented new usage patterns, and exposed per-domain stats APIs.

### v1.2.0 - 2025.11.08

New Feature

* Add high-performance DNS caching resolver with LRU (Least Recently Used) eviction policy, providing significant latency
  reduction and upstream load optimization.
* Support configurable cache size limits with automatic LRU eviction when maximum entries reached.
* Support TTL management with configurable min/max TTL overrides to prevent excessively short or long caching periods.
* Support negative caching (NXDOMAIN and NODATA) per RFC 2308 to reduce upstream queries for non-existent domains.
* Support background cleanup of expired cache entries with configurable cleanup intervals.
* Thread-safe implementation optimized for high-concurrency read operations with O(1) cache lookups and LRU operations.
* Add comprehensive cache statistics tracking (hits, misses, evictions, size, hit rate).
* Add detailed [cache resolver documentation](resolvers/cache.md) with configuration examples and best practices.

Performance

* Cache hit latency: ~585 ns (0.0006 ms) - nearly instant response from cache.
* LRU operations: O(1) constant time for add, remove, and move-to-front.
* Zero lock contention for concurrent cache reads using sync.RWMutex.
* Memory efficient: ~500-1000 bytes per cached entry depending on response size.

### v1.1.9 - 2025.11.07

New Feature

* Add EDNS Client Subnet (ECS) support as defined in RFC 7871 for [nameServer](resolvers/name_server.md) and
  [doh](resolvers/doh.md) resolvers. ECS enables geographic load balancing and optimized DNS responses by including client
  subnet information in queries.
* Support three ECS handling modes: `passthrough` (default, no modification), `add` (add ECS if not present), and
  `override` (always replace ECS with configured value).
* Support both IPv4 and IPv6 client subnets in CIDR notation.
* Add comprehensive [EDNS Client Subnet documentation](EDNS-CLIENT-SUBNET.md) with configuration examples and use cases.

### v1.1.8 - 2025.11.07

Bug Fixes

* Fix critical race conditions in [doh](resolvers/doh.md) and [nameServer](resolvers/name_server.md) resolvers
  using sync.Once for thread-safe client initialization.
* Fix race condition in core instance map using sync.RWMutex for concurrent reads/writes.
* Fix HTTP response body resource leak in [doh](resolvers/doh.md) resolver.
* Fix unbounded goroutine spawning in error handlers.
* Fix potential deadlock in [doh](resolvers/doh.md) error collector channel.

Enhancements

* Add EDNS0 support (UDPSize: 4096) to [nameServer](resolvers/name_server.md) resolver for handling large DNS responses
  over UDP (large TXT records, long CNAME chains).
* Add automatic TCP fallback when UDP responses are truncated, with graceful degradation if TCP fails.
* Optimize TCP fallback with client caching to eliminate repeated allocations (67% memory reduction for large-response
  workloads).
* Maintain full SOCKS5 proxy support in TCP fallback for all protocols (UDP, TCP, TCP-TLS).

Performance

* Zero race conditions detected with Go race detector.
* 99.95% latency improvement for TCP fallback client selection (2ms → 0.001ms).
* Thread-safe with sync.Once providing minimal overhead (~1-5ns atomic load).

### v1.1.7 - 2025.11.07

Enhancement

* Enable [sequence](resolvers/sequence.md), [dns64](resolvers/dns64.md), and filter resolvers
  ([filterOutA](resolvers/filter_out_a.md), [filterOutAAAA](resolvers/filter_out_aaaa.md),
  [filterOutAIfAAAAPresents](resolvers/filter_out_a_if_aaaa_presents.md),
  [filterOutAAAAIfAPresents](resolvers/filter_out_aaaa_if_a_presents.md))
  to be used in [concurrentNameServerList](resolvers/concurrent_name_server_list.md)
  by implementing the nameserver.Resolver interface.

### v1.1.6 - 2024.11.13

New Feature

* Support conditional resource record filtering for A and AAAA by adding new
  resolvers [filterOutAIfAAAAPresents](resolvers/filter_out_a_if_aaaa_presents.md)
  and [filterOutAAAAIfAPresents](resolvers/filter_out_aaaa_if_a_presents.md).

Naming Fixes

* Rename resolver filterA to [filterOutA](resolvers/filter_out_a.md) for better comprehensibility.
* Rename resolver filterAAAA to [filterOutAAAA](resolvers/filter_out_aaaa.md) for better comprehensibility.

### v1.1.5 - 2022.02.05

New Features

* Add multiple addresses support for [address](resolvers/address.md) resolver.
* Support resource record filtering for A and AAAA by adding new resolvers [filterA](resolvers/filter_out_a.md)
  and [filterAAAA](resolvers/filter_out_aaaa.md).

Bug Fix

* Fix a bug in [address](resolvers/address.md) resolver which might cause error in type of answered resource records.

### v1.1.4 - 2021.07.22

New Feature

* Add SOCKS5 proxy support for [nameServer](resolvers/name_server.md) and [doh](resolvers/doh.md).

### v1.1.3 - 2021.07.20

New Feature

* Add an option in [doh](resolvers/doh.md) configuration to allow specifying a resolver for URL resolution.

Bug Fix

* Fix a bug in [doh](resolvers/doh.md) resolver which might cause infinite name resolution when domain names are used
  instead of IP addresses in URLs of DoH services.

### v1.1.2 - 2020.10.20

Bug Fix

* Fix a bug in [doh](resolvers/doh.md) resolver where queries don't fail when error occurs.

### v1.1.1 - 2020.10.19

Bug Fix

* Fix a bug in [nameServer](resolvers/name_server.md) resolver where UDP queries don't time out and fail when the server
  ignores the queries.

### v1.1.0 - 2020.03.26

New Feature

* Support DNS64 by adding a new [dns64](resolvers/dns64.md) resolver.

### v1.0.0 - 2020.03.07

Initial Release

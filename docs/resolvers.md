# Resolvers

secDNS supports the following resolvers.

* [address](resolvers/address.md) - Reply with fixed IPv4/IPv6 addresses.
* [alias](resolvers/alias.md) - Reply with a CNAME (and optionally chase the target).
* [cache](resolvers/cache.md) - (secDNS v1.2.0+) Cache upstream responses with LRU eviction, TTL management, negative caching, prefetch, and stale serving.
* [concurrentNameServerList](resolvers/concurrent_name_server_list.md) - Forward queries to multiple resolvers concurrently and return the first answer.
* [dns64](resolvers/dns64.md) - (secDNS v1.1.0+) Synthesize AAAA records from A responses.
* [doh](resolvers/doh.md) - Forward queries over DNS-over-HTTPS.
* [ecs](resolvers/ecs.md) - Apply EDNS Client Subnet add/override/strip before delegating to another resolver.
* [filterOutA](resolvers/filter_out_a.md) - (secDNS v1.1.6+) Remove A records from upstream responses.
* [filterOutAIfAAAAPresents](resolvers/filter_out_a_if_aaaa_presents.md) - (secDNS v1.1.6+) Remove A records when AAAA answers exist.
* [filterOutAAAA](resolvers/filter_out_aaaa.md) - (secDNS v1.1.6+) Remove AAAA records from upstream responses.
* [filterOutAAAAIfAPresents](resolvers/filter_out_aaaa_if_a_presents.md) - (secDNS v1.1.6+) Remove AAAA records when A answers exist.
* [nameServer](resolvers/name_server.md) - Forward queries to an upstream DNS server (UDP/TCP/DoT).
* [noAnswer](resolvers/no_answer.md) - Reply without any DNS record.
* [notExist](resolvers/not_exist.md) - Reply with NXDOMAIN.
* [recursive](resolvers/recursive.md) - (secDNS v1.3.0+) DNSSEC-validating recursion with adaptive nameserver ranking.
* [sequence](resolvers/sequence.md) - Forward queries to specific resolvers sequentially.

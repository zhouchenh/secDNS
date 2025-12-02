# secDNS

secDNS is a local DNS resolver that helps you bypass DNS spoofing (DNS cache poisoning) from your ISP while keeping latency low and configuration predictable.

## Features

* Upstream flexibility: DoT, DoH, classic DNS (TCP/UDP), and ECS-aware recursive resolution with DNSSEC validation.
* Networking options: SOCKS5 proxy support, source-IP binding, TCP fallback, and qname minimization.
* Performance: LRU cache with TTL bounds, negative caching, stale-while-revalidate, jitter, and prefetch controls.
* IPv6 ready: DNS64 synthesis, ECS handling (add/override/passthrough/strip), and dual-stack listeners.
* Integration: HTTP API listener (`/resolve`) plus UDP/TCP DNS listener; configurable rules route queries to named resolvers.
* Resilience: Failover (`sequence`) and fastest-response (`concurrentNameServerList`) strategies for resolver pools.

## Configuration

See [docs/configuration.md](docs/configuration.md) for the overall JSON schema.

Quick start:
- Download a released binary from GitHub releases.
- Validate a config: `./secDNS -test -config config.json`
- Run with a config: `./secDNS -config config.json`

## Documentation

* [Configuration](docs/configuration.md) - JSON schema, object layout, and examples.
* [Listeners](docs/listeners.md) - Available listeners such as `dnsServer` and the HTTP API, with version notes.
* [Resolvers](docs/resolvers.md) - All upstream resolver types, capabilities, and minimum supported versions.
* [Rules](docs/rules.md) - Rule engines for routing queries to specific resolvers.
* [Version History](docs/version_history.md) - Feature timeline and component availability across releases.

## Version History

See [docs/version_history.md](docs/version_history.md).

## License

[The GNU Affero General Public License v3.0 (GNU AGPLv3)](LICENSE)

## Credits

This project relies on the following third-party project:

* [miekg/dns](https://github.com/miekg/dns)

Documentation loosely ~~copied~~ referenced from:

* [v2ray/v2ray-core](https://github.com/v2ray/v2ray-core)

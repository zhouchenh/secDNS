# recursive Resolver

Status: Full recursive resolution with DNSSEC validation is implemented; production hardening (broader NS probing, caching integration, and extended metrics) is ongoing. Default policy remains permissive; switch to `strict` to enforce DNSSEC.

## Current Behavior
- Starts from built-in IANA root hints (A–M, IPv4/IPv6) with adaptive root/NS ranking (EWMA RTT, probe rotation, failure backoff).
- Iterative recursion with QNAME minimization, DO+EDNS0 by default, UDP first with TCP fallback on truncation.
- Referral handling extracts glue (A/AAAA) and falls back to resolving NS targets; singleflight per question to avoid thundering herds; depth/CNAME/referral limits to prevent loops.
- Authoritative NODATA (SOA/no-referral) responses are returned immediately instead of being retried against other nameservers.
- DNSSEC (root KSK 20326 embedded): validates RRSIG time windows, builds DS→DNSKEY chains to the root, verifies RRsets with trusted keys, and enforces NSEC/NSEC3 coverage for NXDOMAIN/NODATA. AD is set only when the full chain is trusted. `strict` fails on any validation error; `permissive` logs and continues without AD; `off` skips validation.
- Negative answers: validates NSEC/NSEC3 proofs (closest encloser + wildcard denial for NXDOMAIN; type bitmaps for NODATA).
- Connectivity: supports SOCKS5 proxying (username/password) and optional bind address (`sendThrough`) for outbound DNS.

## Default Configuration
```json
{
  "type": "recursive",
  "config": {
    "validateDNSSEC": "permissive",
    "qnameMinimize": true,
    "ednsSize": 1232,
    "timeout": "1500ms",
    "retries": 2,
    "probeTopN": 5,
    "probeInterval": "1h",
    "rootServers": "built-in IANA root hints (A–M)",
    "preferIPv6": false,
    "socks5Proxy": "",
    "socks5Username": "",
    "socks5Password": "",
    "ecsMode": "passthrough",
    "ecsClientSubnet": "",
    "sendThrough": null
  }
}
```

## Notes
- Trust anchors: baked-in ICANN root KSK 20326; RFC 5011-style refresh is not yet implemented.
- Policy tips: use `strict` for DNSSEC-required deployments; `permissive` keeps serving when signatures/proofs are missing or invalid (AD unset).
- Metrics/logging: validation outcomes are counted internally; errors are logged via the resolver logger hook.
- ECS (v1.3.0+): accepts the same `ecsMode` (`passthrough`/`add`/`override`/`strip`) and `ecsClientSubnet` semantics as `nameServer`/`doh`; ECS is propagated on internally generated lookups (CNAME followups, glue, DS/DNSKEY) and honored end-to-end.
- Future hardening: broader NS probing (beyond roots), EDNS padding, cache composition, and richer metrics.

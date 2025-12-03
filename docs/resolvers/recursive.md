# recursive

_Available in secDNS v1.3.0 and later._

* Type: `recursive`

The `recursive` resolver performs full iterative resolution from the IANA root hints with DNSSEC validation. It supports ECS policy controls (passthrough/add/override/strip), qname minimization, UDP-first with TCP fallback, singleflight deduplication keyed by question + ECS, and optional SOCKS5/bind connectivity. Authoritative NODATA (SOA/no-referral) replies are short-circuited. DNSSEC gating checks RRSIG times, DS->DNSKEY chains, and NSEC/NSEC3 proof coverage; AD is set only when the chain validates. See [EDNS Client Subnet](../edns_client_subnet.md) for ECS usage.

## Minimal Example

Define a recursive resolver inline (for example under `resolvers.recursive.<name>.config` in `config.json`):

```json
{
  "type": "recursive",
  "config": {
    "validateDNSSEC": "permissive",
    "qnameMinimize": true
  }
}
```

## ResolverConfigObject

```json
{
  "type": "recursive",
  "config": {
    "validateDNSSEC": "permissive",
    "qnameMinimize": true,
    "ednsSize": 1232,
    "timeout": 1.5,
    "retries": 2,
    "probeTopN": 5,
    "probeInterval": 3600,
    "rootServers": [
      {
        "host": "a.root-servers.net",
        "addresses": ["198.41.0.4", "2001:503:ba3e::2:30"]
      }
    ],
    "maxDepth": 32,
    "maxCNAME": 8,
    "maxReferrals": 16,
    "socks5Proxy": "",
    "socks5Username": "",
    "socks5Password": "",
    "sendThrough": "",
    "ecsMode": "passthrough",
    "ecsClientSubnet": ""
  }
}
```

> `validateDNSSEC`: `"strict"` | `"permissive"` | `"off"` _(Optional)_

DNSSEC policy. `"strict"` fails on any validation error; `"permissive"` serves the response without AD when validation fails; `"off"` skips validation and never sets AD.

Default: `"permissive"`

> `qnameMinimize`: Boolean _(Optional)_

Whether to minimize QNAMEs during iteration.

Default: `true`

> `ednsSize`: Number | String _(Optional)_

UDP payload size placed in the EDNS0 OPT record (1-4096). Accepts numbers or numeric strings.

Default: `1232`

> `timeout`: Number | String _(Optional)_

Per-exchange timeout in seconds (floats allowed). Accepts numbers or numeric strings.

Default: `1.5`

> `retries`: Number _(Optional)_

How many additional attempts to make against the same server before moving on. Range: 0-5.

Default: `2`

> `probeTopN`: Number _(Optional)_

Number of best-ranked servers (EWMA RTT with failure backoff) to try from a candidate set. Range: 1-13.

Default: `5`

> `probeInterval`: Number | String _(Optional)_

Interval hint (seconds) for refreshing nameserver rankings. Accepts numbers or numeric strings.

Default: `3600`

> `rootServers`: Array _(Optional)_

Override root hints. Each entry is an object with `host` (string) and `addresses` (array of IPv4/IPv6 strings). If omitted or empty, the built-in IANA root set (A-M, IPv4/IPv6) is used.

Default: embedded IANA root set

> `maxDepth`: Number _(Optional)_

Overall recursion depth limit (includes referrals and CNAME follow-ups). Range: 1-128.

Default: `32`

> `maxCNAME`: Number _(Optional)_

Maximum CNAME chain length before returning `ErrLoopDetected`. Range: 1-32.

Default: `8`

> `maxReferrals`: Number _(Optional)_

Maximum referral depth before returning `ErrLoopDetected`. Range: 1-64.

Default: `16`

> `socks5Proxy`: String _(Optional)_

Host and port of a SOCKS5 proxy (e.g., `"127.0.0.1:1080"`). If set, all upstream traffic (UDP/TCP) is proxied.

Default: `""`

> `socks5Username`, `socks5Password`: String _(Optional)_

SOCKS5 credentials. Ignored when `socks5Proxy` is empty.

Default: `""`

> `sendThrough`: String _(Optional)_

Local IP to bind for outbound sockets (IPv4 or IPv6). Leave empty to let the OS choose.

Default: `""`

> `ecsMode`: `"passthrough"` | `"add"` | `"override"` | `"strip"` _(Optional)_

ECS handling for outbound queries. `"strip"` removes ECS; `"add"` inserts `ecsClientSubnet` when absent; `"override"` replaces any ECS with `ecsClientSubnet`.

Default: `"passthrough"`

> `ecsClientSubnet`: String _(Optional)_

Client subnet in CIDR form (IPv4 or IPv6). Required when `ecsMode` is `"add"` or `"override"`; ignored for `"passthrough"` and `"strip"`.

Default: `""`

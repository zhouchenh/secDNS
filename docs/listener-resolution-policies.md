# Listener resolution policies

DNS query listeners may select a resolver with an optional outer `resolver` field.
This applies to `dnsServer` and `httpAPIServer`, not the records administration
server. A string selects a named resolver; an inline resolver descriptor also
works. Omitting the field preserves the existing global rules and default.
The empty name `""` refers to that global graph. The existing query validation,
resolution-depth budget, and transport handling remain in effect.

The `policy` resolver uses the existing rule-provider selection logic with its own
`rules` array and `defaultResolver`. It can override selected names and otherwise
reuse a normal graph in process. It consumes the existing depth budget rather
than starting another budget. It is not a new authoritative zone engine.

```json
{
  "listeners": [
    {"type":"dnsServer","config":{"listen":"127.0.0.1","port":1053,"protocol":"udp"}},
    {"type":"dnsServer","resolver":"dns64-policy","config":{"listen":"::1","port":1054,"protocol":"udp"}}
  ],
  "resolvers": {
    "cache": {
      "normal-cache":{"resolver":{"type":"address","config":"192.0.2.10"},"maxEntries":1024,"negativeTTL":30},
      "dns64-cache":{"resolver":"dns64-base","maxEntries":1024}
    },
    "dns64": {
      "dns64-base":{"resolver":"","prefix":"64:ff9b::","ignoreExistingAAAA":false}
    },
    "policy": {
      "dns64-policy":{
        "rules":[{"type":"collection","config":[{"name":"\"exclude.invalid.\"","resolver":""}]}],
        "defaultResolver":"dns64-cache"
      }
    }
  },
  "rules": [],
  "defaultResolver":"normal-cache"
}
```

These are synthetic loopback listeners, not a deployment configuration. Add
separate TCP listeners when needed. The same selection works for IPv4 and IPv6;
it does not create addresses, advertise routes, or configure NAT64 translation.
Multiple named policies are possible, but this example does not reproduce any
existing regional deployment.

## Validation and graph boundaries

Construction occurs inside the configuration loader transaction. Before an
instance is returned (and before any listener can bind), selected configurations
reject unknown references, null selections, unsupported listener kinds, provider
errors, cycles, opaque resolver dependency shapes, paths deeper than 256 edges,
and graphs larger than 4096 distinct resolver objects. All declared named policy
objects must construct successfully, including unused policies; their graphs are
also validated. Inline policies reachable from the global graph enable the same
validation. Unrelated JSON metadata does not enable it.

This is conservative object-graph eligibility, not a proof that every recursive
algorithm is invalid. In particular the legacy `alias` resolver references the
global graph and can make progress by changing a name; that object cycle is
rejected in opt-in configurations. Existing configurations without selections or
policy objects retain their prior behavior. The `authoritative` resolver's
bounded same-store CNAME completion does not introduce such an object cycle.
Custom resolver implementations must expose their actual children through
`resolver.DependencyProvider`; unsupported opaque implementations fail closed.

Policy collections reject malformed entries rather than partially loading.
Other providers retain their existing parsing semantics, but reported provider
errors are fatal in opt-in loads. This is not a strict schema validator for all
legacy resolver and provider fields. There is no hot reload, mutable generation
pinning or cluster synchronization in this feature.

## Client source selection for DNS listeners

A DNS UDP or TCP listener may opt into the top-level `sourcePolicy` with an outer
`sourcePolicyRole`. The policy maps the directly connected socket peer to one of
the existing named resolver graphs. The listener cannot also have an outer
`resolver`; omitting `sourcePolicy` and `sourcePolicyRole` retains the legacy
listener behavior exactly.

```json
{
  "listeners":[
    {"type":"dnsServer","sourcePolicyRole":"normal","config":{"listen":"127.0.0.1","port":1053,"protocol":"udp"}}
  ],
  "resolvers":{"cache":{
    "ordinary-cache":{"resolver":{"type":"address","config":"192.0.2.10"},"maxEntries":1024},
    "special-cache":{"resolver":{"type":"address","config":"192.0.2.20"},"maxEntries":1024}
  }},
  "sourcePolicy":{
    "sourceSets":[
      {"id":"special-clients","members":[{"prefix":"127.0.0.2/32","expiresAt":"2099-01-01T00:00:00Z"}]}
    ],
    "rules":[
      {"listenerRole":"normal","sourceSet":"special-clients","resolver":"special-cache"}
    ],
    "defaults":[
      {"listenerRole":"normal","resolver":"ordinary-cache"}
    ]
  },
  "rules":[],
  "defaultResolver":"ordinary-cache"
}
```

Rule order is significant: the first source set that contains the peer wins.
Members are CIDR prefixes and an optional RFC 3339 `expiresAt`; a member is
inactive at and after that instant. IPv4-mapped peers are treated as IPv4. A
valid peer that matches no active member uses the role's required explicit
default. Missing socket identity, a zone-qualified address, an unknown role, an
unknown resolver reference, partial opt-in, or use on a non-DNS listener fails
closed. EDNS Client Subnet and HTTP or proxy headers are never client identity.
The request pins one clock instant and performs selection before calling a
resolver or looking in a cache.

Each distinct resolver name used by a source policy must reach a disjoint set of
concrete `cache` resolver objects. Configuration loading walks initialized named
resolver dependencies and rejects a cache shared by two different source-policy
resolver names. Reusing one resolver name in several rules or roles is allowed.
This conservative rule avoids cross-policy final answers without changing the
legacy cache-key format. Use separate named cache objects even when their
downstream resolvers are otherwise equivalent.

This source selector is local configuration only. It does not import address
lists, accept address ranges, reload policy, authenticate a source inventory,
configure interfaces or routes, or change network egress.

## Caches and DNS64 limits

Use distinct cache objects above different final-answer policies. Never share a
final synthesized-answer cache with the ordinary listener. A cache below a shared
ordinary graph can be reused because it contains the same ordinary answers for
both fixed listener graphs. The loader does not automatically insert caches;
each resolver object has one fixed graph. The stricter client source contract
above rejects shared concrete cache objects across distinct selected resolver
names. ECS is not client identity.

The existing DNS64 implementation embeds IPv4 in the final 32 bits of a /96
prefix. With `ignoreExistingAAAA:false`, native AAAA and non-NOERROR responses are
preserved. NOERROR without AAAA triggers an A lookup; an AA flag is not required.
Synthesis copies the upstream response, preserves CNAME records and per-record
TTLs, converts A to AAAA, drops answer RRSIGs, and clears AD. Tests cover these
specific behaviors; this is not a claim of complete DNSSEC validation or all RFC
6147 prefix formats. Keep any existing packet translator and routing policy
separate until independently validated.

Tests exercise real loopback UDP/TCP listeners in isolated child processes on
both IP families, shared ordinary and isolated synthesized caches in both query
orders and concurrently, native IPv6 preservation, and an exclusion rule. Each
child is terminated and waited for by its owning test. Source-policy transport
tests send the same question from two IPv4 loopback peers through disjoint caches
in both orders and concurrently. No external DNS service is used.

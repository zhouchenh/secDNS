# ecs

* Type: `ecs`

Applies EDNS Client Subnet (ECS) policy (passthrough/add/override) to queries, then delegates to another resolver. This lets you control ECS without duplicating caches on the downstream resolver (cache or recursive).

## ResolverConfigObject

```json
{
  "resolver": "UpstreamResolverName",
  "ecsMode": "override",
  "ecsClientSubnet": "203.0.113.0/24"
}
```

> `resolver`: Resolver

The downstream resolver to which queries are delegated. ECS is applied before forwarding.

> `ecsMode`: `"passthrough"` | `"add"` | `"override"` | `"strip"` _(Optional)_

How to handle ECS on outbound queries:

* `"passthrough"` (default): leave ECS unchanged.
* `"add"`: add ECS only if not already present.
* `"override"`: always replace ECS with `ecsClientSubnet`.
* `"strip"`: remove any ECS option before forwarding.

> `ecsClientSubnet`: String _(Optional)_

Client subnet to apply when mode is `add` or `override`, in CIDR notation (IPv4 or IPv6), e.g. `"192.0.2.0/24"` or `"2001:db8::/48"`.

## Notes

* ECS is applied on a copy of the query; the original request is not mutated.
* Works with downstream resolvers that cache (e.g., `cache`, `recursive`) so you can reuse a single cache while varying ECS policy.
* Validation follows the same rules as `nameServer`/`doh`: invalid `ecsMode` or subnet causes resolver initialization to fail.

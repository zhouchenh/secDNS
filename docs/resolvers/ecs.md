# ecs

_Available in secDNS v1.3.0 and later._

* Type: `ecs`

The `ecs` resolver applies an EDNS Client Subnet (ECS) policy to outbound queries before delegating to another resolver. Use it to add, override, strip, or simply pass through ECS while reusing the same downstream cache or recursive resolver.

## ResolverConfigObject

```json
{
  "resolver": {
    "type": "recursive",
    "config": {
      "validateDNSSEC": "permissive"
    }
  },
  "ecsMode": "override",
  "ecsClientSubnet": "203.0.113.0/24"
}
```

> `resolver`: String | [ResolverObject](../configuration.md#resolverobject)

The resolver that will perform the actual lookup (for example `cache`, `recursive`, `nameServer`, or `doh`). Accepts a named resolver or an inline [ResolverObject](../configuration.md#resolverobject).

> `ecsMode`: `"passthrough"` | `"add"` | `"override"` | `"strip"` _(Optional)_

How ECS is handled on the outbound query. Defaults to `"passthrough"`.

* `"passthrough"`: Forward any client-supplied ECS unchanged.
* `"add"`: Insert `ecsClientSubnet` only when the client query lacks ECS.
* `"override"`: Replace any incoming ECS with `ecsClientSubnet`.
* `"strip"`: Remove all ECS options before forwarding.

> `ecsClientSubnet`: String _(Optional)_

Client subnet in CIDR notation (IPv4 or IPv6), required when `ecsMode` is `"add"` or `"override"`; ignored for `"passthrough"` and `"strip"`.

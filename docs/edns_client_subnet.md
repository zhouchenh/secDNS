# EDNS Client Subnet (ECS)

EDNS Client Subnet (ECS, RFC 7871) lets a resolver include a client subnet hint so authoritative servers can return geography-aware answers. secDNS supports ECS on resolvers that take `ecsMode` and `ecsClientSubnet` settings (see `nameServer`, `doh`, `ecs`, `recursive`).

## Supported Resolvers

- `nameServer` – DNS over UDP/TCP/DoT
- `doh` – DNS-over-HTTPS
- `recursive` – ECS propagated through glue/referrals/CNAME/DS/DNSKEY
- `ecs` wrapper – apply ECS policy before delegating (use to vary policy while sharing cache/recursive)

## ECS Settings

> `ecsMode`: `"passthrough"` | `"add"` | `"override"` | `"strip"` _(Optional)_

Controls how ECS is handled on outbound queries.

Default: `"passthrough"`

> `ecsClientSubnet`: String _(Optional)_

CIDR subnet (IPv4 or IPv6). Required when `ecsMode` is `"add"` or `"override"`; ignored for `"passthrough"` and `"strip"`.

### Mode Summary

* `passthrough`: forward any client ECS unchanged; no ECS added if absent.
* `add`: insert `ecsClientSubnet` only when the client did not send ECS.
* `override`: replace any client ECS with `ecsClientSubnet`.
* `strip`: remove ECS before forwarding.

## Examples

### Add ECS when missing (IPv4)

```json
{
  "type": "nameServer",
  "address": "1.1.1.1",
  "ecsMode": "add",
  "ecsClientSubnet": "203.0.113.0/24"
}
```

### Override ECS (IPv6)

```json
{
  "type": "doh",
  "url": "https://cloudflare-dns.com/dns-query",
  "ecsMode": "override",
  "ecsClientSubnet": "2001:db8::/48"
}
```

### Strip ECS

```json
{
  "type": "ecs",
  "resolver": { "type": "recursive" },
  "ecsMode": "strip"
}
```

## Tips & Troubleshooting

* Use the `ecs` wrapper to vary ECS policy per listener or rule while sharing downstream cache/recursive resolvers.
* ECS-aware caches key entries by ECS scope/prefix; different subnets do not mix.
* For privacy, use a broader prefix (e.g., `0.0.0.0/0` or `2000::/3`) in `override` mode.
* Ensure `ecsClientSubnet` is valid CIDR when `ecsMode` is `add`/`override`; invalid subnets are rejected.
* If ECS is absent in queries, confirm `ecsMode` is not `passthrough`/`strip`.

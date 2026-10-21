# dns64

_Available in secDNS v1.1.0 and later._

* Type: `dns64`

(secDNS v1.1.0+) The `dns64` resolver synthesizes AAAA resource records from A resource records returned by another
resolver.

## ResolverConfigObject

```json
{
  "resolver": "RecursiveResolver",
  "prefix": "64:ff9b::",
  "ignoreExistingAAAA": false
}
```

or inline:

```json
{
  "resolver": {
    "type": "recursive",
    "config": {
      "validateDNSSEC": "permissive"
    }
  },
  "prefix": "64:ff9b::",
  "ignoreExistingAAAA": false
}
```

> `resolver`: String | [ResolverObject](../configuration.md#resolverobject)

The underlying resolver graph. With the default policy, it receives the original
AAAA query first and an A query only when synthesis is needed. Queries for other
types pass through unchanged. Acceptable formats are:

* String: The unique name of the resolver.
* [ResolverObject](../configuration.md#resolverobject): A [ResolverObject](../configuration.md#resolverobject), defining
  an anonymous resolver.

> `prefix`: String _(Optional)_

The base IPv6 address of a **/96 synthesis prefix**, written as an address without
CIDR notation, for example `"64:ff9b::"`. The implementation copies the first
96 bits and places the IPv4 address in the final 32 bits. It does not implement
the alternative prefix lengths used by other DNS64 implementations. Use a base
with its final 32 bits zero; do not supply `"64:ff9b::/96"`.

Default: `"64:ff9b::"`

> `ignoreExistingAAAA`: Boolean _(Optional)_

When `false`, an existing AAAA answer is returned unchanged. A successful
NOERROR response without an AAAA record triggers an A lookup; the response does
not need the authoritative (AA) flag. NXDOMAIN, SERVFAIL, REFUSED and upstream
errors do not trigger that fallback.

When `true`, the initial AAAA lookup is skipped and the resolver queries A
directly. Enable this only when replacing native IPv6 answers is intended.

Default: `false`

## Response and deployment boundaries

Synthesis copies the upstream response, preserves CNAME records and each record's
TTL, and converts A records to AAAA. It drops answer-section RRSIG records and
clears the authenticated-data (AD) flag. This behavior is not a complete DNSSEC
validation policy; validation belongs to the configured upstream graph.

For normal DNS and DNS64 in one process, select separate listener graphs as shown
in [listener resolution policies](../listener-resolution-policies.md). The DNS64
graph can call the ordinary graph in process, without forwarding queries back to
the service address. Keep caches of final synthesized answers separate from
ordinary answers, and use explicit policy rules for synthesis exclusions.

This resolver does not translate packets, configure a NAT64 gateway, assign
listener addresses, or announce BGP/OSPF routes. Its prefix must match the
existing translator's prefix. Before replacing another DNS64 service, verify its
prefix, native-AAAA policy, exclusions, upstream/egress selection and failure
behavior; matching a sample synthesized answer alone does not establish parity.

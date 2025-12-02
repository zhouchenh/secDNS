# filterOutA

_Available in secDNS v1.1.6 and later._

* Type: `filterOutA`

(secDNS v1.1.6+) The `filterOutA` resolver filters out A resource records in replies from an upstream DNS server.

Use this object as the `config` for entries under `resolvers.filterOutA.<name>` in `config.json`. For inline usage, wrap it with `"type": "filterOutA"` and a `config` block.

## ResolverConfigObject

```json
"UpstreamResolverName"
```

or an inline resolver:

```json
{
  "type": "nameServer",
  "config": {
    "address": "8.8.8.8"
  }
}
```

> String | [ResolverObject](../configuration.md#resolverobject)

A resolver that performs the actual lookup before A records are removed. Acceptable formats are:

* String: The unique name of the resolver.
* [ResolverObject](../configuration.md#resolverobject): An inline resolver definition.

When the incoming query type is `A`, an empty response is returned. For other query types, the upstream response is
returned with all A records stripped from the answer, authority, and additional sections.

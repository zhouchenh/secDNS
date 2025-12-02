# filterOutAAAA

_Available in secDNS v1.1.6 and later._

* Type: `filterOutAAAA`

(secDNS v1.1.6+) The `filterOutAAAA` resolver filters out AAAA resource records in replies from an upstream DNS server.

Use this object as the `config` for entries under `resolvers.filterOutAAAA.<name>` in `config.json`. For inline usage, wrap it with `"type": "filterOutAAAA"` and a `config` block.

## ResolverConfigObject

```json
"UpstreamResolverName"
```

or an inline resolver:

```json
{
  "type": "nameServer",
  "config": {
    "address": "2001:4860:4860::8888"
  }
}
```

> String | [ResolverObject](../configuration.md#resolverobject)

A resolver that performs the actual lookup before AAAA records are removed. Acceptable formats are:

* String: The unique name of the resolver.
* [ResolverObject](../configuration.md#resolverobject): An inline resolver definition.

When the incoming query type is `AAAA`, an empty response is returned. For other query types, the upstream response is
returned with all AAAA records stripped from the answer, authority, and additional sections.

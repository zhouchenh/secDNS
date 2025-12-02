# filterOutAIfAAAAPresents

_Available in secDNS v1.1.6 and later._

* Type: `filterOutAIfAAAAPresents`

(secDNS v1.1.6+) The `filterOutAIfAAAAPresents` resolver filters out A resource records in replies from an upstream DNS
server, if any AAAA resource record presents in replies from an upstream DNS server when some AAAA queries are made.

Use this object as the `config` for entries under `resolvers.filterOutAIfAAAAPresents.<name>` in `config.json`. For inline usage, wrap it with `"type": "filterOutAIfAAAAPresents"` and a `config` block.

## ResolverConfigObject

```json
"UpstreamResolverName"
```

or an inline resolver:

```json
{
  "type": "nameServer",
  "config": {
    "address": "2606:4700:4700::1111"
  }
}
```

> String | [ResolverObject](../configuration.md#resolverobject)

A resolver that performs the actual lookup before conditional filtering is applied. Acceptable formats are:

* String: The unique name of the resolver.
* [ResolverObject](../configuration.md#resolverobject): An inline resolver definition.

The resolver first attempts an AAAA lookup to determine if IPv6 answers exist. If no AAAA records are present, the query
is passed through unmodified. When AAAA answers exist, `A` questions receive an empty response, and other question types
are returned with A records removed from the answer, authority, and additional sections.

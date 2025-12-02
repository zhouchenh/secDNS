# filterOutAAAAIfAPresents

_Available in secDNS v1.1.6 and later._

* Type: `filterOutAAAAIfAPresents`

(secDNS v1.1.6+) The `filterOutAAAAIfAPresents` resolver filters out AAAA resource records in replies from an upstream
DNS server, if any A resource record presents in replies from an upstream DNS server when some A queries are made.

Use this object as the `config` for entries under `resolvers.filterOutAAAAIfAPresents.<name>` in `config.json`. For inline usage, wrap it with `"type": "filterOutAAAAIfAPresents"` and a `config` block.

## ResolverConfigObject

```json
"UpstreamResolverName"
```

or an inline resolver:

```json
{
  "type": "nameServer",
  "config": {
    "address": "1.1.1.1"
  }
}
```

> String | [ResolverObject](../configuration.md#resolverobject)

A resolver that performs the actual lookup before conditional filtering is applied. Acceptable formats are:

* String: The unique name of the resolver.
* [ResolverObject](../configuration.md#resolverobject): An inline resolver definition.

The resolver first attempts an A lookup to determine if IPv4 answers exist. If no A records are present, the query is
passed through unmodified. When A answers exist, `AAAA` questions receive an empty response, and other question types are
returned with AAAA records removed from the answer, authority, and additional sections.

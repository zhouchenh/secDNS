# filterOutAAAAIfAPresents

* Type: `filterOutAAAAIfAPresents`

(secDNS v1.1.6+) The `filterOutAAAAIfAPresents` resolver filters out AAAA resource records in replies from an upstream
DNS server, if any A resource record presents in replies from an upstream DNS server when some A queries are made.

## ResolverConfigObject

```json
{}
```

> String | [ResolverObject](../configuration.md#resolverobject)

A resolver for querying resource records. Acceptable formats are:

* String: The unique name of the resolver.
* [ResolverObject](../configuration.md#resolverobject): A [ResolverObject](../configuration.md#resolverobject), defining
  an anonymous resolver. 

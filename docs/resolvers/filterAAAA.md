# filterAAAA

* Type: `filterAAAA`

(secDNS v1.1.5+) The `filterAAAA` resolver filters out AAAA resource records in replies from an upstream DNS server.

## ResolverConfigObject

```json
{}
```

> String | [ResolverObject](../configuration.md#resolverobject)

A resolver for querying resource records. Acceptable formats are:

* String: The unique name of the resolver.
* [ResolverObject](../configuration.md#resolverobject): A [ResolverObject](../configuration.md#resolverobject), defining
  an anonymous resolver. 

# filterOutA

* Type: `filterOutA`

(secDNS v1.1.6+) The `filterOutA` resolver filters out A resource records in replies from an upstream DNS server.

## ResolverConfigObject

```json
{}
```

> String | [ResolverObject](../configuration.md#resolverobject)

A resolver for querying resource records. Acceptable formats are:

* String: The unique name of the resolver.
* [ResolverObject](../configuration.md#resolverobject): A [ResolverObject](../configuration.md#resolverobject), defining
  an anonymous resolver. 

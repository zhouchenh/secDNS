# dns64

* Type: `dns64`

The `dns64` resolver synthesizes AAAA resource records from A resource records returned by another resolver.

## ResolverConfigObject

```json
{
  "resolver": {},
  "prefix": "64:ff9b::",
  "ignoreExistingAAAA": false
}
```

> `resolver`: String | [ResolverObject](../configuration.md#resolverobject)

A resolver for querying A resource records. Acceptable formats are:

* String: The unique name of the resolver.
* [ResolverObject](../configuration.md#resolverobject): A [ResolverObject](../configuration.md#resolverobject), defining an anonymous resolver.

> `prefix`: String _(Optional)_

An IPv6 prefix for IPv6 address synthesis.

Default: `"64:ff9b::"`

> `ignoreExistingAAAA`: Boolean _(Optional)_

Ignore existing AAAA resource records, forcibly synthesizing AAAA resource records from A resource records

Default: `false`

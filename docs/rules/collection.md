# collection

* Type: `collection`

The `collection` rule contains a collection of name-resolver pairs.

## RuleConfigObject

The RuleConfigObject of the collection rule is an array of [NameResolverPairObject](#nameresolverpairobject).

```json
[
  {
    "name": "www.example.com",
    "resolver": {}
  },
  {
    "name": "www.example.org",
    "resolver": {}
  }
]
```

### NameResolverPairObject

```json
{
  "name": "www.example.com",
  "resolver": {}
}
```

> `name`: String

A valid domain name. Acceptable formats are:

* `"example.com"`: Matches the domain and all its subdomains (e.g., `www.example.com`).
* `"\"example.com\""`: Matches only the literal domain name. Escape the inner quotes with a backslash; subdomains such as `www.example.com` are **not** matched.

> `resolver`: String | [ResolverObject](../configuration.md#resolverobject)

The resolver associated with the domain name. Accepts either the name of a resolver or an inline [ResolverObject](../configuration.md#resolverobject).

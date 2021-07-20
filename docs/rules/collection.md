# collection

* Type: `collection`

The `collection` rule contains a collection of name-resolver pairs.

## RuleConfigObject

The RuleConfigObject of the collection rule is an array of [NameResolverPairObject](#nameresolverpairobject)

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

* String: A valid domain name, such as `"example.com"`. Subdomains like `www.example.com` are also matched.

* "String": A valid domain name quoted by a pair of double quotation marks, such as `"\"example.com\""`. Note that a
  backslash (`\ `) before the double quotation mark (`"`) is required. Subdomains like `www.example.com` are **NOT**
  matched.

> `resolver`: String | [ResolverObject](../configuration.md#resolverobject)

The resolver associated with the domain name.

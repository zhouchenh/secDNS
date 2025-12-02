# sequence

* Type: `sequence`

The `sequence` resolver forwards the queries to specific resolvers configured
in [ResolverConfigObject](#resolverconfigobject), and forwards the replies back to the clients. If one resolver fails to
process the queries, the next resolver will process these queries instead.

Use this object as the `config` for entries under `resolvers.sequence.<name>` in `config.json` (see [configuration.md](../configuration.md#resolverdefinitionobject)). For inline usage, wrap it with `"type": "sequence"` and a `config` block as shown below.

## ResolverConfigObject

```json
[
  "PrimaryDNS",
  "SecondaryDNS",
  {
    "type": "doh",
    "config": {
      "url": "https://dns.google/dns-query"
    }
  }
]
```

> \[ String | [ResolverObject](../configuration.md#resolverobject) \]

An ordered array of resolvers. Each entry is tried in sequence until one responds successfully.

* String: The unique name of a resolver.
* [ResolverObject](../configuration.md#resolverobject): An inline resolver.

> Example
>
> ```json
> [
>   "GooglePublicDNS",
>   {
>     "type": "nameServer",
>     "config": {
>       "address": "8.8.4.4"
>     }
>   }
> ]
> ```
>
> The example above is a ResolverConfigObject for `sequence` to use Google Public DNS. Note that `"GooglePublicDNS"` is the unique name of a pre-defined resolver in [this example](../configuration.md#example).

If every resolver in the list fails, the final error from the last resolver is returned to the client.

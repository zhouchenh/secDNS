# sequence

* Type: `sequence`

The `sequence` resolver forwards the queries to specific resolvers configured
in [ResolverConfigObject](#resolverconfigobject), and forwards the replies back to the clients. If one resolver fails to
process the queries, the next resolver will process these queries instead.

## ResolverConfigObject

```json
[
]
```

> \[ String | [ResolverObject](../configuration.md#resolverobject) \]

An array of configurations for resolvers.

* String: The unique name of a resolver.
* [ResolverObject](../configuration.md#resolverobject): An anonymous resolver.

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

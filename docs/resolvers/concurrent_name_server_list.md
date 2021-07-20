# concurrentNameServerList

* Type: `concurrentNameServerList`

The `concurrentNameServerList` resolver concurrently forwards the queries to specific resolvers configured
in [ResolverConfigObject](#resolverconfigobject). The first reply for every query from other resolvers will be forwarded
back to clients, other replies are discarded.

Note that `concurrentNameServerList` currently supports forwarding to [doh](doh.md), [nameServer](name_server.md)
and [itself](concurrent_name_server_list.md), other resolvers will be ignored if present
in [ResolverConfigObject](#resolverconfigobject).

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
> The example above is a ResolverConfigObject for `concurrentNameServerList` to use Google Public DNS. Note that `"GooglePublicDNS"` is the unique name of a pre-defined resolver in [this example](../configuration.md#example).

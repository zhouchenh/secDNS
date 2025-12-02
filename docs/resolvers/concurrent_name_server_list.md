# concurrentNameServerList

* Type: `concurrentNameServerList`

The `concurrentNameServerList` resolver forwards each query to multiple resolvers at the same time. The first successful
reply is sent back to the client; all slower replies are discarded.

Resolvers that implement the nameserver interface can be used here, including [nameServer](name_server.md),
[doh](doh.md), [sequence](sequence.md), [dns64](dns64.md), [cache](cache.md), filter resolvers, and
`concurrentNameServerList` itself.

Use this object as the `config` for entries under `resolvers.concurrentNameServerList.<name>` in `config.json` (see [configuration.md](../configuration.md#resolverdefinitionobject)). For inline usage, wrap it with `"type": "concurrentNameServerList"` and a `config` block as shown below.

## ResolverConfigObject

```json
[
  "PrimaryDNS",
  "BackupDNS",
  {
    "type": "cache",
    "config": {
      "resolver": "Recursive",
      "prefetchThreshold": 10
    }
  }
]
```

> \[ String | [ResolverObject](../configuration.md#resolverobject) \]

An array of resolvers to query concurrently.

* String: The unique name of a resolver.
* [ResolverObject](../configuration.md#resolverobject): An inline resolver definition.

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

At least one resolver must be provided. Because responses are accepted from the first resolver that replies, prefer
pairing fast, reliable upstreams and ensure each entry implements the nameserver interface.

# Configuration

secDNS uses JSON-based configurations. The top level structure of the configuration is shown below.

```json
{
  "listeners": [],
  "resolvers": {},
  "rules": [],
  "defaultResolver": {}
}
```

> `listeners`: \[ [ListenerObject](#listenerobject) \]

An array of [ListenerObject](#listenerobject) as configuration for [listeners](listeners.md).

> `resolvers`: [ResolverDefinitionObject](#resolverdefinitionobject)

Configuration for resolver definitions.

> `rules`: \[ [RuleObject](#ruleobject) \]

An array of [RuleObject](#ruleobject) as configuration for custom [rules](rules.md).

> `defaultResolver`: String | [ResolverObject](#resolverobject)

Configuration for default resolver. Can be the unique name of a resolver or specific configuration defined in
a [ResolverObject](#resolverobject). This resolver will be used if no rule defined in `rules` is matched.

## ListenerObject

A ListenerObject defines a listener. It handles incoming connections to secDNS. Available types of listeners are
listed [here](listeners.md).

```json
{
  "type": "listener_type",
  "config": {}
}
```

> `type`: String

The type of the listener. See each individual listed [here](listeners.md) for available values.

> `config`: ListenerConfigObject

Listener-specific configuration. See `ListenerConfigObject` defined in each type of the listener.

## ResolverDefinitionObject

The ResolverDefinitionObject is used to define named resolvers. Available types of resolvers are
listed [here](resolvers.md).

```json
{
  "resolver_type_example": {
    "resolver_name_example": {},
    "resolver_name_...": {}
  },
  "resolver_type_...": {
    
  }
}
```

> `"resolver_type_example"`, `"resolver_type_..."`:

The type of a resolver. Note that `"resolver_type_example"` and `"resolver_type_..."` should be replaced by the actual
types of [resolvers](resolvers.md).

> `"resolver_name_example"`, `"resolver_name_..."`: ResolverConfigObject

Specify the name and the configuration of a resolver. Note that `"resolver_name_example"` and `"resolver_name_..."`
should be replaced by any string literal representing a UNIQUE name for the resolver, except for the empty string `""`.
The resolver configuration should be defined in a `ResolverConfigObject`. The format of `ResolverConfigObject` varies by
resolver type.

> ##### Example
>
> ```json
> {
>   "nameServer": {
>     "GooglePublicDNS": {
>       "address": "8.8.8.8"
>     }
>   }
> }
> ```
>
> The example above is a ResolverDefinitionObject which defines a `nameServer` resolver to use Google Public DNS.

## RuleObject

A RuleObject defines a custom rule. It specifies resolvers to be used when resolving specific domain names. Available
types of rules are listed [here](rules.md).

```json
{
  "type": "rule_type",
  "config": {}
}
```

> `type`: String

The type of the rule. See each individual listed [here](rules.md) for available values.

> `config`: RuleConfigObject

Rule-specific configuration. See `RuleConfigObject` defined in each type of the rule.

## ResolverObject

A ResolverObject defines an anonymous resolver. Available types of resolvers are listed [here](resolvers.md).

```json
{
  "type": "resolver_type",
  "config": {}
}
```

> `type`: String

The type of the resolver. See each individual listed [here](resolvers.md) for available values.

> `config`: ResolverConfigObject

Resolver-specific configuration. See `ResolverConfigObject` defined in each type of the resolver.

## Example: HTTP API With Cache Prefetch

The following snippet wires the HTTP API listener to a cache resolver that prefetches popular domains and warms the cache at startup. See [listeners/http_api_server.md](listeners/http_api_server.md) and [resolvers/cache.md](resolvers/cache.md) for the detailed option reference.

```json
{
  "listeners": [
    {
      "type": "httpAPIServer",
      "config": {
        "listen": "127.0.0.1",
        "port": 8080,
        "path": "/resolve"
      }
    }
  ],
  "resolvers": {
    "cache": {
      "edgeCache": {
        "resolver": {
          "type": "nameServer",
          "config": {
            "address": "1.1.1.1",
            "timeout": 3000
          }
        },
        "maxEntries": 50000,
        "prefetchThreshold": 15,
        "prefetchPercent": 0.9,
        "serveStale": true,
        "staleDuration": 45,
        "warmupQueries": [
          {"name": "example.com.", "type": 1},
          {"name": "cloudflare.com.", "type": 28},
          {"name": "cdn.example.net.", "type": 1}
        ]
      }
    }
  },
  "defaultResolver": "edgeCache"
}
```

* `warmupQueries` primes the resolver with known-hot domains on start.
* `prefetchThreshold`/`prefetchPercent` refresh popular entries before they expire.
* The HTTP API exposes the cached answers via `/resolve` so monitoring systems can hit a single endpoint.

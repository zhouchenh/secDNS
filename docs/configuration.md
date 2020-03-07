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

Configuration for default resolver. Can be the unique name of a resolver or specific configuration defined in a [ResolverObject](#resolverobject). This resolver will be used if no rule defined in `rules` is matched.

## ListenerObject

A ListenerObject defines a listener. It handles incoming connections to secDNS. Available types of listeners are listed [here](listeners.md).

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

The ResolverDefinitionObject is used to define named resolvers. Available types of resolvers are listed [here](resolvers.md).

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

The type of a resolver. Note that `"resolver_type_example"` and `"resolver_type_..."` should be replaced by the actual types of [resolvers](resolvers.md).

> `"resolver_name_example"`, `"resolver_name_..."`: ResolverConfigObject

Specify the name and the configuration of a resolver. Note that `"resolver_name_example"` and `"resolver_name_..."` should be replaced by any string literal representing a UNIQUE name for the resolver, except for the empty string `""`. The resolver configuration should be defined in a `ResolverConfigObject`. The format of `ResolverConfigObject` varies by resolver type.

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

A RuleObject defines a custom rule. It specifies resolvers to be used when resolving specific domain names. Available types of rules are listed [here](rules.md).

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

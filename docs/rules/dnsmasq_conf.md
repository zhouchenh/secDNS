# dnsmasqConf

* Type: `dnsmasqConf`

The `dnsmasqConf` rule reads domain names from a dnsmasq configuration (`.conf`) file.

A valid dnsmasq configuration should contain lines of configuration like `server=/www.example.com/x.x.x.x`. Only the
domain names will be accepted and take effect, other configurations are ignored.

## RuleConfigObject

```json
{
  "filePath": "accelerated-domains.china.conf",
  "resolver": "ChinaDNS"
}
```

> `filePath`: String

The path to a valid dnsmasq configuration file. It may be a relative path (can be relative to the secDNS config file) or
an absolute path.

> `resolver`: String | [ResolverObject](../configuration.md#resolverobject)

The resolver associated with the domain names read from the dnsmasq configuration file.

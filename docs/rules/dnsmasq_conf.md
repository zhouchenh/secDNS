# dnsmasqConf

* Type: `dnsmasqConf`

The `dnsmasqConf` rule reads domain names from a dnsmasq configuration (`.conf`) file.

A valid dnsmasq configuration should contain lines of configuration like `server=/www.example.com/x.x.x.x`. Only the
domain names will be accepted and take effect—other directives are ignored. Invalid or malformed domains are skipped and reported through the rule provider’s error handler.

> **Note:** If the same domain appears multiple times in a dnsmasq file (or across multiple rules), only the first mapping takes effect. Subsequent duplicates trigger a `DuplicateRuleWarning` so configuration mistakes can be detected quickly.

## RuleConfigObject

```json
{
  "filePath": "accelerated-domains.china.conf",
  "resolver": "ChinaDNS"
}
```

> `filePath`: String

The path to a valid dnsmasq configuration file. It may be a relative path (can be relative to the secDNS config file) or
an absolute path. The provider reads and validates the file once, caching the domain list for subsequent iterations. Call `Reset()` on the provider if you need to iterate from the beginning again.

> `resolver`: String | [ResolverObject](../configuration.md#resolverobject)

The resolver associated with the domain names read from the dnsmasq configuration file.

## Behavior

* Comments (`# ...`) and surrounding whitespace are stripped before parsing.
* Invalid lines or domains are ignored and reported via the error handler.
* Files are read once and cached in memory to improve performance across large rule sets.
* The provider can be re-used by calling `Reset()` if new iteration over the cached entries is required.

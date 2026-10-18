# address

* Type: `address`

The `address` resolver replies to A/AAAA queries with static IPv4/IPv6 addresses. The legacy string and array forms use a TTL of 60 seconds per record.

## ResolverConfigObject

Example 1:

```json
"127.0.0.1"
```

Example 2 (secDNS v1.1.5+):

```json
[
  "127.0.0.1",
  "::1"
]
```

Example 3 (configurable TTL and opt-in sequence fallthrough):

```json
{
  "addresses": [
    "192.0.2.10",
    "2001:db8::10"
  ],
  "ttl": 300,
  "fallthrough": true
}
```

> String | \[String\] | Object

One, or starting from secDNS v1.1.5, more IP addresses to be replied. Both IPv4 addresses and IPv6 addresses are
supported.

* String: A valid IP address, such as `"127.0.0.1"`.
* \[String\] (secDNS v1.1.5+): An array of valid IP addresses, such as `["127.0.0.1", "::1"]`. 
* Object:
  * `addresses` (required): A valid IP address or a non-empty array of valid IP addresses.
  * `ttl` (optional): An integer from `0` through `4294967295`, in seconds. The default is `60`; an explicit `0` is preserved.
  * `fallthrough` (optional): A boolean, default `false`. When `true`, the resolver returns a not-supported result if the query is not A or AAAA, or if no address of the queried family is configured. This is useful as the first entry in a [sequence](sequence.md), whose next resolver can then answer the query.

For example, this sequence returns the static IPv4 answer for A queries and delegates AAAA and other query types to `DefaultResolver`:

```json
[
  {
    "type": "address",
    "config": {
      "addresses": "192.0.2.10",
      "ttl": 300,
      "fallthrough": true
    }
  },
  "DefaultResolver"
]
```

With `fallthrough` omitted or `false`, a missing address family or another query type retains the legacy behavior: an empty successful response is returned, so a containing `sequence` stops at this resolver.

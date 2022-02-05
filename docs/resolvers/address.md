# address

* Type: `address`

The `address` resolver replies the queries with an IPv4 or IPv6 address.

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

> String | \[String\] (secDNS v1.1.5+)

One, or starting from secDNS v1.1.5, more IP addresses to be replied. Both IPv4 addresses and IPv6 addresses are
supported.

* String: A valid IP address, such as `"127.0.0.1"`.
* \[String\] (secDNS v1.1.5+): An array of valid IP addresses, such as `["127.0.0.1", "::1"]`. 

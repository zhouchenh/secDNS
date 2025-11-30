# doh

* Type: `doh`

The `doh` resolver sends the queries to an upstream DNS server and sends back the replies, using DNS over HTTPS (DoH).

## ResolverConfigObject

```json
{
  "url": "https://dns.google/dns-query",
  "queryTimeout": 1.5,
  "tlsServerName": "dns.google",
  "sendThrough": "0.0.0.0",
  "urlResolver": "",
  "ecsMode": "add",
  "ecsClientSubnet": "192.168.1.0/24"
}
```

> `url`: String

The URL for accessing the DoH service on an upstream DNS server.

> `queryTimeout`: Number | String _(Optional)_

The time that the resolver waits before a query is failed. Acceptable formats are:

* Number: The number of seconds to wait before the timeout.
* String: A numeric string value, such as `"1.5"`, representing the number of seconds to wait before the timeout.

Default: `2`

> `tlsServerName`: String _(Optional)_

The server name of the upstream DNS server, usually a valid domain name. Only required when specifying the host using an
IP address in `url`.

Default: `""`

> `sendThrough`: String _(Optional)_

An IP address for sending traffic out. The default value, "0.0.0.0" represents randomly choosing an IP address available
on the host. Otherwise, the value has to be an IP address from existing network interfaces.

Default: `"0.0.0.0"`

> `urlResolver`: String | [ResolverObject](../configuration.md#resolverobject) _(Optional)_

(secDNS v1.1.3+) The resolver for resolving the domain name in `url`. Only used when specifying the host using a domain
name in `url`.

Default: `""`

> `socks5Proxy`: String _(Optional)_

(secDNS v1.1.4+) The host and port of a SOCKS5 proxy server, like `"127.0.0.1:1080"`, which is used when connecting to
upstream DNS servers. If this option is not specified or set to the default value `""`, connections to upstream DNS
servers will be direct connections and not via any SOCKS5 proxy.

Default: `""`

> `socks5Username`: String _(Optional)_

(secDNS v1.1.4+) The username for SOCKS5 proxy authentication.

Default: `""`

> `socks5Password`: String _(Optional)_

(secDNS v1.1.4+) The password for SOCKS5 proxy authentication.

Default: `""`

> `ecsMode`: `"passthrough"` | `"add"` | `"override"` | `"strip"` _(Optional)_

(secDNS v1.1.9+) The EDNS Client Subnet (ECS) handling mode as defined in RFC 7871. Specifies how client subnet information should be managed in DNS queries:

* `"passthrough"`: Do not modify ECS options. Client ECS information is passed through unchanged.
* `"add"`: Add ECS option with the configured `ecsClientSubnet` only if the client didn't send one. Existing client ECS is preserved.
* `"override"`: Always replace any ECS option with the configured `ecsClientSubnet`, regardless of client requests.
* `"strip"` (secDNS v1.3.0+): Remove any ECS option before sending the query upstream.

See [EDNS Client Subnet documentation](../EDNS-CLIENT-SUBNET.md) for detailed information and use cases.

Default: `"passthrough"`

> `ecsClientSubnet`: String _(Optional)_

(secDNS v1.1.9+) The client subnet to use for EDNS Client Subnet (ECS) in CIDR notation. Required when `ecsMode` is set to `"add"` or `"override"`; ignored for `"passthrough"` and `"strip"`.

Examples:
* IPv4: `"192.168.1.0/24"`, `"10.0.0.0/8"`, `"172.16.0.0/12"`
* IPv6: `"2001:db8::/32"`, `"2001:0db8:85a3::/48"`

The subnet information is used by authoritative nameservers to provide geographically optimized responses. See [EDNS Client Subnet documentation](../EDNS-CLIENT-SUBNET.md) for more details.

Default: `""`

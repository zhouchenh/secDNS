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
  "urlResolver": ""
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

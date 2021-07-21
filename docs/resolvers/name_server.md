# nameServer

* Type: `nameServer`

The `nameServer` resolver sends the queries to an upstream DNS server, and sends back the replies.

## ResolverConfigObject

```json
{
  "address": "8.8.8.8",
  "port": 853,
  "protocol": "tcp-tls",
  "queryTimeout": 1.5,
  "tlsServerName": "dns.google",
  "sendThrough": "0.0.0.0"
}
```

> `address`: String

The IP address of an upstream DNS server.

> `port`: Number | String _(Optional)_

The port of the DNS service. Acceptable formats are:

* Number: The actual port number.
* String: A numeric string value, such as `"1234"`.

Default: `53`

> `protocol`: `"tcp"` | `"udp"` | `"tcp-tls"` _(Optional)_

The type of the network protocol used to communicate with the upstream DNS server, `"tcp"`, `"udp"` or `"tcp-tls"` (DNS
over TLS).

Default: `"udp"`

> `queryTimeout`: Number | String _(Optional)_

The time that the resolver waits before a query is failed. Acceptable formats are:

* Number: The number of seconds to wait before the timeout.
* String: A numeric string value, such as `"1.5"`, representing the number of seconds to wait before the timeout.

Default: `2`

> `tlsServerName`: String _(Optional)_

The server name of the upstream DNS server, usually a valid domain name. Only required when setting `protocol`
to `"tcp-tls"` (DNS over TLS).

Default: `""`

> `sendThrough`: String _(Optional)_

An IP address for sending traffic out. The default value, "0.0.0.0" represents randomly choosing an IP address available
on the host. Otherwise, the value has to be an IP address from existing network interfaces.

Default: `"0.0.0.0"`

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

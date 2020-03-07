# doh

* Type: `doh`

The `doh` resolver sends the queries to an upstream DNS server and sends back the replies, using DNS over HTTPS (DoH).

## ResolverConfigObject

```json
{
  "url": "https://dns.google/dns-query",
  "queryTimeout": 1.5,
  "tlsServerName": "dns.google",
  "sendThrough": "0.0.0.0"
}
```

> `url`: String

The URL for accessing the DoH service on an upstream DNS server.

> `queryTimeout`: Number | String _(Optional)_

The time that the resolver waits before a query is failed. Acceptable formats are:

* Number: The number of seconds to wait before timeout.
* String: A numeric string value, such as `"1.5"`, representing the number of seconds to wait before timeout.

Default: `2`

> `tlsServerName`: String _(Optional)_

The server name of the upstream DNS server, usually a valid domain name. Only required when specifying the host using an IP address in `url`.

Default: `""`

> `sendThrough`: String _(Optional)_

An IP address for sending traffic out. The default value, "0.0.0.0" represents randomly choosing an IP address available on the host. Otherwise the value has to be an IP address from existing network interfaces.

Default: `"0.0.0.0"`

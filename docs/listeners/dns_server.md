# dnsServer

* Type: `dnsServer`

The `dnsServer` listener listens for DNS queries and sends back answers over classic DNS transports (UDP or TCP).
Configure one entry per transport if you want to listen on both UDP and TCP (as in the sample `config.json`).

## ListenerConfigObject

```json
{
  "listen": "0.0.0.0",
  "port": 53,
  "protocol": "udp"
}
```

> `listen`: String

The IP address to be listened on. Set to "0.0.0.0" to listen for incoming connections on all network interfaces.
Otherwise, the value has to be an IP address from existing network interfaces.

> `port`: Number | String _(Optional)_

The port that the listener is listening on. Acceptable formats are:

* Number: The actual port number.
* String: A numeric string value, such as `"1234"`.

Default: `53`

> `protocol`: `"tcp"` | `"udp"` _(Optional)_

The type of acceptable network protocol, `"tcp"` or `"udp"`. DoT is not supported on listener sockets; keep TLS encryption on the resolver side.

Default: `"udp"`

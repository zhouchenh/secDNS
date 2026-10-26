# Facade admin edge

secDNS can retain its exact browser origin, owner, MFA, cookies, CSRF and optional
passkey identity when an HTTPS Facade route fronts the existing HTTPS nginx portal.
The source change does not enable a route or change a database. Forwarded client
identity remains disabled unless the admin listener names exact trusted socket
sources:

```json
{
  "type": "httpAdminServer",
  "authStore": "management",
  "publicOrigin": "https://secdns.aircloud.pro",
  "config": {
    "listen": "127.0.0.1",
    "port": 18056,
    "trustedProxySources": ["127.0.0.1"]
  }
}
```

`trustedProxySources` accepts one to eight exact IP addresses, never CIDRs. Omit
it for the prior socket-source behavior. When the direct peer is not listed,
secDNS ignores all forwarding headers. When it is listed, browser authentication
requires exactly one `X-Forwarded-For` and `X-Real-IP` containing the same valid
address, `X-Forwarded-Proto: https`, `X-Forwarded-Host` equal to the configured
public-origin authority, `X-Forwarded-Port: 443`, and an HTTP Host equal to that
authority. Missing, duplicate, chained or inconsistent metadata fails closed.
IPv4-mapped IPv6 is normalized before comparison and rate-limit use.

The JSON fragment illustrates the listener interface. It is not sufficient
authorization to trust the current loopback hop: any local process that can
reach port 18056 can originate a TCP connection from loopback.

The running topology has two proxy hops. Facade connects with verified TLS to
`100.91.1.82:443` using server name `secdns.aircloud.pro`; nginx then connects to
the loopback admin listener. secDNS therefore trusts only the loopback nginx
socket. nginx must reconstruct the complete tuple after accepting real-IP input
only from the exact Facade backend address. The candidate in
`examples/secdns-facade-nginx.conf` shows the required boundary. Direct nginx
clients cannot select their identity because nginx ignores their forwarded
headers and overwrites the tuple from its validated remote address.

Before `127.0.0.1` can be placed in `trustedProxySources`, activation must also
close direct local access to port 18056 with an independently reviewed OS or
authenticated-intermediary control that admits only nginx. An alternative
topology may expose the exact Facade socket source directly to secDNS. Without
one of those controls, leave trusted-proxy mode disabled; nginx header rewriting
alone does not authenticate the loopback peer.

Activation still requires separate review of the Facade exact-host route,
allowed client networks, edge certificate, nginx configuration and rollback.
Do not add `trustedProxySources` alone to the current nginx configuration: the
current deployed template supplies only part of the required tuple and would
make browser authentication fail closed. DNS listeners and DNS64 are unrelated.


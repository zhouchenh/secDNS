# Listeners

secDNS supports the following listeners. Use the version annotations to ensure your release supports the desired feature.

* [dnsServer](listeners/dns_server.md) - Plain DNS (UDP/TCP) listener that terminates queries on a socket. It does **not** speak DoT/DoH.
* [httpAPIServer](listeners/http_api_server.md) - (secDNS v1.2.1+) HTTP/JSON endpoint that accepts GET or POST (form or JSON) requests and returns DNS responses encoded as JSON.
* [httpAdminServer](listeners/http_admin_server.md) - (secDNS v1.5.0+) Bearer-authenticated HTTP admin API (loopback by default) that populates the record store the `authoritative` resolver answers from.

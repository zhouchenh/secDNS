# Listeners

secDNS supports the following listeners. Use the version annotations to ensure your release supports the desired feature.

* [dnsServer](listeners/dns_server.md) – Traditional DNS listener that accepts UDP or TCP queries on a socket. This listener intentionally does **not** implement DNS-over-TLS (DoT); pair it with upstream DoT resolvers if you require encrypted transport.
* [httpAPIServer](listeners/http_api_server.md) – (secDNS v1.2.1+) HTTP/JSON endpoint that accepts GET or POST (form or JSON) requests and returns DNS responses encoded as JSON.

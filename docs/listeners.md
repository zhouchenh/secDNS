# Listeners

secDNS supports the following listeners. Use the version annotations to ensure your release supports the desired feature.

* [dnsServer](listeners/dns_server.md) – Plain DNS (UDP/TCP) listener that terminates queries on a socket. It does **not** speak DoT/DoH; if you need encryption on the downstream hop, front it with a DoT/DoH terminator (e.g., stunnel/NGINX/Ingress). You can still use DoT/DoH _upstream_ to encrypt the resolver’s outbound queries to public resolvers.
* [httpAPIServer](listeners/http_api_server.md) – (secDNS v1.2.1+) HTTP/JSON endpoint that accepts GET or POST (form or JSON) requests and returns DNS responses encoded as JSON.

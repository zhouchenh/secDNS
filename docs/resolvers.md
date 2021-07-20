# Resolvers

secDNS supports the following resolvers.

* [address](resolvers/address.md) - Reply queries with an IPv4 or IPv6 address.
* [alias](resolvers/alias.md) - Reply queries with a CNAME.
* [concurrentNameServerList](resolvers/concurrent_name_server_list.md) - Forward queries to specific resolvers
  concurrently.
* [dns64](resolvers/dns64.md) - (secDNS v1.1.0+) Synthesize AAAA resource records from A resource records.
* [doh](resolvers/doh.md) - Forward queries to an upstream DNS server, using DNS over HTTPS.
* [nameServer](resolvers/name_server.md) - Forward queries to an upstream DNS server.
* [noAnswer](resolvers/no_answer.md) - Reply queries without any DNS record.
* [notExist](resolvers/not_exist.md) - Reply queries with an NXDOMAIN error.
* [sequence](resolvers/sequence.md) - Forward queries to specific resolvers sequentially.

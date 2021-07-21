# secDNS

secDNS is a DNS resolver to help you bypass DNS spoofing (aka DNS cache poisoning) from your local ISP.

## Features

* Support DoT (DNS over TLS), DoH (DNS over HTTPS), and regular DNS (insecurely over TCP / UDP) upstream resolvers.
* Support query over SOCKS5 proxy.
* Support DNS64.
* Multiple listeners and upstream resolvers can be configured.
* Queries to a group of upstream resolvers can be either queued (failover, trying the next resolver if one fails) or
  concurrent (accepting results from the fastest resolver).
* Support name-based custom rules, enabling the possibility to customize the DNS results.

## Configuration

See [docs/configuration.md](docs/configuration.md).

## Version History

See [docs/version_history.md](docs/version_history.md).

## License

[The GNU Affero General Public License v3.0 (GNU AGPLv3)](LICENSE)

## Credits

This project relies on the following third-party project:

* [miekg/dns](https://github.com/miekg/dns)

Documentation loosely ~~copied~~ referenced from:

* [v2ray/v2ray-core](https://github.com/v2ray/v2ray-core)

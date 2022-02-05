# Version History

### v1.1.5 - 2022.02.05

New Feature

* Add multiple addresses support for [address](resolvers/address.md) resolver.
* Support resource record filtering for A and AAAA by adding new resolvers [filterA](resolvers/filterA.md)
  and [filterAAAA](resolvers/filterAAAA.md).

Bug Fix

* Fix a bug in [address](resolvers/address.md) resolver which might cause error in type of answered resource records.

### v1.1.4 - 2021.07.22

New Feature

* Add SOCKS5 proxy support for [nameServer](resolvers/name_server.md) and [doh](resolvers/doh.md).

### v1.1.3 - 2021.07.20

New Feature

* Add an option in [doh](resolvers/doh.md) configuration to allow specifying a resolver for URL resolution.

Bug Fix

* Fix a bug in [doh](resolvers/doh.md) resolver which might cause infinite name resolution when domain names are used
  instead of IP addresses in URLs of DoH services.

### v1.1.2 - 2020.10.20

Bug Fix

* Fix a bug in [doh](resolvers/doh.md) resolver where queries don't fail when error occurs.

### v1.1.1 - 2020.10.19

Bug Fix

* Fix a bug in [nameServer](resolvers/name_server.md) resolver where UDP queries don't time out and fail when the server
  ignores the queries.

### v1.1.0 - 2020.03.26

New Feature

* Support DNS64 by adding a new [dns64](resolvers/dns64.md) resolver.

### v1.0.0 - 2020.03.07

Initial Release

# authoritative

_Available in secDNS v1.5.0 and later._

* Type: `authoritative`

The `authoritative` resolver answers from a process-local record store instead of
forwarding upstream. Names routed to it (via [rules](../rules.md)) are answered from the
store; unknown names return `NXDOMAIN`, a known name queried for a type it does not have
returns `NODATA` (NOERROR with an empty answer), and each negative answer carries a
synthesized `SOA` in the authority section for negative caching.

The store is populated out of band — typically by the [`httpAdminServer`](../listeners/http_admin_server.md)
admin API — and is **shared by name**, so an `authoritative` resolver and an admin
listener configured with the same `store` operate on one record set. This is the building
block for serving dynamic records such as ACME DNS-01 `_acme-challenge` TXT records without
running a second daemon.

Supported record types: `TXT`, `A`, `AAAA`, `CNAME`. A `CNAME` stored for a name is
returned for a query of any other type by default (the requester re-queries the target). Answers are
unsigned; DNSSEC signing, zone transfer (AXFR/IXFR), and dynamic DNS updates (RFC 2136) are
out of scope.

## ResolverConfigObject

```json
{
  "store": "acme",
  "negativeTTL": 60
}
```

> `store`: String _(Optional)_

Name of the shared record store to answer from. An empty value joins the `default` store.
Use the same value on the `httpAdminServer` listener that populates it.
The name may instead identify a durable `followerRecordStores` entry. In that mode
the resolver serves one pinned accepted generation and returns `SERVFAIL` until the
first generation is available; see [direct follower synchronization](../direct-follower-sync.md).

Default: `""` (the `default` store)

> `negativeTTL`: Number | String _(Optional)_

TTL (seconds) of the synthesized `SOA` and its `MINIMUM` field, which bounds how long
downstream resolvers negatively cache an `NXDOMAIN`/`NODATA` answer. Accepts a number or a
numeric string.

Default: `60`

> `completeCNAME`: Boolean _(Optional)_

Default: `false`. When enabled, A/AAAA queries complete CNAME chains only within the same
record store, preserving each record's TTL. Direct CNAME and other query types are unchanged.
Traversal is limited to 16 aliases and the available resolver depth. Cycles, exhausted
budgets and malformed or conflicting data return SERVFAIL without upstream fallback.
Missing targets or target families return the chain alone, without inventing negative
zone authority. See [the full behavior and concurrency limits](../configuration.md#optional-local-cname-completion).

## Notes

* The resolver does not track a zone apex: the synthesized `SOA` is owned by the queried
  name and uses placeholder `MNAME`/`RNAME` under the reserved `.invalid.` TLD (RFC 6761).
  Only the `MINIMUM`/TTL is operationally meaningful (negative-cache duration).
* With no admin listener and no records, every routed name returns `NXDOMAIN`.

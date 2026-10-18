# exactStoreOverlay

* Type: `exactStoreOverlay`

`exactStoreOverlay` combines an explicitly enrolled exact-record store with an
existing resolver graph. It answers an owner locally when the current immutable
store view contains any live `A`, `AAAA`, `CNAME`, or `TXT` record for that exact
name. When the original owner is absent, it invokes `fallback` once.

This resolver is intended for a changing exact-record snapshot whose set of owners
cannot be listed in static routing rules. It accepts only a `versionedRecordStores`
writer or a `followerRecordStores` replica. A missing, legacy, unready, faulted, or
closed store fails with `SERVFAIL`; it is never treated as an empty snapshot and no
legacy store is created implicitly.

```json
{
  "type": "exactStoreOverlay",
  "config": {
    "store": "owned-static",
    "completeCNAME": true,
    "negativeTTL": 60,
    "fallback": "ordinary-cache"
  }
}
```

> `store`: String _(Required)_

The nonempty, trimmed name of an explicitly configured writer-versioned or follower
store.

> `fallback`: Resolver _(Required)_

The resolver used once when the original question owner is absent from the pinned
store view. A fallback error or nil response becomes `SERVFAIL`.

> `completeCNAME`: Boolean _(Optional)_

Default: `false`. This has the same same-view CNAME behavior and limits as
[`authoritative`](authoritative.md). A local owner never falls through midway through
a chain or after local NODATA, malformed data, a cycle, or depth exhaustion.

> `negativeTTL`: Number | String _(Optional)_

Default: `60`. This is the synthesized SOA TTL and `MINIMUM` for local NODATA.

## Selection and cache placement

For a `sourcePolicyRole` listener, select an overlay separately for each policy root
and give that overlay the already selected policy graph as its fallback. Socket-peer
selection still happens before resolution. Put the overlay outside the fallback cache:
a newly published exact owner then bypasses a previously cached fallback answer on the
next query, while removal exposes that policy's existing cache again. Startup rejects a
cache wrapped around the overlay because it could retain answers across store revisions;
distinct source policies also cannot share one fallback cache instance.

The resolver performs no DNS64 synthesis and does not add a zone boundary. Expired-only
owners are absent at the view's captured time. One query pins one generation and expiry
instant for owner detection and every local CNAME hop. Snapshot transport, enrollment,
and authentication are configured separately; this resolver does not make a follower
authoritative or trusted by itself.

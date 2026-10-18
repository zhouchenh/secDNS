# Direct follower snapshot synchronization

Direct follower mode is an opt-in way to copy one exact-record snapshot from one
explicitly trusted publisher into a durable local follower store. It uses a full
authenticated HTTPS snapshot fetch at startup and bounded revision-event hints to
request later full snapshots. Events never contain authoritative record content.

This mode copies only exact `A`, `AAAA`, `CNAME`, and `TXT` records. It does not copy
listeners, resolver graphs, source policy, DNS64 policy, routing, credentials, or the
rest of the configuration. It is a controlled direct-publisher path; it does not
replace signed snapshot verification or the separate durable trust/mirror design.

## Authority configuration

The authority must use a `versionedRecordStores` binding. Add up to 64 read-only
credentials to that store's `httpAdminServer` listener:

```json
{
  "versionedRecordStores": {
    "published": {
      "backend": "sqlite",
      "sqlitePath": "/var/lib/secdns/published.db",
      "rulesetId": "static-records",
      "lineageId": "static-lineage"
    }
  },
  "listeners": [
    {
      "type": "httpAdminServer",
      "config": {
        "listen": "127.0.0.1",
        "port": 9053,
        "path": "/admin",
        "store": "published",
        "token": "replace-with-a-separate-admin-secret",
        "snapshotReaders": [
          {
            "nodeId": "replica-one",
            "token": "replace-with-at-least-32-random-bytes"
          }
        ]
      }
    }
  ]
}
```

Each `nodeId` and token must be unique. Reader tokens are 32 through 512 printable
ASCII bytes, may not contain whitespace, and may not equal the admin token.
They authorize only `GET {path}/snapshot` and `GET {path}/snapshot/events` for the
listener's one versioned store. They cannot mutate records, replace a snapshot,
preview an import, inspect source policy, or select another node/store. The server
derives the node identity from the configured credential.

The built-in HTTP listener does not terminate TLS. Put it behind a deliberately
configured, authenticated management HTTPS endpoint before using a reader token
across a network. The follower refuses plain HTTP.

## Follower configuration

Configure the durable follower store separately and point an `authoritative`
resolver at its name:

```json
{
  "followerRecordStores": {
    "replica": {
      "sqlitePath": "/var/lib/secdns/replica.db",
      "createIfMissing": false,
      "clusterId": "dns-cluster",
      "kind": "exact-records",
      "rulesetId": "static-records",
      "lineageId": "static-lineage",
      "authorityEpoch": "publisher-epoch-1",
      "nodeId": "replica-one",
      "authorityUrl": "https://publisher.example.invalid/admin",
      "token": "replace-with-at-least-32-random-bytes"
    }
  },
  "defaultResolver": {
    "type": "authoritative",
    "config": {"store": "replica"}
  }
}
```

The SQLite path must be an absolute clean file path and may not collide with any
legacy, writer-versioned, or other follower store. An existing file is always opened
strictly with the configured immutable enrollment tuple. A missing file is created
only when `createIfMissing` is explicitly true. The `-test` command validates this
configuration without touching the filesystem or network.

The example above treats the replica as the complete authority for every question sent
to it. To overlay a changing set of exact owners on an existing ordinary resolver graph,
use [`exactStoreOverlay`](resolvers/exact_store_overlay.md) with the follower store and
that graph as its fallback. Owner membership is then taken from each accepted generation;
it does not require regenerating static selection rules.

`authorityUrl` is one absolute HTTPS origin and fixed base path, with no user info,
query, fragment, redirect, proxy, discovery, or response-selected alternate origin.
Changing the URL, token, lineage, or authority epoch is a deliberate operator
configuration change followed by restart.

At runtime, an empty follower returns DNS `SERVFAIL` until its first full snapshot
is durably accepted. A successful generation is pinned for each DNS query, including
local CNAME completion. A later accepted generation becomes visible atomically. An
authority outage, malformed response, rollback, equivocation, authentication failure,
or event-stream failure leaves the last durably accepted generation serving. On
restart the local high-water mark remains available, but the new worker still performs
an unconditional full fetch before it may use an ETag.

The worker uses ordinary Go TLS verification, one request at a time, bounded timeouts,
bounded snapshot bodies, and bounded SSE lines/events/streams. Its in-process status
contains only fixed state/error categories and enrolled identifiers; it excludes the
token, source URL, records, raw errors, response bodies, and TLS peer details. This
worker adds no credential issuance, CA provisioning, automatic membership, writer
election, or deployment behavior. An existing admin listener can explicitly expose
an allowlisted [read-only local worker status page](local-follower-status.md).
This does not query remote node health or change synchronization behavior.

# Versioned authoritative records and batch API

Versioned stores are optional. Existing `recordStores`, authoritative resolvers, admin CRUD and the embedded editor keep their legacy behavior unless a store name is explicitly enrolled below.

```json
{
  "versionedRecordStores": {
    "pilot": {
      "backend": "sqlite",
      "sqlitePath": "/private/state/pilot.db",
      "rulesetId": "pilot",
      "lineageId": "deployment-lineage"
    }
  }
}
```

For volatile tests, use `backend: "memory"` and omit `sqlitePath`. Both identity fields remain required. Existing authoritative and admin components select this mode through `store: "pilot"`; there is no second component-level mode switch. An omitted store name means `default`, which may itself be explicitly enrolled. Unconfigured names retain legacy lazy memory stores.

Names and paths cannot overlap legacy stores or one another. Startup validates configuration without filesystem writes in `-test` mode, opens all requested stores before publishing any bindings, and starts listeners only afterward. New SQLite files begin with an empty revision 1; existing schema 2 files must match their enrollment identity. Schema 1 files are refused: runtime startup never performs migration. There are no JSON seeds, automatic enrollment, hot reload or concurrent process writers. Closed versioned names remain reserved for the process lifetime, so shutdown cannot silently replace them with empty legacy stores.

Each authoritative invocation pins one immutable generation and one expiry instant, including every same-store CNAME hop. TTL zero and TXT chunk order are retained. Expired records remain in canonical snapshots but are filtered from answers without a new revision. This is not a multi-store transaction or a guarantee across an entire resolver graph. Existing negative SOA placeholders and CNAME completion limitations still apply. Closed stores return local SERVFAIL, not an error that permits default upstream fallback.

## Authenticated snapshot API

The existing admin bearer authentication protects `GET` and `POST <base>/snapshot`. Keep admin traffic on a protected management path; this change adds no transport encryption. GET returns the complete canonical envelope, including retained expired entries and the decimal-string revision.

POST replaces the entire exact record set atomically:

```json
{
  "expected": {"ruleset_id": "pilot", "lineage_id": "deployment-lineage", "revision": "1"},
  "operation_id": "operator-edit-001",
  "records": [
    {"name": "host.invalid.", "type": "A", "values": ["192.0.2.1"], "ttl_seconds": 300}
  ]
}
```

The body is limited to 4 MiB. Field spelling is exact; unknown or duplicate fields, nulls and malformed Unicode are rejected. Existing exact snapshot record limits and validation apply. Absolute `expires_at` values use RFC3339Nano, including past timestamps for lossless snapshot transfer; relative expiry is not accepted. TTL zero is preserved. The server assigns the next revision.

Success returns `operation_id`, decimal-string `revision`, `content_sha256` and `committed_at`. Durable commit precedes success and publication. Retrying an identical operation returns its original receipt, even after another edit; reusing its ID for different content fails. Clients must retain the exact expected revision, operation ID and payload when retrying an uncertain result. A digest is not authentication or a signature.

Errors have a fixed `error` code: malformed input is 400, oversized body 413; identity, revision and operation conflicts are 409 (`identity_conflict`, `revision_conflict`, `operation_conflict`). Receipt capacity and revision exhaustion are also 409 and require operator intervention. Storage or closed-state failure is 503 `snapshot_unavailable`. Authentication remains 401/403. Failed writes publish no new generation.

Versioned mode refuses legacy per-record CRUD with 409 `versioned_batch_required`, and does not serve the single-record editor or its assets. Legacy stores do not expose snapshot routes. A future batch editor must handle conflicts explicitly; no GUI or automatic cluster synchronization is included here. This surface represents exact records only, not ordered RouterOS regex, forwarding or subdomain policy.

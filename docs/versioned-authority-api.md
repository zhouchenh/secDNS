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

Versioned mode refuses legacy per-record CRUD with 409 `versioned_batch_required`. Legacy stores do not expose snapshot routes. With the existing `ui: true` admin option, versioned stores serve a separate snapshot editor; legacy stores keep their single-record editor. The default remains off. Automatic cluster synchronization is not included. This surface represents exact records only, not ordered RouterOS regex, forwarding or subdomain policy.


## Optional snapshot editor

Enable `ui: true` on an admin listener bound to a configured versioned store, then open `<base>/ui/`. Its static shell contains no token or records; all snapshot requests require the entered bearer token. The editor uses only the same origin, embedded assets, and the existing restrictive headers. Tokens stay in page memory and are cleared on disconnect or page hide. No cookies or browser storage are used. Protect the administration transport; this editor adds no encryption.

Create, edit and delete actions stage local changes. Filtering never alters the complete draft. Stage unfinished record fields, review added/changed/removed counts, then confirm a complete snapshot replacement. TTL zero, ordered TXT chunks (including duplicate and empty strings), retained expired records and exact nanosecond expiration text are preserved. Expiration is absolute only; permanent entries omit `expires_at`. Server validation remains authoritative. Revisions are decimal strings, including values beyond JavaScript's safe integer range.

The base snapshot, local draft, latest comparison snapshot, frozen pending request and operation receipt are separate. A refresh cannot silently replace a dirty draft or unfinished form. A successful receipt acknowledges one operation, not the latest state: the editor requires a separate canonical GET before preparing another replacement. A replay can return an older receipt while that GET shows a newer revision.

The record comparison lists local changes and observed server changes separately against the base, with each record's exact values, TTL and expiration. Only changed rows are shown by default; enable **Show unchanged rows** to inspect all retained records. Rows are sorted for display only, and the comparison excludes unstaged form fields. An unavailable server snapshot is not treated as an empty record set. The observed revision and freshness warning describe the last accepted snapshot, not a promise that the server is still at that revision. Raw snapshot JSON remains available below the readable comparison. Viewing or filtering the comparison never adopts records, changes the draft, or submits a request.

If a response is lost or malformed, the outcome is uncertain. The explicit retry action sends the identical serialized request and operation ID; it does not recompute expiration or mint a new operation. Disconnect aborts browser requests but cannot prove the server cancelled them. Reauthentication preserves pending recovery without automatically sending anything. Conflicts preserve the draft and require comparison, explicit discard/reload and manual re-entry. There is no automatic merge, force save, or shortcut that replaces only the expected revision.

Drafts and pending recovery exist only in this page's memory. Closing or reloading loses them; the editor warns before navigation when local work is pending. Clearing local work requires separate confirmation and cannot undo a server operation. Do not mistake the local draft or receipt for a durable backup. Memory-backed stores still lose data on server restart; SQLite durability follows the configured backend.

The editor's RouterOS review link opens a separate `noopener` tab and creates a random memory-only same-origin handoff channel. A complete strict exact conversion can be transferred only by an explicit button in that tab. The editor independently checks the random channel, expected source and target paths, 30-second message age, 4 MiB payload bound, exact-record shape and matching ruleset ID. It accepts records only while connected to a fresh snapshot with a clean draft, no unfinished form and no pending operation. Refused or unsupported sources never expose the action; dirty or mismatched editors preserve their current work and reject the transfer.

An accepted transfer only replaces the local browser draft and displays the strict profile plus source/content hashes. It never copies a bearer token, posts to the snapshot API, changes a store or bypasses the existing comparison and revision-aware confirmation. Any later apply still freezes the complete draft against the editor's loaded base and uses the normal explicit replacement dialog. The random fragment capability is removed from the child address after startup; no cookie or browser storage is used.

Validation uses `node scripts/test-versioned-editor-state.cjs` and `scripts/test-versioned-editor-browser.cjs`; the RouterOS preview browser suite exercises the cross-tab candidate handoff. The browser suites require an existing Playwright installation and a dedicated synthetic localhost memory server with the snapshot editor enabled. They may replace that test store's contents; never point them at an operational admin instance. `PLAYWRIGHT_MODULE`, `EDITOR_TEST_URL`, `EDITOR_SCREENSHOT` and `EDITOR_MOBILE_SCREENSHOT` optionally select installed tooling, the localhost test endpoint and output images. No dependency download is required.

# Local follower status

The optional read-only status page observes follower workers inside one running
secDNS process. It is not a fleet inventory, remote health monitor, or convergence
proof. No status request contacts an authority or changes a snapshot.

Add an explicit allowlist to an existing admin listener (alongside `type` and
`config`, not inside `config`):

```json
{
  "type": "httpAdminServer",
  "followerStatusStores": ["replica"],
  "config": {
    "listen": "127.0.0.1", "port": 9053, "path": "/admin",
    "store": "management", "token": "replace-with-a-private-admin-token", "ui": true
  }
}
```

Each of 1 through 64 unique names must identify a configured local
`followerRecordStores` entry. Unknown, duplicate, empty or malformed lists refuse
startup, including syntax-only `-test`. Omission exposes no status endpoint. The
admin listener still cannot bind a follower as its editable record store; its
existing management store and mutation rules are unchanged. Configuring status
does not create or enable any follower or trust relationship.

`GET /admin/followers` accepts the listener's existing legacy admin credential or
an authenticated human/scoped agent with `records:read`. Snapshot-reader tokens
are deliberately insufficient. Existing cookie origin checks and mixed-credential
refusal apply. The response is `no-store`; it contains only the allowlisted store
names, enrolled identifiers, local revision/content digest, fixed worker/error
categories, availability and timestamps. It excludes source URLs, credentials,
records, raw errors and peer details. A missing runtime binding returns 503 rather
than an empty successful observation. Revision is a decimal string to preserve
the complete uint64 range in browsers.

The embedded record workspace links to `/admin/ui/followers/`, a separate page so
inspection cannot alter a draft or pending operation. Connect or explicitly select
Refresh status to take a sample; there is no background polling. Authentication
loss clears the sample and in-flight responses cannot repopulate it. A failed
refresh retains the previous sample with an explicit unknown-current-state notice.

## Meaning of fields

- `observed_at` is this request's local sampling time. Worker rows are individually
  sampled; this is not an atomic multi-store generation.
- `accepted`/`revision`/digest describe the worker's last durably accepted generation,
  including one recovered from disk. They do not assert that the store is still
  available; `store_state` independently checks in-memory view availability.
- `last_accepted_at` is the time a full 200 response completed durable acceptance
  in this process, including an idempotent repeat. It is null for a generation only
  recovered from disk. It is not the revision's original creation time.
- `last_contact_at` advances after a durably accepted 200, a valid no-change 304
  following acceptance, or a validated 200 event-stream header. It does not advance
  on an authentication/transport/protocol failure or prove a later event valid.
  Event comments/heartbeat bytes do not change it. Existing finite streams trigger
  later fetches; this feature adds no connection or polling loop.
- Contact is `recent` up to 90 seconds, `stale` afterwards, or `unknown` when absent
  or in the future relative to local time. This label never means a remote host is
  offline. `connection` is the last worker state, not an active reachability probe.
- `store_state` is `available`, `not_ready` (no accepted snapshot yet), or
  `unavailable` (closed/faulted store). Contact errors can coexist with available
  retained data. Process-local times reset on restart and rely on the local clock.

Validation uses synthetic local worker/API tests and
`node scripts/test-follower-status-browser.cjs` with an installed Playwright module
via `PLAYWRIGHT_MODULE`. The browser fixture uses only a temporary loopback server
and synthetic identifiers. No deployment or multi-node control is implied.

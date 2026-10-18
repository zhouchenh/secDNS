# httpAdminServer

_Available in secDNS v1.5.0 and later._

* Type: `httpAdminServer`

The `httpAdminServer` listener exposes a small bearer-authenticated HTTP API that
populates the record store the [`authoritative`](../resolvers/authoritative.md) resolver
answers from. It is intended to bind a **loopback or management address** and must never be
exposed to the public internet.

It **fails closed**: without a configured `token` it refuses to serve, so the mutating API
can never run unauthenticated. The listener and the authoritative resolver join the same
store by `store` name, so a record written here is immediately answered by the resolver.

## ListenerConfigObject

```json
{
  "listen": "127.0.0.1",
  "port": 9053,
  "path": "/admin",
  "store": "acme",
  "token": "a-long-random-secret",
  "snapshotReaders": []
}
```

> `listen`: String _(Optional)_

The IP address to bind. Defaults to loopback; set a routable address only deliberately,
behind appropriate network controls.

Default: `127.0.0.1`

> `port`: Number | String _(Optional)_

The port to listen on (number or numeric string).

Default: `9053`

> `path`: String _(Optional)_

Base path for the admin endpoints. A leading slash is added if omitted; a trailing slash is
trimmed.

Default: `/admin`

> `store`: String _(Optional)_

Name of the shared record store to mutate. Must match the `authoritative` resolver's
`store`. An empty value joins the `default` store.

Default: `""` (the `default` store)

> `token`: String _(Required)_

Bearer token required on every API request. The listener refuses to serve if this is empty.
Use a long, random value and transport it over loopback or TLS-terminating infrastructure.

> `sourcePolicyExplain`: Boolean _(Optional)_

Expose the authenticated, read-only source-policy diagnostic endpoint described below.
The default is `false`. Enabling it requires a valid top-level `sourcePolicy`; startup
fails if the policy is absent or invalid. It does not enable source selection on a DNS
listener by itself.

Default: `false`

> `snapshotReaders`: Array _(Optional)_

Up to 64 per-node read-only credentials for the snapshot and revision-event GET
routes of a writer-versioned store. Omission preserves the existing admin-only
behavior. See [direct follower snapshot synchronization](../direct-follower-sync.md)
for the strict identity/token rules and transport boundary.

Default: `[]`

## Authentication

Every API endpoint requires `Authorization: Bearer <token>`. The token is compared in constant
time. A missing or malformed header returns **401**; a present but incorrect token returns
**403**. A configured snapshot-reader token is accepted only on `GET {path}/snapshot`
and `GET {path}/snapshot/events`; all other endpoints still require the admin token.

## Endpoints

> `POST {path}/source-policy/explain`

Available only when `sourcePolicyExplain` is true. Evaluate the compiled source selector
for a synthetic client address, listener role, and explicit RFC3339Nano instant:

```json
{
  "listener_role": "normal",
  "client_ip": "192.0.2.10",
  "at": "2026-10-18T00:00:00Z"
}
```

The request is limited to 4 KiB and is strict: all three fields are required; unknown,
duplicate, null, malformed, or trailing values are rejected. Zone-qualified addresses
and instants outside Go's normalized years 1 through 9999 are invalid. IPv4-mapped
addresses are reported as IPv4.

The response identifies the immutable selector and its deterministic decision:

```json
{
  "schema": "secdns.source-policy-explain.v1",
  "evaluation": "diagnostic_preview",
  "policy_fingerprint": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "listener_role": "normal",
  "client_ip": "192.0.2.10",
  "evaluated_at": "2026-10-18T00:00:00Z",
  "resolver": "regional",
  "source_set": "regional-clients",
  "rule_index": 0,
  "reason": "matched_rule"
}
```

An unmatched valid address reports `reason` as `explicit_default`, omits `source_set`,
and uses `rule_index: -1`. The fingerprint is a content diagnostic, not an authority
signature. The supplied `at` is a hypothetical preview instant; this response is never
evidence of a runtime request or network reachability. The endpoint does not resolve a
name, call any selected resolver, inspect a cache, contact an upstream/router, mutate a
store, or reveal source-set members. Source selection does not depend on a DNS name or
record type, so they are deliberately absent from this request.

Errors are stable codes: invalid requests and unknown roles return **400**,
oversized requests return **413**, and an enabled but unbound selector returns **503**.
The existing bearer guard runs before the body is read. When the option is disabled the
route is absent.

> `POST {path}/records`

Set or replace the record for a `{name, type}` (idempotent).

```json
{
  "name": "_acme-challenge.example.com",
  "type": "TXT",
  "values": ["challenge-token"],
  "ttl_seconds": 60,
  "expires_in_seconds": 1800
}
```

* `type`: one of `TXT`, `A`, `AAAA`, `CNAME`.
* `values`: non-empty array. For `A`/`AAAA` each value must be a valid address of the
  matching family; for `CNAME` exactly one valid target is required; for `TXT` each value is a
  character-string of at most 255 bytes (an empty string is valid, null is not).
* `ttl_seconds`: DNS TTL served in answers (defaults to `60` when omitted/zero).
* `expires_in_seconds` _(optional)_: store lifetime — the record is auto-removed after this
  many seconds. Omit, use null, or use `0` for no expiry. Must be nonnegative and fit a Go duration.

* `expires_at` _(optional)_: absolute expiration as an RFC3339Nano string. Empty string or
  null means no expiry. A nonempty timestamp must be in the future, including when the
  store validates the mutation under its lock. The zero-time timestamp is not permanence.
  Do not send both expiry fields, even if one is null or zero. Imports must omit already
  expired records; do not turn them into permanent records.

Owner names are trimmed, lowercased and fully qualified. IP strings are trimmed and
canonicalized; CNAME targets are trimmed, lowercased and fully qualified. TXT values keep
their original contents. Literal whitespace/control characters inside DNS names are
invalid. Unknown request fields remain ignored, but duplicate recognized keys are rejected
case-insensitively, consistently with accepted field spellings.

Validation, future-expiry and CNAME-exclusivity checks are atomic with mutation for both
memory and SQLite stores. A live CNAME cannot coexist with other live types at its owner;
expired records do not block replacement. A failed request changes neither cached nor
durable state. Direct internal memory Set remains permissive for compatibility, but the
admin path always uses SetValidated. This is not compare-and-swap or multi-user conflict
resolution; valid updates to the same name/type remain last-writer-wins.

Returns `{"status": "ok"}` only after the mutation succeeds.

> `DELETE {path}/records/{name}/{type}`

Remove the record for `{name, type}`. Returns `{"deleted": true|false}` indicating whether
one was present.

> `GET {path}/records`

List the live (non-expired) records. Expiry is emitted in UTC RFC3339Nano so an unchanged record can be echoed back without extending its expiry or losing fractional seconds. Permanent records omit expires_at:

```json
{
  "records": [
    {"name": "_acme-challenge.example.com.", "type": "TXT", "values": ["challenge-token"], "ttl_seconds": 60, "expires_at": "2026-06-05T05:30:00Z"}
  ]
}
```

## Errors

Malformed/invalid records or expiry return **400**; a conflict with another live RRset at a CNAME owner returns **409**; storage or closed-store failures return generic **503**. Validation messages do not echo the submitted data. Authentication behavior is unchanged. Errors return an HTTP status and a JSON body:

```json
{"error": "unsupported record type (allowed: TXT, A, AAAA, CNAME)"}
```

## ACME DNS-01 walkthrough

1. Publish, in your real zone, a delegation for the challenge subzone to the host running
   secDNS, and a `CNAME` from `_acme-challenge.example.com` to a name under that subzone.
2. Route `*.acme-validation.example.com` (the subzone) to an `authoritative` resolver via a
   rule, sharing a store with this listener.
3. The ACME client requests a certificate; the CA returns a token `T`.
4. The client `POST`s the token: `{name: "_acme-challenge.acme-validation.example.com",
   type: "TXT", values: [T], ttl_seconds: 60, expires_in_seconds: 1800}`.
5. The CA resolves the challenge name, follows the `CNAME` to secDNS, and reads the `TXT`.
6. On success the client `DELETE`s the record.

## Optional records editor

Set `"ui": true` in this listener configuration to enable the embedded editor at
`{path}/ui/` (normally `/admin/ui/`). It is disabled by default. The HTML, JavaScript
and CSS are public static assets without tokens or records; all record requests still
require bearer authentication. The listener still refuses to start without a token.
No external assets, telemetry or frontend package installation are used.

Enter your admin token and select **Connect**. The page connects only to its own server;
it does not connect automatically. The token is kept in page memory, sent only in the
Authorization header, and cleared on Disconnect or page exit. Browser extensions and
password managers remain outside the editor's control. Use a trusted browser over
loopback or an appropriately protected HTTPS management connection.

The editor supports local filtering, creating, editing and confirmed deletion. Owner
and type are fixed during an edit; renaming requires a separate create and delete.
Each value has its own field, including an empty TXT string. TTL is in seconds; zero
uses the API default of 60 seconds. Expiration is separate from DNS TTL. **Keep existing
expiration** sends the original timestamp unchanged, including nanoseconds. Choose
**Permanent** explicitly to remove expiration, or set a new RFC3339 timestamp or relative
number of seconds. Expired timestamps are rejected and drafts remain editable.

Validation, conflict, authentication and storage errors are displayed without discarding
the draft. A successful write followed by a failed refresh is reported separately;
refresh before another mutation. If a connection fails after sending a mutation, inspect
the refreshed list before retrying because the server may have completed it.

This editor is intended for one operator at a time. There is no revision check or
compare-and-swap protection: another writer can replace a record while it is being edited.
**Saved** means the API accepted the write; restart persistence depends on the configured
record store, not the editor. It does not provide import, zone management or deployment.

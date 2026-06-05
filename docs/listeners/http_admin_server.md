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
  "token": "a-long-random-secret"
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

Bearer token required on every request. The listener refuses to serve if this is empty.
Use a long, random value and transport it over loopback or TLS-terminating infrastructure.

## Authentication

Every endpoint requires `Authorization: Bearer <token>`. The token is compared in constant
time. A missing or malformed header returns **401**; a present but incorrect token returns
**403**.

## Endpoints

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
  matching family; for `CNAME` the first value is the target; for `TXT` each value is a
  character-string.
* `ttl_seconds`: DNS TTL served in answers (defaults to `60` when omitted/zero).
* `expires_in_seconds` _(optional)_: store lifetime — the record is auto-removed after this
  many seconds. Omit (or `0`) for no expiry. Must not be negative.

Returns `{"status": "ok"}`.

> `DELETE {path}/records/{name}/{type}`

Remove the record for `{name, type}`. Returns `{"deleted": true|false}` indicating whether
one was present.

> `GET {path}/records`

List the live (non-expired) records:

```json
{
  "records": [
    {"name": "_acme-challenge.example.com.", "type": "TXT", "values": ["challenge-token"], "ttl_seconds": 60, "expires_at": "2026-06-05T05:30:00Z"}
  ]
}
```

## Errors

Validation and auth failures return an HTTP status and a JSON body:

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

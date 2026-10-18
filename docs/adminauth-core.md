# Node-local administration authentication core

`internal/adminauth` is an unwired library. Existing listener configuration,
legacy bearer authentication, editors, record databases and running previews
are unchanged. This is a bounded first part of the human/agent authentication
contract, not a working human login or a new GUI authentication flow.

## Local ownership and durable identity

Explicit `CreateKey`, `Create`, and `Open` operations use a separate private key
and SQLite database. Create never adopts an existing empty file; Open never
creates a missing file. A failed creation is retained for diagnosis. Callers
must provide a private existing parent directory. Unix file/directory mode and
symlink checks are enforced; Windows ACL privacy remains an operator deployment
requirement. A trusted local operator must prevent concurrent path replacement.

The database binds immutable realm ID, node ID, display name and an HMAC key
check. A wrong key or identity refuses startup. It does not recover a lost key,
silently rotate identity, or migrate an unknown schema. Schema 1 currently has
four exact tables: realm, credentials, bootstrap and audit. The realm's human
setup state is always `pending`: no password, TOTP, passkey, recovery code or
human session is accepted by this slice. Those need a reviewed additive schema
migration and real authentication protocol, not a caller-supplied success flag.

Open checks SQLite application/version IDs, exact table definitions and object
set, integrity, bounded counts and byte/type/semantic constraints before
publishing a handle. DELETE journaling, FULL synchronization and an exclusive
connection lock are required. Existing WAL databases are refused without mode
conversion. Transactions serialize in one process; another owner cannot open
the same database. A transaction commit error faults the handle until close and
strict reopen, even if the commit may have reached disk. It returns no credential
on that path. Do not blindly retry ambiguous issuance with a new identity.

## Agent credentials and bootstrap authority

Each credential has a random 128-bit public ID and 256-bit secret. Only an HMAC
digest under the separate local key is stored. IDs select rows; comparison is
constant-time. Credentials bind exactly one node-local realm and node, immutable
scopes, label/purpose, creation/expiry, last-use and revocation timestamps.
The seven supported scopes are `ui:view`, `records:read`, `records:write`,
`snapshot:events`, `routeros:preview`, `source-policy:explain`, and `audit:read`.
No auth-management or credential-issuance scope exists.

The current issuance entry is **local operator bootstrap only**:

1. `CreateBootstrap` fixes the allowed scope set and optional maximum credential
   expiry. It returns a ten-minute random grant once and refuses to replace an
   outstanding grant. `CancelBootstrapLocal` explicitly cancels a lost/expired
   grant before creating another.
2. `BootstrapIssueAgent` validates the grant, subset scopes and expiry cap, then
   inserts a credential, consumes the grant and appends audit in one transaction.
   It returns the credential once after commit. Concurrent redemption has exactly
   one winner. Failed validation does not consume the grant.

This combined operation deliberately exports no issuer capability that callers
can forge, serialize, or reuse. Neither a zero-value Actor nor an authenticated
agent can issue another credential. The local methods are privileged embedding
primitives, **not HTTP handlers**. Never expose CreateBootstrap, RevokeLocal or
AuditLocal to a request merely because it carries an Actor, role string, or
`reauthenticated=true`. Future human issuance must mint authority only after
verified recent MFA/passkey authentication and enforce the issuance envelope.
The requested scopes may equal the allowed envelope but may never exceed it.

Configured legacy/admin/reader token values can be supplied transiently at
Create/Open solely for keyed collision rejection. They are neither persisted nor
accepted here. Future integration must supply the complete listener collision
inventory; this package cannot discover configuration it has not received.

Verify and revoke linearize under the store lock and transaction. A previously
returned Actor describes the request authenticated at that instant; it is not a
session or a promise that a later request remains authorized. Reauthenticate
each new request. Returned scope slices are owned copies. Expiry is inclusive
at its Unix-second boundary, and verification before credential creation fails.
Callers supply a trusted wall clock; this is not a monotonic anti-rollback clock.

## Bounds and audit

At most 128 credentials, including revoked rows, are retained. There is no
automatic eviction or reset. Capacity exhaustion refuses new issuance while
existing verification/revocation continues; operational adoption requires an
explicit reviewed archival/migration policy. The latest 2,048 audit entries are
retained. Audit contains fixed action names, timestamps, sequence and opaque
credential IDs, never token material, operator labels, passwords or DNS data.
Bootstrap creation/cancellation, issuance and revocation commit with audit;
audit failure rolls back the action. Public errors are fixed categories.

The package does not implement user/password guessing limits, Argon2, TOTP,
passkeys, encrypted authenticator enrollment, browser sessions, cookies, CSRF,
HTTPS-origin checks, CLI bootstrap wiring or HTTP authorization adapters. Those
are required before claiming human login or agent GUI readiness. No auth state
is replicated with DNS snapshots. Database/key backup restoration can resurrect
old credentials and revocations; no rollback-resistant external authority is
claimed.

Tests cover exact-key/identity/open ownership, unknown schema and corrupt rows,
scope widening, expiry, concurrent one-use redemption, durable revoke/reopen,
caller mutation, real audit-write rollback, simulated lost commit acknowledgement
and fail-closed handle behavior. All tests use synthetic credentials and local
temporary databases, with no candidate or production access.

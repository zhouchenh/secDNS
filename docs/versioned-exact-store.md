# Versioned exact-record storage substrate

This internal opt-in store provides atomic generations for the exact snapshot
format described in [exact record snapshots](exact-record-snapshots.md). It is
activated only by an explicit `versionedRecordStores` binding; legacy `Store`, its
API, and its database schema remain the default. There is no automatic network
synchronization, authority election, or production migration in this change.

## Identity, reads and replacement

`NewVersionedMemory` and `OpenVersionedSQLite` require explicit ruleset and lineage
IDs. A new empty store starts at revision 1. Reopening requires the same identity;
a different lineage cannot silently enroll over existing state.

`Acquire` returns a view of one immutable snapshot and captures one expiry time.
All lookups on that view use the captured time. Accessors copy records and values.
A held view survives later replacements and `Close`. The atomic pointer load is
its linearization point: readers do not wait for writer disk I/O, and calls after
`Close` returns fail. This API is a foundation for later resolver integration;
existing authoritative queries do not yet acquire these views.

`Replace` takes expected identity/revision, an operation ID, and a complete exact
record list. Operation IDs are 1–128 ASCII letters, digits, dots, underscores or
hyphens. Input is copied, validated and canonicalized by the existing snapshot
compiler. Revisions are assigned by the store, never the caller. Revision zero
is invalid, uint64 overflow fails, and byte-identical replacement still advances
the revision unless it is a retry of an acknowledged operation.

The request digest binds replacement kind, identity, expected revision and
canonical content digest. Under the writer lock, receipt replay precedes CAS:
the same ID and request returns its original result, even after newer revisions;
the same ID with different input conflicts. A stale new operation conflicts.
Digests detect content changes; they are not authentication or signatures.

`ReplaceWithOperatorSuppliedProvenance` additionally binds the fixed
`secdns.routeros-exact-explicit.v1` profile, an operator-supplied source SHA-256,
and the server-checked canonical content SHA-256. It uses a separate request-digest
domain. The source hash and profile are assertions, not proof that bytes came from
RouterOS or that a particular compiler produced them. Legacy `Replace` keeps its
original digest preimage exactly and clears provenance on the new generation.
Snapshot and optional provenance publish through one immutable atomic generation.

SQLite updates the snapshot and inserts the receipt in one transaction, then
publishes the new immutable pointer only after commit. Failure leaves both
memory and durable state unchanged. `Close` waits for an in-flight writer before
closing the database; no writer publishes after it returns. Memory mode mirrors
these operations only within its process and offers no restart durability.

## Schema and ownership

SQLite uses application ID 1396985427 and schema version 3, with exactly two
non-internal tables:

```sql
CREATE TABLE snapshot_state (id INTEGER PRIMARY KEY CHECK(id=1), envelope BLOB NOT NULL, operator_provenance BLOB);
CREATE TABLE operation_receipts (operation_id TEXT PRIMARY KEY, request_sha256 TEXT NOT NULL, committed_revision TEXT NOT NULL, content_sha256 TEXT NOT NULL, committed_at TEXT NOT NULL, operator_provenance BLOB);
```

The single envelope is the source of truth; there is no separately editable row
cache. Startup checks exact schema SQL, integrity, one canonical envelope,
identity and digest. Revisions are canonical decimal TEXT to preserve uint64
precision. Receipts must be valid, contiguous and unique from revision 2 through
the current revision, and the latest digest must match the envelope. Size guards
use byte length, including embedded NUL tails, before loading payloads. Unexpected
tables, triggers, schema versions, storage types or inconsistent history fail.
Provenance is NULL when absent or a bounded canonical JSON BLOB when present. Its
content hash must match its snapshot or receipt, and the current snapshot tuple must
match the latest receipt. Noncanonical, partial, mismatched or text-typed values fail
strict open.

The first ledger is capped at 10,000 receipts, without eviction. At capacity,
matching retries still work but new operations fail with `ErrReceiptCapacity`.
This is an explicit operational limit, not indefinite idempotency. A later
maintenance contract is required before sustained large-scale use. Expiry does
not prune canonical entries, create revisions, or free receipt capacity; an
explicit replacement can remove retained expired records.

The store reuses the legacy private-file checks and pure-Go modernc connection
settings: one connection, exclusive ownership, FULL synchronous commits and a
finite busy timeout. Unix parent/file permissions must be private. Windows ACLs
remain the operator's responsibility. Busy timeout does not bound every possible
filesystem stall. The design supports one local authority process, not shared
SQLite writers, network filesystems, copied live database files or WAL replication.
Local commit success does not imply any follower has received the generation.

## Explicit schema conversion

Only `OpenVersionedSQLite` with `AllowSchema1Migration:true` converts schema 1.
The default rejects it with `ErrMigrationRequired`. The conversion reads every
original row before expiry filtering and compiles a whole revision-1 snapshot.
It preserves TTL zero/max values, absolute nanosecond expiry, and ordered empty
or repeated TXT chunks. Allowed canonical normalization follows the snapshot
format. Incompatible duplicate addresses, escaped/Unicode names, malformed data,
or retained CNAME conflicts cause refusal; no records are silently dropped,
merged or repaired.

Creating schema 3, storing the snapshot, dropping schema 1 and changing the
version happen in the same transaction. Errors or failed commits preserve the
original schema and data. Old legacy binaries refuse schema 3. Operational
rollback therefore requires a separately prepared pre-migration backup; this
package provides no downgrade or automatic restore. No real database is migrated
by merely building or merging this source change.

A valid schema-2 database opens in compatibility mode by default. Its legacy
replacements and receipt digests remain byte-compatible; a provenance-bearing
replacement is refused before mutation. `AllowSchema2Migration:true` adds the two
nullable columns and changes the version in one transaction after fully validating
the old state. Existing envelopes, receipts and request digests are not rewritten.
Runtime configuration supplies neither migration permission, so existing instances
are never upgraded automatically.

## Verification and next boundary

Synthetic tests cover CAS contention and replay, immutable reads while commit is
blocked, Close ordering, exact expiry across restart, ledger capacity, malformed
and oversized storage, schema-2 compatibility, transactional migration/refusal,
provenance restart/replay and corruption, deferred-constraint commit
failure followed by a successful write, receipt insert failure, read-only writes,
exclusive ownership, and subprocess death before/after commit. Private test hooks
are inaccessible to configuration or API callers.

Resolvers acquire one view for an entire same-store CNAME lookup and versioned
mutations require CAS/idempotency metadata. This substrate still does not establish
cluster synchronization, source authenticity, or cross-store atomicity.

## Explicit offline schema4 opt-in for single-RRset mutations

New versioned SQLite stores still start at schema3. Existing schema2/3 opens and full-snapshot replacement behavior remain unchanged. Schema4 adds a nullable canonical single-RRset request to each operation receipt. Legacy replacement rows have NULL metadata and retain their exact previous digest verification. Targeted rows bind canonical request bytes, operation ID, enrollment and expected revision to the receipt's domain-separated digest. Malformed or inconsistent metadata fails startup; it is never treated as an opaque hash.

To enable targeted mutations, stop the writer, make a private backup of the complete offline database (and any existing SQLite journal), and build the helper locally:

```sh
go build -o secdns-recordstore ./cmd/secdns-recordstore
./secdns-recordstore -operation enable-rrset-mutations -database /private/state/pilot.db -ruleset-id pilot -lineage-id deployment-lineage
```

The helper requires an existing private schema3 record database and exact enrollment. It obtains the same exclusive SQLite lock as the writer, validates the old schema/content/receipts and performs the schema change in one transaction. It neither creates a missing database nor migrates authentication databases, schema1/2, or already migrated schema4. Interrupted or failed attempts must be inspected before retrying. Ordinary runtime startup never opts into schema4. Schema4 can be opened by this version without further migration; older binaries are not guaranteed to open it. To revert, stop the writer and restore the offline backup together with a compatible binary; do not attempt to downgrade schema in place. This command does not modify running services or generate credentials.

Retained canonical targeted-request metadata is capped at 16 MiB total in addition to the existing 10,000-receipt limit. New targeted writes that would exceed it return the existing receipt-capacity error without a commit; exact retries still return prior receipts. Startup checks the aggregate before materializing receipt metadata. Receipts are not silently pruned.
The schema4 metadata envelope also binds the canonical request to the resulting content digest through a separate domain-separated outcome checksum, including historical receipts. The idempotency request digest stays independent of current contents. These checks detect inconsistent stored data; they are not cryptographic authentication against an attacker able to rewrite the whole database.

# Versioned exact-record storage substrate

This internal opt-in store provides atomic generations for the exact snapshot
format described in [exact record snapshots](exact-record-snapshots.md). It is
not activated by configuration, DNS resolvers, the editor, or HTTP endpoints.
Legacy `Store`, its API, and its database schema remain the default. There is no
network synchronization, follower protocol, authority election, or automatic
production migration in this change.

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

SQLite updates the snapshot and inserts the receipt in one transaction, then
publishes the new immutable pointer only after commit. Failure leaves both
memory and durable state unchanged. `Close` waits for an in-flight writer before
closing the database; no writer publishes after it returns. Memory mode mirrors
these operations only within its process and offers no restart durability.

## Schema and ownership

SQLite uses application ID 1396985427 and schema version 2, with exactly two
non-internal tables:

```sql
CREATE TABLE snapshot_state (id INTEGER PRIMARY KEY CHECK(id=1), envelope BLOB NOT NULL);
CREATE TABLE operation_receipts (operation_id TEXT PRIMARY KEY, request_sha256 TEXT NOT NULL, committed_revision TEXT NOT NULL, content_sha256 TEXT NOT NULL, committed_at TEXT NOT NULL);
```

The single envelope is the source of truth; there is no separately editable row
cache. Startup checks exact schema SQL, integrity, one canonical envelope,
identity and digest. Revisions are canonical decimal TEXT to preserve uint64
precision. Receipts must be valid, contiguous and unique from revision 2 through
the current revision, and the latest digest must match the envelope. Size guards
use byte length, including embedded NUL tails, before loading payloads. Unexpected
tables, triggers, schema versions, storage types or inconsistent history fail.

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

## Explicit schema 1 conversion

Only `OpenVersionedSQLite` with `AllowSchema1Migration:true` converts schema 1.
The default rejects it with `ErrMigrationRequired`. The conversion reads every
original row before expiry filtering and compiles a whole revision-1 snapshot.
It preserves TTL zero/max values, absolute nanosecond expiry, and ordered empty
or repeated TXT chunks. Allowed canonical normalization follows the snapshot
format. Incompatible duplicate addresses, escaped/Unicode names, malformed data,
or retained CNAME conflicts cause refusal; no records are silently dropped,
merged or repaired.

Creating schema 2, storing the snapshot, dropping schema 1 and changing the
version happen in the same transaction. Errors or failed commits preserve the
original schema and data. Old legacy binaries refuse schema 2. Operational
rollback therefore requires a separately prepared pre-migration backup; this
package provides no downgrade or automatic restore. No real database is migrated
by merely building or merging this source change.

## Verification and next boundary

Synthetic tests cover CAS contention and replay, immutable reads while commit is
blocked, Close ordering, exact expiry across restart, ledger capacity, malformed
and oversized storage, transactional migration/refusal, deferred-constraint commit
failure followed by a successful write, receipt insert failure, read-only writes,
exclusive ownership, and subprocess death before/after commit. Private test hooks
are inaccessible to configuration or API callers.

The next integration must acquire one view for an entire same-store CNAME lookup
and must require CAS/idempotency metadata for versioned mutations. Until that
separate change is reviewed, do not claim query-pinned authority responses,
cluster synchronization or conflict-safe GUI editing from this substrate alone.

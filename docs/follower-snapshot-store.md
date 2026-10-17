# Enrolled follower snapshot storage

The internal `recordstore.FollowerStore` stores one exact-record snapshot received from an enrolled authority. It is a source-only building block: no configuration, registry binding, DNS listener, API, downloader, replication transport, editor, promotion or automatic migration uses it yet. Existing writer and legacy stores are unchanged.

## Enrollment and trust

`FollowerEnrollment` pins the case-sensitive cluster ID, kind, ruleset ID, lineage ID and authority epoch. Kind is `exact-records`; the other identifiers contain 1–128 ASCII letters, digits, periods, underscores or hyphens. Epochs are opaque identifiers, not counters. Constructors validate the tuple before filesystem access. Every `Accept` supplies the same tuple and an envelope whose ruleset and lineage also match.

These caller assertions are **not authentication**. A future trusted transport adapter must authenticate the publisher and bind authorized outer metadata to the envelope before calling the store. The content digest covers canonical schema, ruleset and records; it does not authenticate cluster, epoch, lineage or revision. There is no trust-on-first-message, signing, membership transition or re-enrollment API.

## Lifecycle and ordering

`NewFollowerMemory` and `CreateFollowerSQLite` start enrolled but uninitialized. `Acquire` returns `ErrFollowerNotReady` until an actual valid positive-revision snapshot is accepted. A valid empty snapshot differs from uninitialized state.

`Accept(asserted, envelope)` strictly parses the existing exact-record envelope and returns a value state plus one outcome:

| Input | Result |
| --- | --- |
| First matching valid positive revision | `initial` |
| Higher revision, including identical content | `advanced` |
| Same revision and digest | `unchanged`, without a write |
| Same revision with another digest | Equivocation error |
| Lower revision | Rollback error |
| Other enrollment or envelope namespace | Identity error |

Gaps and maximum uint64 revisions are supported. The follower never increments a revision, edits content, creates writer receipts or adopts another epoch. Every rejection returns a zero result. Malformed assertion/input and size limits are checked before identity/ordering; closed or faulted lifecycle takes priority over input checks.

Input and canonical output are limited to the existing 4 MiB envelope bound. Record/value limits and strict duplicate, Unicode, type, digest and revision validation come from `recordset.Parse`. Accepted input is copied and canonicalized; the caller must not mutate its buffer concurrently with the call. Expired records, TTL zero and ordered TXT chunks remain canonical content. Expiry filtering never changes the digest or watermark.

`Acquire` loads one immutable publication without waiting for disk and captures one clock instant. Its view exposes copied metadata, records, live records, lookups and canonical envelope bytes. Old views remain valid across updates, faults and Close. A load that precedes Close may return afterward; no new view is acquired after Close completes. Held views can retain older generations, so memory is bounded per generation rather than independently of callers retaining unlimited views. Zero/error views are not usable.

## SQLite ownership and recovery

`CreateFollowerSQLite` requires a missing final path and uses exclusive file creation. It never replaces an existing file. `OpenFollowerSQLite` requires an existing nonempty private regular file and uses SQLite must-exist read/write mode. Neither method converts legacy/writer databases. A failed creation may leave its own partial file for inspection; there is no automatic deletion or retry-as-new behavior.

Paths must satisfy existing clean absolute local-path rules. Final symlinks/nonregular files are refused; Unix parent and file permissions must be private. Windows operators remain responsible for restrictive ACLs. The parent directory and filesystem must be trusted against concurrent privileged replacement. One connection holds exclusive SQLite ownership with FULL synchronous mode and a finite lock busy timeout. The timeout does not bound physical I/O stalls or guarantee a wall-clock deadline.

The independent database uses application ID `0x53444631`, user version 1 and exactly two tables:

- `follower_enrollment`: one id=1 row with the immutable tuple and a `has_snapshot` flag.
- `follower_state`: no row while uninitialized, otherwise one id=1 row containing the canonical decimal revision, digest and canonical envelope BLOB.

Startup verifies integrity, exact table definitions and object count, storage types, byte-length bounds, row/flag consistency, enrollment and canonical parsed state before publishing a handle. Extra tables, indexes, triggers or views are rejected. There is no startup pruning, reset or schema migration. Invalid stored content returns a fixed schema error; errors do not expose paths, SQL or envelope data.

Acceptance is serialized with Close. A transaction checks the enrollment and updates the complete state and flag, then commits before the atomic in-memory publication. Reads continue using the prior immutable generation during disk work. A definite pre-commit failure with confirmed rollback leaves the prior view usable. A commit error or failed rollback confirmation marks the handle faulted: new Accept and Acquire calls fail until explicit Close and strict reopen. Already held views remain usable. The implementation does not infer that an ambiguous commit left disk unchanged or retry automatically.

Close is idempotent, waits for mutation and publishes terminal closed state before closing the database. A fixed storage error is retained if physical close fails. Process death after commit but before publication/return recovers the durable generation on reopen, without an operation receipt. Same-current replay is unchanged; an older retry is rollback.

This watermark survives ordinary restart and rejects stale incoming generations relative to the retained database. It cannot detect a coherent restoration of an entire older database, privileged tampering, disk loss or reinstall without an external trusted anchor. It is not globally rollback-proof or proof that the authority has no newer snapshot.

## Verification

Synthetic tests cover memory/SQLite bootstrap and revision ordering (including >2^53 and max uint64), same-content watermark persistence, strict input and identity rejection, canonical/copy/expiry fidelity, concurrent reads/accepts/Close, strict create/open and schema rejection, byte/type/NUL bounds, exclusive process ownership and constructor lock release. Actual SQL write and deferred-constraint commit failures exercise publication and fault behavior. Exact subprocess exit codes prove before-commit and after-commit crash boundaries for both first acceptance and a higher same-content generation. Existing writer/config/authority/admin suites remain separate regression coverage.

No test enrolls or contacts a production node. Transport authentication, signed manifests, external antirollback anchors, ingress resource policy and runtime integration are separate reviewed work.

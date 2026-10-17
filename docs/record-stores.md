# Optional SQLite record stores

The default remains process-local memory. To persist one or more named stores, add a top-level `recordStores` object:

```json
{
  "recordStores": {
    "internal": {"sqlitePath": "/var/lib/secdns/internal.db"}
  }
}
```

This is a fragment, not a complete resolver configuration. Set the existing authoritative resolver and admin listener `store` fields to the same name. Use `default` for components that omit their store name. Unconfigured stores remain in memory. Names must be nonempty and trimmed; database paths must be clean absolute local paths. URI paths, query parameters, duplicate names/options/paths and unknown store options are rejected. Store topology changes require a process restart; there is no hot reload.

## Startup and ownership

The main executable parses store options and loads the usual resolver configuration first. It then opens and rehydrates every configured database before starting any listener. An open, integrity, schema or row-validation failure aborts startup. Partial startup closes only the newly opened stores and publishes no registry entries. Existing stores cannot be replaced. Standalone callers of LoadConfig must explicitly use recordstore.Prepare before Listen; LoadConfig itself does not open databases.

A database uses a versioned application-owned schema and the pure-Go modernc.org/sqlite driver. One process exclusively owns each database. A competing application opener fails even while the first owner is idle. Do not share a database across SecDNS instances, copy a live file as a backup, or use a network filesystem. Symlink files, nonregular files and detected duplicate hardlink identities are rejected. Existing parent directories must be created by the operator; the application does not create a directory tree or delete files on startup failure.

On Unix, the immediate parent directory and existing database must have no group/other permission bits; newly created databases use mode 0600. On Windows, Go mode bits do not enforce ACL isolation: use a private directory and verify its ACL before use. File validation assumes the private directory is not concurrently modified by an untrusted actor; it is not a sandbox for adversarial path replacement.

There are no JSON record seeds or automatic imports. A new database starts empty and is populated through the existing admin API. Existing address/alias resolver configuration is separate from the record store. Persisted state is authoritative on restart: a deleted record is not restored from configuration.

## Mutation and expiry

Set and Delete return errors. SQLite transactions commit before the in-memory view changes and before the admin API reports success. Failed mutations return a generic HTTP 503 without database details; DELETE of a missing record remains HTTP 200 with `deleted:false`. SQLite uses FULL synchronous commits. The pinned driver's failed-Commit cleanup is exercised by a deferred-constraint test, followed by a successful transaction and reopen checks.

Persistent records are validated before writes and on startup, including expired rows. Supported types are A, AAAA, CNAME and TXT. CNAME records require one valid target and cannot coexist with other live RRsets at the same owner. Invalid database records fail startup rather than being skipped or silently repaired. Direct internal in-memory Set retains its existing permissive behavior. The admin API uses atomic validated mutations for both memory and SQLite; invalid records return 400 and live CNAME conflicts return 409. See the admin API documentation for normalization and exact expiry.

DNS TTL and absolute expiration are separate. The absolute expiry survives restart without resetting its duration. Reads filter expired records immediately. Startup and periodic GC remove expired database rows transactionally; GC failure retains the cached row but reads still exclude it, and a later sweep retries. Deletion reclaims logical rows, not necessarily file size; no automatic VACUUM or maintenance command is added. An expired row may count as present to DELETE before a sweep and absent afterward, matching the in-memory store's existing semantics.

The store lock spans the database commit. DNS reads for that store can wait behind slow disk writes. The finite SQLite busy timeout limits lock contention waits, not arbitrary filesystem or hardware stalls. This is persistence, not a high-availability design or protection against storage failure.

## Shutdown and validation

The process owns store cleanup. Close waits for any current mutation, prevents later writes and stops the store GC goroutine. In durable mode, SIGINT/SIGTERM returns from the main run after cleanup; existing listener interfaces have no drain API, so this is process-exit shutdown, not graceful connection draining. Acknowledged commits survive abrupt process exit; incomplete transactions are not published after reopening.

`-test` validates store configuration syntax without opening a database or creating sidecars. It does not verify filesystem permissions, disk health or persisted contents. Tests cover restart, update/delete, absolute expiry, transactional GC, corruption/schema/row failures, commit and delete rollback, exclusive subprocess ownership, abrupt process exit, partial startup rollback, close/concurrency, API failures and nonmutating config checks. Failure injection uses SQL constraints/triggers; actual hardware-loss and disk-full faults have not been simulated.

No deployment or production record import is included.

References: [modernc SQLite driver](https://pkg.go.dev/modernc.org/sqlite@v1.50.1), [SQLite locking mode](https://www.sqlite.org/pragma.html#pragma_locking_mode), [SQLite synchronous commits](https://www.sqlite.org/pragma.html#pragma_synchronous).
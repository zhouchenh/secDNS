# SQLite platform availability

The existing release binary target list is unchanged. SQLite persistence uses the
documented platform set of the pinned modernc.org/sqlite v1.50.1 dependency:

| System | Architectures |
|---|---|
| macOS | amd64, arm64 |
| FreeBSD | amd64, arm64 |
| Linux | 386, amd64, arm, arm64, loong64, ppc64le, riscv64, s390x |
| Windows | 386, amd64, arm64 |

Android and iOS are excluded, including their Go Linux/Darwin build-tag aliases.
Generated dependency files for other systems do not establish supported runtime
behavior. Memory stores and DNS behavior remain available on those binaries.

On other targets, legacy/versioned SQLite opens and follower SQLite create/open
return `recordstore.ErrSQLiteUnsupported` before filesystem access. They create no
database, journal, sidecar or directory and do not silently fall back to memory.
Existing supported-platform database ownership, migration and durability rules
are unchanged. The follower store remains an internal substrate.

`go test ./internal/recordstore -run '^TestSQLitePlatform'` checks release-target
file selection and the Android/iOS exclusions. It also builds a native test-only
overlay of the unavailable backend to exercise all constructors and memory modes
without introducing a runtime option or running foreign binaries.

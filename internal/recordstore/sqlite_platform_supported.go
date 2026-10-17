//go:build (darwin && !ios && (amd64 || arm64)) || (freebsd && (amd64 || arm64)) || (linux && !android && (386 || amd64 || arm || arm64 || loong64 || ppc64le || riscv64 || s390x)) || (windows && (386 || amd64 || arm64))

package recordstore

import _ "modernc.org/sqlite"

// The allowlist follows modernc.org/sqlite v1.50.1's documented platform table.
const sqlitePlatformSupported = true

package recordstore

import "errors"

// ErrSQLiteUnsupported means this binary has no qualified SQLite backend.
// Memory stores remain available; persistence must never silently fall back.
var ErrSQLiteUnsupported = errors.New("SQLite persistence is not supported on this platform")

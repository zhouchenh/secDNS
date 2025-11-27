# ERROR_HANDLING

Improper error management leading to silent failures or crashes.

## Panic in Request Handler
- **Context:** Malformed packet processing
- **Symptom:** Server crash on crafted malicious packets; DoS vulnerability.
- **Root Cause:** Missing bounds checks; no `recover()` in handler goroutines.
- **Fix:** Add `defer recover()` in handlers; validate all slice accesses; use fuzz testing.

## Silent Error Swallowing
- **Context:** Zone file parsing, upstream queries
- **Symptom:** Missing records; silent resolution failures; hard to debug issues.
- **Root Cause:** `if err != nil { return }` without logging or propagating error.
- **Fix:** Implement structured logging; return errors with context (`fmt.Errorf("parsing zone %s: %w", name, err)`).

## Timeout Not Propagated
- **Context:** Chained operations (cache miss → upstream → cache store)
- **Symptom:** Requests hang; client timeouts; goroutine accumulation.
- **Root Cause:** Outer timeout set but not passed to inner operations; each operation has independent timeout.
- **Fix:** Pass `context.Context` through entire call chain; use single deadline for full request lifecycle.


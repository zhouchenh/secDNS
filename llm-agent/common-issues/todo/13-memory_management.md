# MEMORY_MANAGEMENT

Additional memory and GC-related issues in DNS workloads.

## String Allocation Explosion
- **Context:** QNAME parsing and normalization
- **Symptom:** High allocation rate; GC dominating CPU at peak QPS.
- **Root Cause:** Converting labels to strings repeatedly (string(b)) and concatenating for every query instead of reusing or interning.
- **Fix:** Normalize and intern common domain names; keep label representation as []byte where possible; reuse temporary buffers.

## Per-Client Statistics Map Leak
- **Context:** Telemetry per client IP / per QNAME
- **Symptom:** Memory footprint grows with number of unique clients or domains and never shrinks.
- **Root Cause:** Using unbounded map[string]*Stats keyed by client IP or QNAME without any eviction or TTL.
- **Fix:** Add max size and TTL for stats maps; aggregate rare entries into catch-all buckets; periodically purge old keys.

## Caching Full Request and Response Objects
- **Context:** Response cache implementation
- **Symptom:** Cache uses large amounts of memory; high GC activity; heap never returns to baseline.
- **Root Cause:** Storing full request/response structs including temporary buffers and context fields instead of minimal wire-format or normalized structs.
- **Fix:** Cache only minimal canonical representation (e.g., encoded answer section and TTL metadata); avoid storing contexts, loggers, or large temporary slices.

## Excessive Large Slice Capacity
- **Context:** Zone file loading, in-memory indexes
- **Symptom:** RSS significantly higher than expected from record counts.
- **Root Cause:** Creating large slices with high capacity and then sub-slicing, causing large backing arrays to persist.
- **Fix:** Use precise make([]T, len) or make([]T, 0, expected) and copy to right-sized slices when done; periodically re-build compact structures.


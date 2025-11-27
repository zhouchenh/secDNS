# MEMORY_MANAGEMENT

Pitfalls in heap allocation, buffer reuse, and GC pressure.

## Dirty Buffer Reuse (sync.Pool)
- **Context:** Packet serialization/deserialization
- **Symptom:** DNS responses contain garbage data from previous requests; unexpected truncated packets.
- **Root Cause:** Putting a `[]byte` buffer back into `sync.Pool` without resetting its length (`buf = buf[:0]`) or zeroing sensitive fields.
- **Fix:** Always `Reset()` buffers before `Put()`; check length on `Get()`.

## Slice Memory Leak (The 'Slice Trap')
- **Context:** Parsing large zone files
- **Symptom:** High memory usage even after releasing large datasets.
- **Root Cause:** Keeping a small sub-slice of a large backing array (e.g., `record.Name = line[10:20]`), keeping the entire large array in memory.
- **Fix:** Copy string data to new memory: `string(byteSlice)` or `strings.Clone()`.

## Excessive Allocations in Hot Path
- **Context:** Per-query processing
- **Symptom:** High GC pause times; reduced throughput under load.
- **Root Cause:** Creating new slices, maps, or string concatenations for every DNS query instead of reusing.
- **Fix:** Pre-allocate structures; use `sync.Pool`; prefer `[]byte` operations over string manipulation.

## Cache Unbounded Growth
- **Context:** Response caching
- **Symptom:** OOM after extended runtime; memory grows monotonically.
- **Root Cause:** Cache entries added but never evicted; TTL expiration not enforced.
- **Fix:** Implement LRU/LFU eviction; background goroutine for TTL-based cleanup; set max cache size.


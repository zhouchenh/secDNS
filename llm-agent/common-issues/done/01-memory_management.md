# MEMORY_MANAGEMENT

Pitfalls in heap allocation, buffer reuse, and GC pressure.

## Dirty Buffer Reuse (sync.Pool)
- **Context:** Packet serialization/deserialization
- **Symptom:** DNS responses contain garbage data from previous requests; unexpected truncated packets.
- **Root Cause:** Putting a `[]byte` buffer back into `sync.Pool` without resetting its length (`buf = buf[:0]`) or zeroing sensitive fields.
- **Fix:** Always `Reset()` buffers before `Put()`; checking length on `Get()`.

## Slice Memory Leak (The 'Slice Trap')
- **Context:** Parsing large zone files
- **Symptom:** High memory usage even after releasing large datasets.
- **Root Cause:** Keeping a small sub-slice of a large backing array (e.g., `record.Name = line[10:20]`), keeping the entire large array in memory.
- **Fix:** Copy string data to new memory: `string(byteSlice)` or `strings.Clone()`.


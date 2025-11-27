# PERFORMANCE_TUNING

Performance pitfalls specific to Go DNS servers at scale.

## Logging on the Hot Path with Mutex Contention
- **Context:** Per-query structured logging
- **Symptom:** High CPU usage in logging library; reduced QPS; p99 latency spikes when log level is verbose.
- **Root Cause:** Synchronous logging with shared io.Writer + mutex for every query, often including expensive string formatting.
- **Fix:** Use asynchronous, batched logging; limit logs on hot paths; sample logs; use low-allocation loggers.

## Single Socket Bottleneck Without SO_REUSEPORT
- **Context:** Multi-core UDP handling
- **Symptom:** CPU utilization uneven across cores; one CPU pegged while others idle.
- **Root Cause:** Only one UDP socket bound on a single goroutine; kernel cannot distribute load across cores.
- **Fix:** Use multiple UDP sockets with SO_REUSEPORT when supported; run read loops pinned to multiple CPUs.

## Ignoring CPU Cache Locality
- **Context:** Large in-memory zone/cache structures
- **Symptom:** CPU profile dominated by cache misses; poor scaling on multi-core machines.
- **Root Cause:** Using large, pointer-heavy structures (e.g., nested maps, linked lists) for lookups.
- **Fix:** Use cache-friendly data structures (flat slices, tries, or packed arrays); minimize pointer chasing in hot paths.

## Excessive Reflection in Config and Plugins
- **Context:** Plugin system, dynamic handlers
- **Symptom:** CPU time spent in reflection; pprof shows reflect.Value.* as hot.
- **Root Cause:** Using reflection-based plugin registration or config binding on every query.
- **Fix:** Limit reflection to startup time; generate static bindings or use interfaces without reflection in request path.


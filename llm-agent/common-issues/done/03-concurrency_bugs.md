# CONCURRENCY_BUGS

Issues related to Go's scheduler, goroutine management, and shared state.

## Unbounded Goroutine Spawning
- **Context:** UDP packet handling
- **Symptom:** OOM crash during DDoS or high load; scheduler thrashing.
- **Root Cause:** Spawning `go handler(pkt)` for every incoming UDP packet without a worker pool or semaphore.
- **Fix:** Implement `sem := make(chan struct{}, maxWorkers)` or use a fixed-size worker pool.

## Configuration Hot-Reload Race Condition
- **Context:** Runtime zone file updates
- **Symptom:** Inconsistent DNS answers; sporadic panic (nil pointer dereference) during reads.
- **Root Cause:** Modifying a map/slice in global config struct while readers access it without `RWMutex` or `atomic.Value`.
- **Fix:** Use `sync/atomic.Value` to swap the entire config pointer or `RWMutex`.

## Channel Deadlock in Graceful Shutdown
- **Context:** Server termination
- **Symptom:** Process hangs indefinitely during SIGTERM.
- **Root Cause:** Workers waiting on a channel that is never closed, or main loop waiting on `Wait()` without signaling workers to exit.
- **Fix:** Propagate `context.Context` for cancellation; ensure `close(quitChan)` happens before `wg.Wait()`.

## Lock Contention on Hot Paths
- **Context:** Cache access, metrics counters
- **Symptom:** High CPU with low throughput; goroutines blocked on mutex acquisition.
- **Root Cause:** Using a single `sync.Mutex` for cache lookups shared across all goroutines.
- **Fix:** Use sharded locks, `sync.Map` for read-heavy workloads, or lock-free structures with `atomic` operations.

## Goroutine Leak in Upstream Resolver
- **Context:** Recursive/forwarding queries
- **Symptom:** Gradual memory increase; goroutine count grows unbounded.
- **Root Cause:** Goroutine spawned for upstream query but context timeout not enforced; upstream never responds, goroutine waits forever.
- **Fix:** Always use `context.WithTimeout`; select on `ctx.Done()` alongside response channel.


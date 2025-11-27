# CONCURRENCY_BUGS

Issues related to Go's scheduler, goroutine management, and shared state.

## Unbounded Goroutine Spawning
- **Context:** UDP packet handling
- **Symptom:** OOM (Out of Memory) crash during DDoS or high load; scheduler thrashing.
- **Root Cause:** Spawning `go handler(pkt)` for every incoming UDP packet without a worker pool or semaphore.
- **Fix:** Implement `sem := make(chan struct{}, maxWorkers)` or use a fixed-size worker pool.

## Configuration Hot-Reload Race Condition
- **Context:** Runtime zone file updates
- **Symptom:** Inconsistent DNS answers; sporadic panic (nil pointer dereference) during reads.
- **Root Cause:** Modifying a map/slice in global config struct while readers access it without `RWMutex` or `atomic.Value`.
- **Fix:** Use `sync/atomic.Value` to swap the entire config pointer or `RWMutex`.

## Channel deadlock in Graceful Shutdown
- **Context:** Server termination
- **Symptom:** Process hangs indefinitely during SIGTERM.
- **Root Cause:** Workers waiting on a channel that is never closed, or main loop waiting on `Wait()` without signaling workers to exit.
- **Fix:** Propagate `context.Context` for cancellation; ensure `close(quitChan)` happens before `wg.Wait()`.


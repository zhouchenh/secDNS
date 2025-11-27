# CONCURRENCY_BUGS

Additional issues related to goroutines, shared state, and synchronization in a high-throughput DNS server.

## Shared Buffer Data Race
- **Context:** UDP/TCP request handling with buffer reuse
- **Symptom:** Corrupted DNS packets; randomly malformed answers; sporadic SERVFAILs under load.
- **Root Cause:** Multiple goroutines reading/writing the same []byte buffer obtained from a pool without per-request ownership.
- **Fix:** Enforce single-owner semantics for buffers; never share mutable []byte between goroutines; copy before passing to concurrent workers.

## Ticker and Timer Goroutine Leak
- **Context:** Periodic tasks (cache cleanup, metrics flush)
- **Symptom:** Goroutine count and memory usage grow slowly over time; only noticeable after days/weeks.
- **Root Cause:** Creating time.Ticker or time.AfterFunc within request handlers or hot paths and never calling Stop() or letting contexts cancel.
- **Fix:** Create tickers in long-lived goroutines with clear lifecycle; always call ticker.Stop() on shutdown; tie timers to context.Context.

## Worker Pool Starvation
- **Context:** Single worker pool for heterogeneous tasks
- **Symptom:** Simple A/AAAA queries become slow when heavy operations (zone reload, AXFR, DNSSEC signing) run.
- **Root Cause:** Same bounded worker pool used for both cheap and expensive jobs; long-running tasks block all workers.
- **Fix:** Separate pools/queues for latency-sensitive and heavy tasks; apply priority or dedicated goroutine sets.

## Double Channel Close on Shutdown
- **Context:** Graceful shutdown and reload signals
- **Symptom:** Panic: close of closed channel during reload or termination, often intermittent.
- **Root Cause:** Multiple signal handlers or goroutines attempting to close the same quit/done channel.
- **Fix:** Use sync.Once or context.Context cancellation instead of manual channel close from multiple callers.

## Using context.Background in Long-Lived Goroutines
- **Context:** Upstream resolution, cache loaders
- **Symptom:** Requests remain pending after clients cancel; upstream queries continue even after timeout.
- **Root Cause:** Spawning goroutines with context.Background() instead of the request-scoped context.
- **Fix:** Always derive contexts from the incoming request context (ctx) and propagate them; avoid context.Background() in request path.


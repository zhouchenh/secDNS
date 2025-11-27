# RESILIENCE_FAILOVER

Issues affecting robustness under partial failures, upstream problems, and restarts.

## Retry Storm on Upstream Failure
- **Context:** Recursive resolver with multiple upstreams
- **Symptom:** When one upstream fails, CPU and network usage spike due to mass retries; timeouts for all clients.
- **Root Cause:** Aggressive retry logic without backoff or circuit breaking; each query fans out to all upstreams repeatedly.
- **Fix:** Implement exponential backoff, jitter, and circuit breaker per upstream; limit total retries per query.

## Non-Atomic Configuration Reload
- **Context:** Hot reload of zones and upstream settings
- **Symptom:** Short windows where some queries see old config and some see partially new config; rare panics.
- **Root Cause:** Updating shared config structure in-place while requests read from it; multi-step updates not atomic.
- **Fix:** Build new config snapshot off to the side; swap pointer atomically (atomic.Value); avoid in-place mutations.

## Ignoring Partial Zone Load Failures
- **Context:** Bulk zone file import
- **Symptom:** Some records silently missing; inconsistent behavior between primaries and secondaries.
- **Root Cause:** Aborting on first error without reporting or continuing with partially loaded zone; or silently skipping invalid records.
- **Fix:** Collect and report all parse errors; fail zone load atomically on serious issues; expose status in metrics and logs.

## No Warm-Up After Restart
- **Context:** Cache-heavy deployments
- **Symptom:** Immediately after restart, latency spikes and upstream load is high until cache re-fills.
- **Root Cause:** Cold cache and lazy initialization of indexes; no preloading or priming queries.
- **Fix:** Preload hot zones/records into cache at startup; optionally persist cache snapshots and restore them safely.


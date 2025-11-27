# TESTING_QUALITY

Additional gaps in testing strategy specific to DNS workloads.

## Lack of Cross-Implementation Interop Tests
- **Context:** Compatibility with common resolvers and stub clients
- **Symptom:** Works in unit tests but fails with specific resolvers (e.g., Windows, Android, systemd-resolved).
- **Root Cause:** Only testing with one client library or test harness; not validating behavior against multiple real-world implementations.
- **Fix:** Create integration tests using different resolver stacks (bind, unbound, system libraries); capture and replay real query traces.

## No Chaos Testing for Upstream Failures
- **Context:** Recursive resolver with multiple upstreams
- **Symptom:** Unexpected outage when a single upstream misbehaves (slow, flapping, or corrupt).
- **Root Cause:** Not testing behavior under partial upstream and network failures.
- **Fix:** Introduce chaos tests that inject latency, packet loss, and corruption into upstream paths; assert graceful degradation.

## Insufficient Long-Running Soak Tests
- **Context:** Memory leaks and counter wraparounds
- **Symptom:** Service stable in short load tests but degrades after days/weeks.
- **Root Cause:** Only running short-duration performance tests; not observing long-term stability.
- **Fix:** Add soak tests (many hours/days) at realistic and peak loads; monitor resources, latencies, and error rates over time.


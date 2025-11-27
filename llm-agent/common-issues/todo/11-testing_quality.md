# TESTING_QUALITY

Gaps in testing leading to production issues.

## No Fuzz Testing
- **Context:** Packet parsing
- **Symptom:** Crashes on malformed packets discovered in production.
- **Root Cause:** Only tested with well-formed packets; edge cases not covered.
- **Fix:** Implement Go native fuzzing (`go test -fuzz`); run continuously in CI.

## Race Conditions Not Detected
- **Context:** Concurrent access patterns
- **Symptom:** Sporadic failures in production; unreproducible bugs.
- **Root Cause:** Tests not run with `-race` flag; race detector not in CI pipeline.
- **Fix:** Run `go test -race` in CI; test under concurrent load.

## Missing Load Testing
- **Context:** Pre-production validation
- **Symptom:** Performance degradation discovered only in production; capacity planning failures.
- **Root Cause:** Unit tests pass but no realistic load simulation.
- **Fix:** Implement load tests with `dnsperf` or `flamethrower`; test at 2x expected peak load.


# OBSERVABILITY

Monitoring, metrics, and debugging issues.

## Metrics Cardinality Explosion
- **Context:** Prometheus metrics
- **Symptom:** OOM in metrics collection; slow scrapes; high memory usage.
- **Root Cause:** Using unbounded labels (query name, client IP) in metrics; creating new metric per unique query.
- **Fix:** Use bounded label sets (query type, response code, zone); aggregate client IPs into subnets.

## Missing Request Tracing
- **Context:** Debugging resolution failures
- **Symptom:** Unable to trace why specific queries fail; blind spots in recursive resolution.
- **Root Cause:** No request ID propagation; logs not correlated across resolution steps.
- **Fix:** Generate request ID; propagate via context; include in all log entries for request.

## Health Check False Positives
- **Context:** Load balancer integration
- **Symptom:** Unhealthy server receives traffic; cascading failures.
- **Root Cause:** Health endpoint returns 200 but doesn't verify actual DNS resolution capability.
- **Fix:** Health check should perform actual DNS query; verify upstream connectivity; check cache health.


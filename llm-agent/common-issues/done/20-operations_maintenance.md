# OPERATIONS_MAINTENANCE

Day-2 operational issues that lead to subtle production bugs or outages.

## Overly Verbose Logging by Default
- **Context:** Production startup configuration
- **Symptom:** Disk fills quickly; I/O becomes bottleneck; log rotation struggles during incident.
- **Root Cause:** Default log level set to debug or trace in production; high-frequency events logged.
- **Fix:** Set conservative default log level (info/warn); make higher verbosity opt-in and time-bounded.

## Missing Safe Defaults for Unknown Config Fields
- **Context:** Config file evolution
- **Symptom:** Old configs behave unexpectedly after upgrade; new features silently disabled or misconfigured.
- **Root Cause:** Ignoring unknown fields or assuming zero-values are safe; no versioning of configuration schema.
- **Fix:** Validate config with strict schema; reject unknown fields or log loudly; version and migrate config formats.

## Clock Skew Between Cluster Nodes
- **Context:** Cache expiry, negative caching, DNSSEC validation
- **Symptom:** Different nodes return different TTLs; DNSSEC validation fails depending on node.
- **Root Cause:** NTP misconfiguration or large time drift between replicas/regions.
- **Fix:** Require time synchronization (NTP) and monitor clock offsets; fail fast or degrade gracefully on large skew.


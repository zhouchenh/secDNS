# CONFIGURATION

Additional configuration and deployment mistakes that manifest as runtime bugs.

## Inconsistent Time Unit Parsing
- **Context:** Config file TTLs, timeouts, and intervals
- **Symptom:** Timeouts much shorter or longer than intended (e.g., 5ms instead of 5s).
- **Root Cause:** Mixing raw integers with time.Duration without clear units; interpreting seconds as nanoseconds or vice versa.
- **Fix:** Use human-readable duration strings parsed with time.ParseDuration; document units clearly; validate ranges at startup.

## Misconfigured Access Control Lists
- **Context:** Recursive vs authoritative mode access
- **Symptom:** Recursive resolution unintentionally exposed to the internet or unintentionally blocked for internal clients.
- **Root Cause:** Confusing CIDR lists; default-allow when ACL is empty; not differentiating between query types.
- **Fix:** Explicitly separate ACLs for recursion and authoritativeness; apply secure defaults (deny-all, then allow-listed).

## pprof / Debug Endpoints Exposed Publicly
- **Context:** HTTP admin/metrics server
- **Symptom:** Sensitive runtime info (goroutines, heap) exposed; potential DoS via expensive debug handlers.
- **Root Cause:** Binding debug/pprof endpoints on 0.0.0.0 without auth or network restrictions.
- **Fix:** Bind debug endpoints to localhost or a dedicated admin network; require authentication or IP whitelisting.

## Inconsistent Zone Replication Settings
- **Context:** Primary–secondary deployments
- **Symptom:** Secondaries serving stale data or failing to update; serials out of sync.
- **Root Cause:** Not validating SOA serial increments; misconfigured NOTIFY/AXFR/IXFR settings between nodes.
- **Fix:** Enforce strictly monotonic serials; test NOTIFY and transfer configuration; expose replication lag metrics.


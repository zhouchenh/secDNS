# CONFIGURATION

Deployment and configuration management issues.

## GOMAXPROCS Misconfiguration in Containers
- **Context:** Kubernetes/Docker deployment
- **Symptom:** Using more CPU than container limit; throttling; poor performance.
- **Root Cause:** Go runtime sees host CPU count, not container limit; spawns too many threads.
- **Fix:** Use `automaxprocs` library; set GOMAXPROCS explicitly based on container CPU limit.

## File Descriptor Limits
- **Context:** High connection count
- **Symptom:** 'too many open files' errors; connection failures.
- **Root Cause:** Default ulimit too low for expected connection count; not increased in container/systemd.
- **Fix:** Set `LimitNOFILE` in systemd unit; configure container ulimits; tune `net.core.somaxconn`.

## Improper Signal Handling
- **Context:** Container orchestration
- **Symptom:** Connections dropped on restart; data loss; slow termination.
- **Root Cause:** Not handling SIGTERM; immediate exit without draining connections.
- **Fix:** Implement graceful shutdown: stop accepting, drain existing, timeout, force exit.


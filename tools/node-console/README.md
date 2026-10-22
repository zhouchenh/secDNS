# Isolated candidate node adapter

This deployment-specific adapter exposes only AMD103, Intel108 and CIX106. It is
not a general SSH command API. The console launches the configured Python
interpreter with `adapter.py status NODE`, `adapter.py drain|resume NODE UUID`,
or `bgp-get NODE`, `bgp-validate NODE`, and `bgp-apply NODE UUID`.

The host-side `candidate_status.py` belongs at
`/opt/secdns-persistent-20261021/candidate_status.py`, root-owned mode 0700. Installing
the helper does not restart DNS or routing. SSH host trust and keys are referenced
from existing local files, never returned to the browser.

Status reports DNS service state, the current-boot health-controller observation,
maintenance intent, all four native-family BGP peer states, and the prefixes FRR
actually reports in each peer's advertised routes. Health older than twelve
seconds is unknown, not healthy. Unknown route response formats or unexpected
advertisements make inspection stale. Local probes check synthetic listener and
DNS64 semantics. A separate upstream worker sends unique positive-answer queries
through the real resolver path using sslip.io or traefik.me. These external
canaries exercise the default resolver chain, not every policy branch or upstream.
Each profile and transport gets a distinct name so an existing cached answer
cannot mask that probe's upstream failure. The worker runs every fifteen seconds,
with a six-second round budget, two failed rounds to withdraw, two successful
rounds to recover, and a thirty-five-second freshness limit. Local probe timing
and the twelve-second controller heartbeat are independent.

Drain changes only the existing maintenance flag. DNS keeps running and VIPs stay
installed; the existing health controller withdraws announcements. Resume clears
maintenance and waits for the controller's normal healthy recovery threshold and
actual advertisements. The Windows adapter serializes changes across the cohort
and refuses drain unless another freshly observed candidate is healthy and
advertising every profile. External administrators still need to coordinate their
operations with this owner.

Each remote change persists a UUID/action-bound receipt before writing the flag.
A repeated UUID returns that receipt without executing again. A pending or
uncertain receipt is not permission to retry with a new UUID: inspect fresh state
and reconcile the operation first. The console supplies its own authenticated
actor audit; remote receipts deliberately contain no account secrets.

Run local tests with `python -m unittest discover -s tools/node-console`.
This implementation does not edit peer addresses, ASNs, prefixes, production DNS,
or OSPF settings.

## Candidate BGP configuration

Validate and apply read a JSON object from standard input containing
`expected_revision` and `config`. The revision is a canonical configuration SHA256.
Only the four fixed peers' enabled state and keepalive/hold timers, and the four
normal/DNS64 IPv4/IPv6 announcement eligibility flags, can change. At least one
peer per address family must remain enabled. Addresses, ASNs, router identity,
synthetic prefix filters and private BGP port 1179 are fixed.

The host validates FRR syntax before mutation, drains verified advertisements,
saves the previous configuration, and arms an independent rollback timer before
replacing the private routing configuration. Only the candidate routing service
restarts; DNS and its database remain running. Confirmed success requires fresh
runtime peer state and actual advertisements matching the requested flags.
Confirmed rollback similarly requires verified restored configuration and state.

The adapter may report an uncertain result after its 100-second SSH deadline while
the independent 120-second watchdog is still recovering the operation. Recovery
can require another forty seconds. Never submit another change to compensate for
an uncertain operation: use read-only reconciliation of the UUID-bound receipt
and status. A durable pending transaction blocks subsequent configuration apply.


## Linux console host

The adapter supports Windows and Linux. Linux uses fixed paths, never paths or
hosts supplied by an HTTP request:

- SSH: `/usr/bin/ssh`, with `/dev/null` configuration, strict known-host checking,
  batch mode and identities-only enabled.
- Keys: `/etc/secdns-admin/ssh/keys/`, with the existing inventory key filenames.
- Known hosts: `/etc/secdns-admin/ssh/known-hosts/`, with the inventory relative
  filenames (including the `lxc-three-node-prep-r3` subdirectory).
- Global mutation lock: `/var/lib/secdns-admin/adapter-state/mutation.lock`.

Provision the state directory owned by the service identity with mode 0700;
its lock must be a regular service-owned 0600 file. Keys must be private regular
files. Known-host files and all path ancestors must be owned by root or the
service identity and not writable by other accounts. Symlinks fail closed.
Root-owned sticky ancestor directories are allowed for isolated test fixtures.
Linux uses nonblocking `flock`; Windows retains its existing nonblocking byte
lock. Run only one active console coordinator for this candidate inventory:
locks on different machines cannot serialize one another.

Generate a new scoped management key on the Linux host, and enroll only its
public key with a reviewed forced-command restriction on each candidate. Do not
copy workstation private keys. This source change does not provision keys,
change SSH policy, install services, or expose any listener.

A network portal also requires an exact HTTPS public origin, a trusted TLS
terminator, and consistent migration of the existing authentication database and
key while its sole writer is stopped. Preserve immutable authentication store
identity; do not initialize another owner or enroll MFA again. The admin HTTP
listener does not itself terminate TLS. Deployment must keep existing DNS and
replication listeners unchanged. Portability tests do not authorize deployment.
## Health settings (candidate upstream checks)

The Health settings dialog manages only the existing upstream canary worker. It uses the same human session, CSRF checks, fixed node inventory, durable operation receipts, and serialized candidate mutation guard as BGP settings. Record-agent tokens do not gain routing or health-control privileges.

Supported integer settings: interval 3–15 seconds, per-provider probe timeout 500–2500 ms, failure threshold 2–3 rounds, recovery threshold 2–5 rounds. The conservative budget of two provider timeouts plus 500 ms overhead must fit within the interval. Each transport starts the first provider, hedges to the second after 250 ms without a successful first result, and waits for both attempts to finish. At most sixteen probe subprocesses exist per round. An advertised profile with an unconfirmed failed round is checked again one second after that round completes; the configured interval otherwise applies. Two failed rounds are still required, but the temporal protection against short outages is shorter. Every attempt uses a fresh name. Healthy probe traffic may double when latency triggers hedging; this is not a zero-cost optimization. The read-only stale bound is `2*interval + ceil(2*timeout/1000) + 1` seconds. Existing nodes without a settings file retain 15 s / 2500 ms / 2 / 2; the recommended test configuration is 3 s / 1000 ms / 2 / 2.

Eight profile/transport workers run concurrently; each tries the two fixed canary domains sequentially and stops on its first success. Healthy load is approximately 8/3 queries per second per node at the recommended setting (five times the previous 8/15). There is no overlapping round: if subprocess teardown exceeds the bounded round budget, the worker stops and its observations expire. Local DNS semantic checks and their recovery gate are unchanged.

Settings load only between upstream rounds, with gates reset on a revision change. This can briefly withdraw the node's routes. A successful apply requires a completed round bearing the new revision and restoration of the baseline eligible health/advertisements. Rollback likewise requires the old revision and baseline recovery. The independent rollback timer is scheduled before the file change; request interruption is not evidence of failure. An uncertain response must be reconciled, never automatically retried. No DNS process restart, account change, or arbitrary canary/endpoint configuration is part of a settings apply.

The deployed health controller uses `query_helper` pointing to the locally built `secdns-health-query` binary. It passes the configured timeout in milliseconds to the DNS exchange itself; the subprocess gets a separate 250 ms startup/cleanup allowance. Structured timeout/network errors are recorded per attempt. The old parity fixture remains available for legacy callers but hardcodes a 700 ms DNS timeout and must not be used to qualify adjustable timeout semantics. Helper-only rollout changes the root-owned health configuration path and restarts the private routing controller, not DNS or the admin service.

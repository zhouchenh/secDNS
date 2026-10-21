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


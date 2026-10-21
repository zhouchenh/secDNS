# Isolated candidate node adapter

This deployment-specific adapter exposes only AMD103, Intel108 and CIX106. It is
not a general SSH command API. The console launches the configured Python
interpreter with `adapter.py status NODE`, or `adapter.py drain|resume NODE UUID`.

The host-side `candidate_status.py` belongs at
`/opt/secdns-persistent-20261021/candidate_status.py`, root-owned mode 0700. Installing
the helper does not restart DNS or routing. SSH host trust and keys are referenced
from existing local files, never returned to the browser.

Status reports DNS service state, the current-boot health-controller observation,
maintenance intent, all four native-family BGP peer states, and the prefixes FRR
actually reports in each peer's advertised routes. Health older than twelve
seconds is unknown, not healthy. Unknown route response formats or unexpected
advertisements make inspection stale. Health probes currently check synthetic
listener/DNS64 semantics; they do not prove every upstream resolver is available.

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

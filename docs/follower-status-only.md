# Status-only admin listener

Set `config.followerStatusOnly: true` on an `httpAdminServer` to expose only local
follower observations, without binding or implicitly creating any record store.
This is an explicit opt-in; omitted or false retains existing writer-admin routes.

```json
{
  "type": "httpAdminServer",
  "followerStatusStores": ["owned-static"],
  "config": {
    "listen": "127.0.0.1", "port": 18055, "path": "/owned-static",
    "token": "<operator-provided-token>", "ui": true,
    "followerStatusOnly": true
  }
}
```

The allowlisted names must identify configured follower workers. Empty, unknown,
duplicate or missing names fail startup. Omit `store`, `snapshotReaders` and
`sourcePolicyExplain` entirely: these options conflict with status-only mode even
when supplied as empty or false. The token remains mandatory. No parked writable
store is needed. With `ui:false`, only the status API is exposed.

Registered application routes are GET `<path>/followers`, and, when `ui:true`,
GET `<path>/ui` / `<path>/ui/` redirects to `<path>/ui/followers/`, its script and
stylesheet. Go's standard GET handling also supports HEAD. The unauthenticated
static shell contains no worker data; status GET uses the unchanged `records:read`
authorization wrapper, rejects snapshot-reader credentials and ambiguous mixed
cookie/bearer requests, and returns no-store responses. Scope semantics, redacted
error categories, accepted-revision/contact distinction and manual-only refresh
are unchanged from the existing local follower status view. This is not a fleet
health monitor or a remote-offline verdict.

No record, snapshot, events, import, preview, explain, editor or auth-management
routes are registered. The status-only page deliberately omits the record workspace
link and human/agent/passkey login scripts. For this bounded mode, enter the existing
legacy admin bearer or a suitable scoped bearer in the memory-only token form.
Existing backend cookie verification remains available to a preexisting valid
session, but this listener does not create sessions or expose interactive human
login/setup/recovery/passkey management. Ordinary writer listeners retain those
features unchanged. Do not treat omission of login routes as new human-login support.

Existing loopback forwards and base paths continue to work, including `/owned-static/ui/`.
This source feature does not create forwards, credentials, TLS, services, stores,
or deployment configuration. The actual-browser test uses the real Go route mux
and synthetic in-process status data only; no authority or candidate is contacted.

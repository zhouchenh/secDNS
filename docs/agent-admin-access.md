# Scoped agent access

This opt-in integration adds named agent API credentials and short browser sessions. Existing admin and snapshot-reader tokens remain supported. It does not add human password/TOTP/passkey sign-in, credential-management HTTP routes, shared sessions between nodes, TLS termination, or a deployment. The public release 1.8.0 predates this feature.

## Separate local identity

Build `go build ./cmd/secdns-adminauth`. Supply a private JSON definition with absolute, normalized `path` and `keyPath`, `realmID`, `nodeID`, and `displayName`. Keep the auth database/key separate from record databases. Parent directories must be private; on Windows the operator must enforce their ACLs. This slice permits exactly one configured auth realm/listener per process. A realm belongs to one listener and node. Do not put independent realms behind round-robin browser routing: cookies are host-scoped, not port-scoped.

Explicit offline operations:

```
secdns-adminauth -definition /private/admin-definition.json -operation create
secdns-adminauth -definition /private/admin-definition.json -operation issue-agent -name automation -scopes ui:view,records:read
secdns-adminauth -definition /private/admin-definition.json -operation revoke-agent -credential-id <issued-id>
```

Issuance intentionally prints the new credential once to the local command's output. Redirect it to a private destination; never paste it into logs, URLs or configuration examples. The command requires exclusive database ownership, so stop the owning process before offline administration. A failed/uncertain issuance must be inspected, not replayed blindly; an outstanding unused bootstrap can be explicitly cancelled with `cancel-bootstrap`. Issuing a grant never confers HTTP administration privileges. There are at most 128 lifetime credential rows, including revoked rows; this slice supplies no eviction/reset/recovery scheme.

The runtime opens an existing store only. New creation uses auth schema 2. Existing schema 1 is refused at runtime; after preserving an offline backup of the DB and its matching key, use `-operation migrate-schema1`. Migration validates the full old schema/rows/key/identity and changes its version in a single transaction. Failure before commit leaves schema 1 intact; an uncertain commit returns failure and closes the handle, requiring explicit readback. Do not replay migration after a committed error. Schema 2 adds the session audit vocabulary; old schema-1 software must not open it. No record database migration occurs.

Example integration fragment (substitute private absolute paths and retain the listener's existing token/store/listen settings):

```json
{
  "adminAuthStores": {
    "management": {
      "path": "/private/admin.db",
      "keyPath": "/private/admin.key",
      "realmID": "authority",
      "nodeID": "node-a",
      "displayName": "Administration"
    }
  },
  "listeners": [{
    "type": "httpAdminServer", "authStore": "management",
    "publicOrigin": "https://secdns.aircloud.pro"
  }]
}
```

The fragment is not a complete runnable listener. Use the existing admin listener type and required fields from your configuration. `publicOrigin` is a configurable exact HTTPS origin without a path; the hostname shown is one deployment preference, not built-in policy. Creation of DNS records/certificates and HTTPS termination are separate operator work. Without `publicOrigin`, scoped bearer API requests work over the existing protected transport, but browser session exchange is disabled. Configuration validation and `-test` perform no auth-store I/O. Actual startup validates every configured legacy admin/reader token against the agent store, rejects aliasing paths/shared realms, and releases already-opened auth handles on later startup failure.

## Permissions

| Operation | Required agent scopes |
|---|---|
| Snapshot or legacy-record GET | `records:read` |
| Snapshot/record POST or legacy-record DELETE | `records:write` |
| Snapshot events | **both** `records:read` and `snapshot:events` |
| RouterOS preview and exact conversion | `routeros:preview` |
| Offline source-policy explain API | `source-policy:explain` |
| Browser session exchange | `ui:view` |

Write never implies read. `audit:read` is reserved in this slice; no remote audit route is exposed. Agents cannot issue/revoke credentials or perform human setup. Scope checks run before request-body reads. Requests carrying both an Authorization header and a session cookie are rejected even if one credential is invalid. A rejected bearer never falls back to a cookie. The legacy UI explicitly selects configured legacy access; it does not reinterpret an agent credential as an administrator. Direct API agent callers omit that UI-only legacy-selection header.

## Browser session behavior

The Agent access form is available only when the browser location.origin exactly matches the configured publicOrigin; the client repeats this check before dispatching credentials. Alternate HTTP or HTTPS origins cannot exchange a credential. The Agent access form is separate from the labelled legacy-token form. It clears the input immediately after dispatch and retains no long-lived bearer after completion. Session cookies are `__Host-secdns_session`, Secure, HttpOnly, SameSite Strict, Path `/`, without Domain. Session secrets are stored only as keyed digests in a bounded process-local registry (256 sessions); capacity admission removes entries whose durable credentials are expired/revoked, but never evicts valid sessions. Restart invalidates all sessions. Inactivity expires after 15 minutes and absolute lifetime is two hours. Only authenticated and scope-authorized user actions refresh inactivity; background reads do not. Durable credential expiry/revocation is checked on every request.

The independent random CSRF value and its digest are retained in bounded **process memory**, never SQLite. Authenticated same-origin `GET /auth/session` returns the same CSRF value for reload recovery, along with actor/realm/node/scopes/expiry. Raw session secrets and agent bearers are not retained. This GET requires same-origin Fetch Metadata, rejects any mismatching Origin, uses no-store, and has no permissive CORS. Cookie mutations additionally require exact Origin, CSRF and a non-simple content type (JSON, or octet-stream for import preview). Logout removes the in-memory session even if its audit append fails, returning unavailable in that case. Session creation is published only after its fixed audit event commits.

Switching agent identity explicitly ends an existing browser session before presenting the new credential. Switching to legacy access on the configured origin also requires successful server logout first; a failed switch cannot silently retain and later restore agent authority. Expired-cookie reconciliation occurs without a bearer; credentials are never mixed. Actor/CSRF metadata remains in page memory, not localStorage/sessionStorage/IndexedDB. The UI displays the actual agent and permissions. Read-only controls cannot write, and the server independently denies direct write requests. Logout/expiry/relogin preserves local drafts and immutable pending replacement identity/body; relogin never automatically resubmits. Page reload/closure still loses existing editor recovery state as documented by the editor; this slice does not persist drafts.

Record CAS receipts remain the source of truth for record mutations. Auth audit and record writes do not form one cross-database transaction, and this slice does not claim comprehensive actor-attributed mutation auditing. Session/logout events contain only fixed fields and credential ID, never credential/CSRF values or record content.

## Verification

Focused tests cover permission intersections, authentication before body reads, cookie/origin/CSRF ambiguity, session expiry/revoke/restart/close, audit failure, schema migration rollback and committed-error uncertainty, offline issuance/revocation and startup ownership cleanup. Existing editor state tests remain applicable.

An opt-in real Chromium test runs against an ephemeral Go HTTPS server and synthetic records:

```
ADMINAUTH_BROWSER=1 PLAYWRIGHT_MODULE=<existing-install> go test ./internal/listeners/servers/http/admin/server -run '^TestAgentBrowser$' -count=1 -v
```

The browser context accepts only this test's self-signed fixture via its isolated test setting; machine/candidate trust stores are unchanged. The fixture deliberately returns a failure after committing one replacement, then proves logout/relogin does not resubmit and explicit retry uses identical bytes. It also checks actual Secure/HttpOnly cookies, reload resume, import preview, read-only direct-write denial and mobile visibility. The test process owns and closes the server/browser. No external DNS, production API, live preview, real credentials or network configuration is used.

Session metadata includes the server-derived `record_role: writable_authority`. This admin listener rejects follower-store bindings. The workspace displays that node role separately from credential scopes; record writes still require `records:write`. The role does not claim replication or cluster convergence.

The configured HTTPS origin must use browser-canonical port spelling: omit the default port 443; nondefault ports use decimal without leading zeros. Requests and browser location must match the configured origin exactly.

# Candidate node console

The optional node console adds **Nodes**, **DNS health** and **Routing** to the existing human-authenticated admin UI. It observes the isolated AMD, Intel and CIX candidates and supports candidate drain/resume. It does not configure production routers or arbitrary BGP peers.

On the human admin listener, configure these absolute local paths:

```json
{
  "nodeAdapterExecutable": "C:/path/to/python.exe",
  "nodeAdapterScript": "C:/path/to/tools/node-console/adapter.py",
  "nodeAuditDirectory": "C:/private/secdns/node-audit"
}
```

The included adapter is deployment-specific: its inventory identifies only `amd103`, `intel108` and `cix106`. Review the inventory and SSH trust files before enabling it. Keep adapter files and audit directory writable only by the service owner and trusted administrators. No API input can set a host, executable, command, prefix or configuration path.

## Access and operations

- `GET /admin/nodes/{node}` returns a fresh observation of service process, DNS checks, BGP peer state and observed announcements.
- `POST /admin/nodes/{node}/maintenance` accepts exactly `action` (`drain` or `resume`), canonical UUID `request_id`, string `expected_withdraw` (`true` or `false`), and `confirm_node` matching the URL node.
- Both require the existing human session and same-origin browser policy. Writes also require the session CSRF header. Record-scoped agents and legacy bearer credentials do not acquire routing privileges.
- Writes serialize, verify fresh maintenance state, and durably record intent before invoking the adapter. Each request ID is reserved even if the outcome is uncertain. Never blindly retry an uncertain operation; refresh and reconcile its actual state.
- Drain requires another healthy advertising candidate, withdraws only candidate announcements and leaves DNS running. Resume restores eligibility and confirms DNS health and announcements through readback.
- The UI refreshes on entry and on demand. A stale or unavailable observation is never reported as verified withdrawal. No automatic destructive or failure-injection action is exposed.

This initial management slice does not edit peer ASNs, addresses, policy or timers. Existing account, MFA and record databases are unchanged. Audit receipts are separate JSONL files with intent and outcome, actor identity and operation ID; credentials are never recorded.

## Local verification

Run `go test ./internal/listeners/servers/http/admin/server`. Opt into the disposable Chromium workflow with `ADMINAUTH_BROWSER=1` and a local Playwright module via `NODE_PATH`, then run `go test ./internal/listeners/servers/http/admin/server -run TestNodeConsoleBrowser -v`. The browser fixture creates an ephemeral human account and uses synthetic node observations; it never opens the real owner database or contacts candidate/production hosts.

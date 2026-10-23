# Real Facade / secDNS TLS integration fixture

Build from this secDNS worktree root (PowerShell):

```powershell
go build -C tools/facade-e2e-helper -o facade-helper.exe .
$env:SECDNS_FACADE_HELPER=(Resolve-Path tools/facade-e2e-helper/facade-helper.exe).Path
go test ./internal/listeners/servers/http/admin/server -run '^TestFacadeRealTLS$' -v -count=1
```

The helper module uses a relative replace pointing to the neighboring Facade worktree. Verify its HEAD is `8da83c60274b66ae1b2da23bd9d731a88a5ab358` before building. It imports the actual `internal/apphost` implementation; it does not copy or mock the proxy. The small process harness supplies an ephemeral loopback TLS listener, not the full Facade daemon/L4 demultiplexer.

The secDNS test uses actual HTTP routes/auth code and fresh SQLite auth/record databases in Go test temporary directories. All account/password/TOTP material is disposable. A fresh local CA/certificate is used with verified names on both TLS hops; no verification bypass exists. Headers are forged at the client and checked after the real proxy. Node status and BGP runner results are synthetic; neither SSH nor FRR nor production services are accessed. The test exercises HTTP API and static UI delivery, not browser clicks, JS execution, physical security keys, nginx or real BGP sessions.

The test process owns and terminates helper processes at cleanup. No shared listener or candidate process is restarted. Generated helper executable is ignored by Git.

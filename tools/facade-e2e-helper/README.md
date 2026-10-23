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

For the checked, reproducible run, use `./tools/facade-e2e-helper/run.ps1`. It refuses a changed Facade HEAD or dirty source tree before compilation. Facade HEAD and clean status were verified on 2026-10-23.

Optional browser handoff: set `SECDNS_FACADE_BROWSER_MANIFEST` to a private temporary JSON file, then run the same script. It binds only `127.0.0.1:443` (fails if occupied), uses `https://secdns.localhost/admin/ui/` with the matching fixture public origin and certificate SAN, and remains for at most 20 minutes. The manifest contains only generated disposable account setup material and is removed on normal cleanup. On Windows restrict its ACL to the current user before browser handoff. The browser must resolve `.localhost` to loopback; no DNS/hosts edits, verification bypasses or browser flags are used. A fresh untrusted CA can produce a browser certificate warning; leave trust decisions to the user. This optional variant proves localhost browser behavior only; the automated API case separately retains the exact secdns.aircloud.pro origin. It still does not model nginx or L4 demultiplexing.

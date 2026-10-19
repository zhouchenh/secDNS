# Human owner sign-in

Human sign-in is opt-in and node-local. It adds a username/password plus authenticator-code flow alongside the existing dedicated Agent access and legacy-token paths. It does not deploy a portal, create DNS records or certificates, synchronize identities between nodes, or change any record database. Optional passkeys are available after separate explicit schema/RP setup; see [Passkeys](passkey-admin-access.md). Remote agent-credential management remains subsequent work.

## Enable explicitly while offline

Use the existing private definition file and matching authentication key. Stop the process owning that auth database and preserve a private backup of the database **and its matching key**. Schema 2 remains supported for agent-only access; runtime never migrates it. With a locally built `secdns-adminauth`:

```
secdns-adminauth -definition /private/admin-definition.json -operation enable-human
secdns-adminauth -definition /private/admin-definition.json -operation setup-human
```

`enable-human` validates schema 2, then adds four strictly validated tables and advances to schema 3 in one transaction. Existing credentials, audit history, realm identity and separate record data remain intact. Old software must not open schema 3. A rollback restores the offline auth backup with its matching key; it never restores or replaces the record database. Unknown or uncertain migration outcomes require strict readback, not blind replay. `setup-human` prints a one-use local grant once, valid for ten minutes. Keep it private and enter it only at the configured HTTPS portal. Restart the normal server, open the existing record workspace, and use **Set up owner**. The configured origin belongs to one explicit realm, not a round-robin pool of independent auth stores.

Setup collects a username, display name and password, then shows an authenticator QR code and the same manual key. The PNG is generated inside secDNS and returned only in the existing HTTPS/no-store enrollment response; it is never sent to an external QR service or image URL. The label identifies the realm/node and uses the explicit SHA-1/six-digit/30-second profile. Scan the QR code or add that key to an authenticator and confirm a current six-digit code. No owner session exists before confirmation. Completion consumes the local grant, stores the owner and encrypted seed, generates recovery codes, and records the setup event transactionally. Save all ten recovery codes immediately; each works once. A failed response after a durable commit is not proof that setup failed: retain the password/authenticator and inspect sign-in state rather than submitting another setup blindly. Legacy access is never disabled by setup or failure.

## Password and authenticator behavior

- Passwords are exact, unnormalized UTF-8 values of 15–256 Unicode code points. Spaces are retained. Control characters and a bounded embedded common/product-derived denylist are refused. No external password service receives a password or digest.
- Password verifiers use Argon2id PHC strings: 64 MiB, three iterations, four lanes, 16-byte random salt and 32-byte output. The parser accepts only these bounded parameters. A process-wide derivation slot and a nonqueued human-operation gate bound expensive concurrent work.
- TOTP uses RFC 6238's SHA-1 interoperability profile, six digits and 30-second steps. Only the current and adjacent steps are considered; successful counters are committed atomically and cannot be reused, including for recent reauthentication. Wait for a new code when necessary.
- Seeds use AES-GCM under a domain-separated key derived from the separate local authentication key, with realm/node binding. They are shown only during pending enrollment. Starting replacement leaves the current factor and sessions working until confirmation; confirmation replaces the factor/codes and invalidates older human sessions.
- Persistent account and socket-source buckets apply increasing delays after five attempts, capped at 512 seconds. They survive restart; no forwarded header controls source identity. At most 1,024 buckets are retained, with stale entries removed after a day. Capacity fails closed. A malicious client can temporarily delay account access; local operator recovery remains separate.

## Sessions and account security

Password verification creates only a five-minute, source-bound MFA ceremony. A valid unused authenticator code completes login. Human sessions use the same Secure/HttpOnly/SameSite-Strict host cookie as agent sessions, but retain distinct principal identity and permissions. Human idle expiry is 30 minutes and absolute expiry is 12 hours; restart invalidates all process-local sessions. The UI warns two minutes before expiry. Background reads do not renew idle expiry. Existing origin, Fetch Metadata, CSRF, scope and mixed-credential checks remain enforced. Long-lived agent credentials are never converted into human authority.

Password/grant admission and authenticator guesses have separate durable account-wide and socket-source rate budgets. A correct password does not clear accumulated debt. New ceremonies are refused while the authenticator budget is cooling down, and each confirmation consumes that budget; this prevents an admitted password step from imposing a cooldown longer than its own five-minute MFA challenge. Combined password+TOTP reauthentication respects both budgets. Only completed authentication clears both, and restarting does not erase their debt (pending challenges themselves do not survive restart). Existing admission keys and database schema are unchanged.

Account security offers password+TOTP reauthentication, password change, authenticator replacement, recovery-code regeneration, revocation of other human sessions, and the latest 100 fixed authentication audit events. Sensitive actions require actual human session/CSRF verification and MFA within five minutes. Reauthentication rotates the session secret. Password changes invalidate older human sessions but do not extend the prior MFA-recentness timestamp. Agent credentials, including write-capable agents, cannot invoke these controls. Auth events do not claim to be a transactionally joined record-mutation audit.

## Recovery

**Saved-code recovery** requires the password and one of the ten saved codes. It opens a restricted replacement ceremony, never a full session. Confirming the new authenticator atomically consumes/replaces all old recovery codes, increments the human security generation, and invalidates old human sessions. Codes have independent 128-bit randomness and salted Argon2id verifiers. Cancellation leaves the working factor intact.

If every factor is lost, stop the owning process and use the explicit local `recover-human` operation to create a one-use ten-minute grant. Restart and choose **Recover with local grant** at the exact configured HTTPS origin. This forces a new password and authenticator, replaces all recovery codes, and invalidates prior human sessions. It cannot reveal old credentials. `cancel-human` explicitly removes an outstanding grant; it does not reset the owner. Grants cannot be replaced implicitly.

Inspect recent security events and revoke other sessions after recovery. There is no email/SMS recovery, shared-node cookie authority, remote root recovery, or automatic credential issuance. Recovery never modifies DNS records. A key/database loss needs the offline backup or a separately designed operator procedure; this feature does not promise lossless recovery from missing cryptographic material.

## Local validation

Go regressions cover schema migration rollback/commit uncertainty, strict reopen/encrypted-seed corruption, atomic one-winner setup, OTP replay, source-bound ceremonies, persistent rate refusal, root/saved-code recovery, old-factor preservation, session generation invalidation, recent-MFA expiry and agent denial. The opt-in `ADMINAUTH_BROWSER=1` fixture uses an isolated localhost TLS server and installed Chromium with synthetic credentials, proving setup/login/reload/rotation/recovery and a 375-pixel layout. It also reruns the agent-session browser flow. No real portal, candidate, CA or production service is changed by these tests.


For the persistent-record-store intersection, run the separate local fixture:

```sh
ADMINAUTH_SCHEMA4_BROWSER=1 PLAYWRIGHT_MODULE=<existing-install> go test ./internal/listeners/servers/http/admin/server -run '^TestHumanSchema4Browser$' -count=1 -v
```

This uses disposable auth credentials and a temporary SQLite record store explicitly migrated to schema4. It exercises real password/TOTP login, the secure human session cookie, CSRF rejection without writes, the single-RRset editor without a bearer token, and exact operation replay after a deliberately truncated acknowledgement. Closing and reopening the store verifies the snapshot and exactly one targeted receipt remain durable. It does not capture screenshots or access an existing portal or database; the temporary TLS exception is limited to the test browser context.
## Shared administration console

The embedded record, RouterOS import and local follower pages share persistent navigation and a compact instance header. Navigation is generated from the listener's real capabilities: a follower-only listener never gains record-write or import routes. The instance label is the current browser endpoint, not a claim of cluster discovery or fleet health.

The versioned record table separates names and values and supports text and record-type filtering. Existing staged edits, comparison/review, schema-dependent targeted versus full-snapshot writes and exact uncertain-operation retry remain unchanged. Navigating away with local draft changes, pending operations or pasted import source prompts before losing page-local state. Existing human, agent and legacy authentication modules are grouped under account access; credentials and CSRF handling are not replaced by the presentation layer.

The RouterOS page still invokes the existing preview/conversion API and explicit candidate handoff. This console does not add OS networking, routing-protocol control or a global cluster dashboard. No production configuration is changed by enabling the presentation update.

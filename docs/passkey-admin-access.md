# Human passkeys

Passkeys are optional, node-local human authentication. Password plus authenticator,
recovery codes, dedicated agent credentials and legacy access remain available.
Initialize the owner with password/TOTP first. This source change provisions no
portal, certificate, DNS record, live auth database, or shared multi-node identity.

## Explicit offline enablement

Stop the process owning the auth database and preserve an offline private backup
of that database and its matching key. Use a locally built administration tool:

```sh
secdns-adminauth -definition /private/admin-definition.json -operation enable-passkeys \
  -public-origin https://secdns.aircloud.pro -rp-id secdns.aircloud.pro
```

This validates initialized schema 3, atomically adds schema 4 and a random stable
user handle, and binds the exact origin and RP. Runtime does not migrate. Existing
schema 2/3 stores remain supported without passkeys. Configure `passkeyRPID` on the
same admin listener as `authStore` and `publicOrigin`; the RP must exactly equal
the canonical HTTPS origin hostname. Parent-domain/multi-origin federation and
Host/forwarded-header-derived identity are unsupported. Explicit port 443 must be
omitted; nondefault ports remain part of the exact origin. The preferred portal
is configurable, initially one explicit realm, never independent-node round robin.

A configured RP/store mismatch fails startup. Omit `passkeyRPID` to keep existing
human/agent authentication without passkey endpoints. An uncertain offline
migration must be reconciled before retrying. Rollback restores the offline auth
backup with its matching key while stopped; old binaries cannot open schema 4.
Record databases and user DNS edits are never part of this rollback.

## Browser use

After recent human authentication, enter a name and select **Add a passkey**.
The browser/device creates a discoverable credential with user verification
required. secDNS stores public credential data only, never biometric data or
private authenticator keys. The browser must support the standard WebAuthn JSON
conversion APIs; otherwise the page directs users to password/authenticator.

Use **Verify identity with a passkey** to test a passkey and refresh recent human
authentication. **Show saved passkeys** lists names and counter warnings. The
authenticated list API also returns creation and last-use metadata. Rename and removal require recent human authentication. Removing
any key conservatively invalidates all human sessions and signs out this browser;
other passkeys, password/TOTP and recovery remain enrolled. Account recovery removes
all old passkeys atomically. Ordinary password/TOTP replacement retains enrolled
passkeys but invalidates sessions through the existing human epoch.

Challenges are one-use, source/type/human/session-bound, expire in five minutes,
and are lost on restart. No pending challenge or browser credential is persisted
in local/session storage. At most 32 pending ceremonies and 16 public credentials
are admitted. Cancellation or a lost response is not proof that a server-side
operation did not commit: inspect the saved-key list before retrying registration.

Registration inserts credential and audit together after a current-session check.
Login/reauthentication updates counter/last-used and audit in the transaction before
publishing/rotating a session. Wrong origin/RP, signature, UV, user handle,
challenge, removed key, or changed human epoch refuses. Failed commits fault the
store handle and never publish an unaudited session.

Zero counters remain supported by the standard WebAuthn verifier. A nonzero
counter regression denies authentication, preserves the previous counter and
records a fixed warning; synced authenticators can trigger this signal without
proving a clone. Use password/TOTP or another key to investigate. A later valid
increasing assertion may authenticate; the visible warning is retained. The
server makes no hardware-binding, attestation-trust, or shared-device assurance.

Verification uses pinned `github.com/go-webauthn/webauthn v0.17.4` (BSD-3-Clause)
and its standard COSE/signature handling. Attestation preference is none and no
external metadata service is configured. No custom cryptographic verifier,
authenticator discovery network call, or external enrollment service is used.

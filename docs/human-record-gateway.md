# Human console with a connected record authority

An optional `httpAdminServer` gateway lets an existing local human administration realm manage one remote versioned record authority. Owner passwords, authenticators, recovery data, sessions and auth key remain in the original local auth store. No identities are copied to DNS nodes. Agent credentials keep their separate local scoped access.

Configure the listener's existing `authStore` and HTTPS `publicOrigin` bindings normally. In its `config`, replace the local `store` binding with:

```json
{
  "recordAuthorityURL": "http://127.0.0.1:18055/owned-static",
  "recordAuthorityTokenFile": "C:/private/existing-authority-token.private"
}
```

Keep this configuration private. `recordAuthorityTokenFile` references an existing absolute regular private file, read once during listener preparation (maximum512 token bytes, optional trailing CRLF). Symlinks are refused; Unix group/other permissions are refused, and Windows private ACLs must be verified during deployment. No file is created or permissions changed. An inline `recordAuthorityToken` is also supported, but exactly one credential source is allowed. Reuse an existing protected token file to avoid duplicate secrets. The upstream must be an explicit numeric loopback HTTP endpoint, normally an existing SSH forward with pinned host identity. The gateway does not establish or weaken that transport. Public network HTTP, DNS hostnames, redirects, arbitrary request-selected paths, local record bindings and follower-only mode are refused. The auth store must already exist; enabling this option neither creates an owner nor migrates any database. Preserve the existing TLS proxy/origin and auth DB/key when updating an installation. The original local records DB can remain retained but is not bound to this gateway listener.

The current appliance editor, human login/account UI and RouterOS import preview are served locally. The supported upstream operations are exactly GET/POST `/snapshot` and POST `/snapshot/rrset`. They use the same local human-cookie/origin/CSRF and scoped agent authorization as other admin operations; legacy bearer access to these gateway routes is refused. No browser cookies, CSRF values, origin or browser authorization header are sent upstream. A configured server-side authority credential is injected only for that fixed endpoint. The upstream sees the gateway credential, not the original human identity; this is not distributed identity or per-human upstream auditing.

Record contents, capability, ETag, provenance, CAS conflicts and commit/replay receipts come from the remote authority. The gateway never invents commits, writes its own record store, follows redirects or automatically retries. A dropped or oversized upstream response becomes a gateway error; a write may already have committed. The editor retains the frozen operation ID/body for explicit exact retry. Do not submit a fresh operation or restore a stale database to resolve uncertainty. Requests/responses are bounded to4MiB, with an8-second upstream timeout. Remote event streams, follower management, routing configuration and arbitrary HTTP forwarding are not exposed.

The local auth schema and passkey configuration remain unchanged. A future stable public hostname is independent of this existing HTTPS-origin integration. Test mutations belong only in disposable synthetic stores; live verification can read the actual snapshot and auth state without changing DNS records.

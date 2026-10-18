# Version History

## v1.9.1 - 2026.10.18

Restore Cross-platform Daemon Builds

This release fixes the optional authentication store's unconditional SQLite dependency,
which prevented v1.9.0 from building on 20 of the existing 46 daemon asset targets.
The v1.9.0 tag remains immutable; its release workflow failed before publishing any assets.

All 46 daemon targets are preserved. Authentication stores now use the same supported
platform boundary as record stores: Darwin amd64/arm64; FreeBSD amd64/arm64; Linux
386/amd64/arm/arm64/loong64/ppc64le/riscv64/s390x; Windows 386/amd64/arm64.
Android and iOS are excluded from SQLite-backed authentication support. On unsupported
platforms, opt-in auth key/store creation, opening and offline migrations fail explicitly
before filesystem effects. Configurations without an auth-store binding retain legacy
administration; there is no memory-store or unauthenticated fallback.

The 49-asset packaging contract is unchanged: 46 daemon binaries plus the Linux amd64,
Linux arm64 and Windows amd64 offline adminauth helpers. All 46 daemon targets were built
locally before this follow-up release. Human/agent/passkey behavior and explicit offline
auth-schema migrations remain as documented below; no running instance is upgraded or
initialized by these source changes.

## v1.9.0 - 2026.10.18

Opt-in Human and Agent Administration

This release adds node-local authentication stores and browser sign-in while preserving
legacy-token access and the behavior of configurations without an auth binding.

* scoped agents: dedicated credentials have exact realm/node audiences and explicit scopes.
  Agents can use the API and exchange credentials for bounded browser sessions, but cannot
  issue credentials or gain human authority. Cookie sessions use exact origin, CSRF and
  durable credential checks; ambiguous bearer/cookie requests refuse.
* human sign-in: password plus TOTP, ten one-use recovery codes, local QR enrollment,
  recent-authentication controls and explicit local recovery. Passwords use Argon2id;
  authenticator seeds are encrypted under the separate auth key. Agent and human sessions
  remain distinct, and recovery does not grant an agent human authority.
* optional passkeys: discoverable, user-verified WebAuthn enrollment, login and
  reauthentication for one exact configured HTTPS origin/RP. Nonzero counter regression
  denies and records a warning without claiming a clone. No hardware/attestation assurance
  or shared-node identity is implied. Password/authenticator recovery remains available.
* dependencies: update `golang.org/x/crypto` from v0.51.0 to v0.52.0, without claiming that
  the affected SSH code paths were reachable in prior secDNS behavior.

The built-in admin listener still does not terminate TLS. Network access needs a separately
protected HTTPS endpoint; this release does not provision certificates, DNS, or a portal.
Auth state is not replicated between nodes, and these changes do not deploy or initialize
any running instance.

Authentication schemas are separate from record-store schemas and never migrate at runtime.
With the owning process stopped, `migrate-schema1` advances auth schema 1 to 2; `enable-human`
advances schema 2 to 3; after initializing the human owner, `enable-passkeys` advances schema
3 to 4 and binds the exact origin/RP. Before each migration, preserve the auth database and
its matching key together as a private offline backup. Older binaries cannot open later
schemas. Reconcile uncertain outcomes before retrying; never blindly replay a migration.
Record databases, user DNS records and snapshot synchronization are outside these migrations.

The intended packaging (not published for v1.9.0) contains 49 assets: the unchanged 46 `secDNS` daemon binaries plus
`secdns-adminauth-linux-amd64`, `secdns-adminauth-linux-arm64`, and
`secdns-adminauth-windows-amd64.exe`. The helper is local/offline administration tooling,
not an HTTP service or remote credential-management endpoint. Other helper platforms can
be built from the tagged source.

See [scoped agent access](agent-admin-access.md), [human owner sign-in](human-admin-access.md),
[passkeys](passkey-admin-access.md), and the [auth-store contract](adminauth-core.md).

## v1.8.0 - 2026.10.18

Direct Exact-Record Synchronization

This release adds an opt-in path for copying a complete exact-record snapshot from one
explicitly trusted HTTPS publisher into a durable follower store, then serving changing
owner sets without regenerating static routing rules. Existing configurations retain their
previous behavior unless these stores, credentials, workers, and resolvers are configured.

* snapshot API: return a strong representation ETag on authenticated full-snapshot reads
  and honor standard `If-None-Match` list, wildcard, and weak-comparison semantics after
  authentication. A match returns an empty `304 Not Modified`; every `200` remains a full
  canonical envelope that the client must validate and durably accept.
* revision events: expose an authenticated, bounded Server-Sent Events stream of `advanced`
  and `resync` hints. Streams carry only identity and revision metadata, last at most 30
  seconds, and use finite subscription and buffer limits. Events are hints to fetch a full
  snapshot, never authoritative content or durable-write acknowledgements.
* direct followers: allow a configured follower store to fetch from one fixed HTTPS origin
  with a distinct read-only per-node credential and immutable enrollment tuple. Startup
  performs an unconditional full fetch before using an ETag. Later failures leave the last
  durably accepted generation serving, while an empty or invalid store fails closed.
* resolver: add `exactStoreOverlay` to answer owners present in one pinned writer or follower
  store generation and invoke an existing fallback graph once only when the original owner is
  absent. Startup rejects caches above the overlay and fallback caches shared across distinct
  source-policy roots, so accepted additions and removals are not hidden by stale final-answer
  cache entries.

Synchronization copies exact `A`, `AAAA`, `CNAME`, and `TXT` snapshots only. It does not copy
listeners, resolver graphs, source policy, DNS64 policy, routing, credentials, or general node
configuration. This is a direct trusted-publisher mode using ordinary Go TLS verification; it
does not integrate signed-snapshot verification, the separate durable trust/mirror design,
writer election, discovery, redirect following, CA provisioning, deployment, or automatic
upgrade of existing instances. The built-in admin listener does not terminate TLS, so a
separately configured protected HTTPS management endpoint is required for network use.

The release workflow continues to publish the 46 existing `secDNS` platform binaries. See the
[versioned authority API](versioned-authority-api.md),
[direct follower synchronization](direct-follower-sync.md), and
[`exactStoreOverlay` resolver](resolvers/exact_store_overlay.md).

## v1.7.0 - 2026.10.18

Opt-in Client Source Resolver Selection

* listeners: allow UDP and TCP DNS listeners to opt into resolver selection from the
  directly connected socket peer. The top-level source policy uses exact CIDR members,
  optional expiry, ordered rules for each listener role, and a required explicit default.
  Selection runs before resolution and cache lookup; missing peer identity, unknown roles,
  partial configuration, and invalid references fail closed. Configurations that omit the
  feature retain their existing listener behavior.
* configuration: validate every selected resolver graph and reject cycles, unsupported
  dependency shapes, and concrete cache objects shared by distinct selected resolver names.
  This keeps final-answer caches isolated without changing the legacy cache-key format.
* admin: optionally expose a bearer-authenticated source-policy explanation endpoint. Its
  strict request is limited to 4 KiB and requires an explicit listener role, synthetic client
  address, and evaluation instant. The response reports the immutable policy fingerprint and
  selection reason without resolving a name, reading a cache or store, contacting a network,
  or revealing source-set members.

Source identity is limited to the UDP or TCP socket peer. The feature does not reconstruct an
original client from EDNS Client Subnet, proxy headers, or address translation; authenticate a
source inventory; reload policy dynamically; synchronize policy between instances; import
router or client inventory; or change interfaces, routes, or egress. The explanation endpoint
is diagnostic only and this release does not add a browser form for it. See
[listener resolution policies](listener-resolution-policies.md) and the
[admin listener](listeners/http_admin_server.md).

The release workflow continues to publish the 46 existing `secDNS` platform binaries, which
include the source selector, listener integration, and optional admin diagnostic. The
`cmd/routeros-dns-preview` command remains a source-tree tool and is not published as a
separate release asset.

## v1.6.4 - 2026.10.18

Operator Provenance and Aggregate Import Coverage

* tooling: add `--coverage-only` to the source-tree RouterOS exact conversion command. It
  runs the same whole-source compiler and reports bounded aggregate diagnostic/blocker counts
  without source fields, names, values, comments, bindings or candidate content. Refused input
  still exits nonzero and yields no content hash or partial candidate.
* admin: preserve the fixed strict profile, source SHA-256 and canonical content SHA-256 as
  operator-supplied provenance when an unchanged transferred candidate is explicitly submitted.
  GET and POST keep their existing bodies and expose the tuple through three response headers;
  any local edit, including edit then revert, omits the original tuple.
* storage: new versioned SQLite stores use schema 3 with bounded canonical nullable provenance
  blobs and request-digest binding. Existing schema-2 stores open in legacy-compatible mode and
  continue legacy replacements without a rewrite. Tuple-bearing writes are refused until an
  explicit library caller opts into the atomic schema-2-to-3 migration.

Runtime configuration does not expose or enable schema migration, so this release never
automatically upgrades an existing database. Operational migration still requires separate
authorization and the normal pre-migration backup; older binaries cannot open schema 3. The
stored source/profile tuple is an operator assertion, not proof of RouterOS authenticity,
compiler provenance, policy parity, or apply authorization.

The release workflow continues to publish the 46 existing `secDNS` platform binaries. The
embedded admin/editor and provenance storage behavior are included in those binaries. The
`cmd/routeros-dns-preview` coverage command remains a source-tree tool and is not published as
a separate release asset. See the [RouterOS import preview](routeros-import-preview.md),
[versioned authority API](versioned-authority-api.md), and
[versioned exact store](versioned-exact-store.md).

## v1.6.3 - 2026.10.18

Exact Import Draft Handoff and Address Resolver Options

* admin: add strict exact conversion to the authenticated RouterOS import page. It requires
  an explicit ruleset ID and either returns the complete canonical A, AAAA, and CNAME
  candidate or refuses the complete source with blockers and no candidate content.
* admin: allow an operator to explicitly transfer a successful exact candidate into the
  originating versioned editor's clean local draft. The same-origin memory channel carries no
  credential and performs no store request. The editor records source and content hashes,
  preserves dirty or busy work, and retains its existing complete-snapshot review, revision
  check, explicit confirmation, and exact-retry behavior. Nothing is applied automatically.
* resolver: let the static `address` resolver use an optional uint32 TTL and opt-in
  fallthrough for unsupported query types or an absent address family. Existing string/list
  forms and object defaults retain TTL 60 and the previous empty-response behavior.

The release workflow continues to publish the 46 existing `secDNS` platform binaries. The
embedded authenticated pages and address-resolver behavior are included in those binaries.
The `cmd/routeros-dns-preview` command remains a source-tree tool and is not published as a
separate release asset.

Strict conversion still supports literal static DNS records only. It does not prove that a
pasted source is a complete router export, translate the full RouterOS policy surface, contact
a router, or bypass the versioned editor's review and revision-aware replacement flow. See the
[RouterOS import preview](routeros-import-preview.md),
[versioned records editor](versioned-authority-api.md#optional-snapshot-editor), and
[address resolver](resolvers/address.md).

## v1.6.2 - 2026.10.18

RouterOS Import Review and Exact Conversion

This release adds an optional authenticated browser page for reviewing RouterOS DNS-static
exports and a strict source-tree conversion command. Existing configurations and the default
preview command behavior are unchanged.

* admin: add a read-only RouterOS import preview page for file or pasted input. The page is
  available only when the authenticated admin UI is explicitly enabled, shows the complete
  bounded source report and diagnostics, and does not apply, store, or send records.
* tools: add strict exact-record conversion to
  `go run ./cmd/routeros-dns-preview --compile-exact --ruleset-id <id>`. Conversion requires the
  complete submitted source; requires explicit type, TTL, enabled state, and exact matching;
  canonicalizes supported A, AAAA, and CNAME records; and refuses unsupported policy,
  duplicate/conflicting data, CNAME cycles, or incomplete input. A refused conversion reports
  blockers and emits no candidate content.
* tooling: exact conversion reports source and content identities, ruleset bindings, and
  `can_apply: false`. It does not create a revision, compare current state, or perform an apply.

The release workflow continues to publish the 46 existing `secDNS` platform binaries. The
authenticated preview page is included in those binaries. The RouterOS preview/conversion
command remains a source-tree command and is not published as a separate release binary.

The strict exact profile supports literal static DNS records only. It does not translate the
full RouterOS DNS policy surface, prove that a pasted export is a complete router export, contact
a router, or mutate a store. See the [RouterOS import preview](routeros-import-preview.md).

## v1.6.1 - 2026.10.18

Readable Versioned Record Comparison

* admin: show readable base, local draft and observed server records side by side,
  with separate local/server change labels, exact values, TTL and expiration.
  Show changed rows by default, with an unchanged-row toggle, raw JSON disclosure
  and a layout that stacks on mobile screens.
* internal: add an inactive, bounded signed-snapshot verifier and interoperability
  tests for later integration. It requires caller-supplied trusted keys and clock;
  this release adds no synchronization transport or durable trust store.

Comparison controls do not change drafts or submit requests. Existing revision
checks, exact retries and explicit discard/reload behavior remain unchanged.
The optional editor remains disabled by default. See the
[versioned records editor](versioned-authority-api.md#optional-snapshot-editor).

## v1.6.0 - 2026.10.18

Persistent Records and Listener Resolution Policies

This release adds optional persistent record stores, versioned batch editing, and
per-listener resolver selection. Existing configurations keep their default in-memory
record stores and global resolver selection. New storage modes and editors require
explicit configuration.

* listeners: select a named or inline resolver for each DNS or HTTP query listener. The
  new policy resolver combines rules with a default resolver, with dependency and cycle
  validation before listeners start. UDP response sizing now applies consistently to
  `udp`, `udp4`, and `udp6` listeners.
* authoritative: optionally complete A/AAAA CNAME chains within the same record store,
  preserving record TTLs and bounded chain handling. The default remains disabled.
* records: optionally persist named legacy stores in SQLite, with strict startup
  validation, exclusive database ownership, and absolute expiration retained across
  restarts. Admin mutations validate record data and CNAME conflicts atomically.
* records: add explicitly configured versioned stores for complete A, AAAA, CNAME, and
  TXT snapshots. Authenticated batch replacement checks the expected revision and retains
  operation receipts for exact retries. A query reads one immutable generation across its
  same-store CNAME chain. Versioned records preserve TTL zero, ordered TXT chunks, and
  exact absolute expiration values.
* admin: add optional embedded editors for legacy records and versioned snapshots. The
  versioned editor stages local changes, reviews the complete replacement, preserves dirty
  drafts on refresh, and retains the identical request for explicit retry after an
  uncertain result. Editors are disabled by default; administration still requires a
  bearer token and a protected management transport.
* config: make configuration test mode reject reported rule-input failures. Repeated or
  concurrent configuration loads are isolated, and test mode validates storage settings
  without creating databases.
* tools: add a source-tree RouterOS DNS-static preview command,
  `go run ./cmd/routeros-dns-preview`. It reads a restricted literal export from standard
  input, retains unsupported-policy diagnostics, and never applies records or contacts a
  router. It is not a separate release binary.
* internal: add enrolled follower snapshot persistence and strict reopen/failure handling
  for later integration. This internal component has no runtime configuration or
  synchronization transport in this release.

The release continues to publish all 46 existing platform binary names. SQLite
persistence is available on macOS amd64/arm64; FreeBSD amd64/arm64; Linux 386, amd64, arm,
arm64, loong64, ppc64le, riscv64, and s390x; and Windows 386, amd64, and arm64. Other
published targets retain in-memory operation and report SQLite persistence as unavailable.
A configured database is never silently replaced by memory.

Memory stores remain volatile. Versioned enrollment is explicit, and normal startup does
not convert a legacy database. Editor drafts and pending retries live only in page memory;
clearing local work cannot undo an already dispatched server write. Listener selection
does not configure host addresses, routes, or translation. Cluster synchronization,
source-address policies, routing/network management, and a routing GUI are outside this
release.

Source documentation: [listener resolution policies](listener-resolution-policies.md),
[authoritative resolver](resolvers/authoritative.md), [record stores](record-stores.md),
[versioned authority API](versioned-authority-api.md),
[RouterOS import preview](routeros-import-preview.md), and
[follower snapshot store](follower-snapshot-store.md).

## v1.5.1 - 2026.06.05

Config-Load Isolation Fix

This release fixes a latent bug in configuration loading. Configuration is
backward-compatible.

* config: clear the pending named-resolver list between loads. A string resolver
  reference (a `defaultResolver` or rule `"name"`) is appended to a process-global pending
  list while a config is described, and resolved at the end of the load. That list was
  cleared only when the load succeeded; a not-found reference returned early and left its
  entry behind, so a subsequent load in the same process re-processed — and re-failed on —
  a name from the earlier failed config. The list is now cleared on every exit of the
  resolve step and at the start of each load. secDNS loads one config per process in normal
  operation, so this changes no runtime behavior; it makes repeated loads correct (and the
  test suite order-independent).

## v1.5.0 - 2026.06.05

Authoritative Resolver and Admin API

This release adds the ability to answer DNS authoritatively from a process-local record
store, populated dynamically over a bearer-authenticated HTTP admin API — for serving
records such as ACME DNS-01 `_acme-challenge` TXTs without running a second daemon.
Configuration is backward-compatible: the new behavior is inactive unless an
`authoritative` resolver or `httpAdminServer` listener is configured.

* resolvers: add an `authoritative` resolver. It answers from a shared, in-memory,
  TTL-aware record store instead of forwarding upstream — returning the store's record for
  a name, a stored `CNAME` for a query of any other type, `NODATA` (NOERROR) when the name
  exists for another type, and `NXDOMAIN` otherwise, each negative answer carrying a
  synthesized `SOA` (configurable `negativeTTL`) for downstream negative caching. Supported
  types are `TXT`, `A`, `AAAA`, and `CNAME`; answers are unsigned. Stores are shared by
  name (`store`, default `default`), so a resolver and an admin listener that name the same
  store operate on one record set.
* listeners: add an `httpAdminServer` listener — a bearer-authenticated HTTP admin API
  (`POST`/`DELETE`/`GET {path}/records`) that populates the record store the `authoritative`
  resolver answers from. It binds loopback by default and fails closed, refusing to serve
  without a configured `token`; the token is compared in constant time, a missing or
  malformed `Authorization` header is `401` and a wrong token `403`. Record writes accept a
  DNS TTL (`ttl_seconds`) and an optional store lifetime (`expires_in_seconds`) after which
  the record is auto-removed. Names, record types, and IP values are validated.
* docs: add `docs/resolvers/authoritative.md`, `docs/listeners/http_admin_server.md`, and
  an end-to-end ACME DNS-01 example (`examples/acme-dns01-config.json`).

## v1.4.6 - 2026.06.05

Concurrent Glue Resolution

This release resolves the IPv4 and IPv6 addresses of a nameserver concurrently when
chasing a glueless referral, cutting glue-resolution latency. Configuration is
backward-compatible.

* recursive: resolve A and AAAA glue addresses concurrently. Chasing a glueless referral
  previously resolved each nameserver's A address and then its AAAA address in series, so
  the slower of two independent sub-resolutions was paid twice over per name. The two are
  now resolved in parallel and joined, roughly halving the latency of a glue chase. The
  per-query resolution budget the two share is now an atomic counter claimed with a single
  decrement, so exactly the configured number of upstream exchanges still succeeds under
  the fan-out, and the live goroutine count stays bounded by the remaining budget (every
  spawned exchange charges the budget before running).

## v1.4.5 - 2026.06.05

Per-Query Resolution Budget

This release adds a global per-query work-and-time budget to the recursive resolver,
bounding the total upstream traffic a single client query can trigger. Configuration is
backward-compatible.

* recursive: cap per-query work with a global resolution budget. `maxDepth` and
  `maxReferrals` bound how *deep* iterative resolution recurses, but not how *wide* — a
  referral can branch into an out-of-band glue chase per nameserver, and each chase is
  itself a full resolution from the roots, so a maliciously glueless or deeply nested
  delegation could fan a single client query out into exponentially many upstream
  exchanges. A per-query budget, shared across the whole iterative tree (referrals, CNAME
  restarts, and glue chasing all draw from one counter), is now charged at the single
  upstream-exchange chokepoint; when it is spent the query is answered SERVFAIL. Two new
  options configure it: `maxQueries` (default 256, the total upstream exchanges allowed
  per query — generous for any legitimate resolution but finite) and `maxResolutionTime`
  (default 30 seconds, a wall-clock backstop for the whole query that complements the
  per-exchange `timeout`; set 0 to disable). Background scoreboard probes are not on this
  path and are unaffected, and each DNSSEC DNSKEY/DS validation fetch is bounded
  independently of the main query's budget.

## v1.4.4 - 2026.06.05

Resource Bounding, Diagnostics, and Operability

This release bounds two previously unbounded resolver caches, adds a fast path to the
core dispatcher, makes a strict-mode DNSSEC SERVFAIL diagnosable, gives malformed
configurations a locatable error, fixes the process exit code on a failed startup, and
hardens the HTTP API and dnsmasq-conf provider against malformed input. Configuration is
backward-compatible.

* recursive: bound the glue and trusted-key caches. The out-of-band glue cache and the
  DNSSEC trusted-key cache grew without limit, so a long-running resolver chasing many
  distinct delegations could accumulate entries indefinitely. Both now carry a maximum
  size and prune expired (then oldest) entries on insert once full. Dead writes of unused
  `dnskey:`/`ds:` cache keys — written but never read — were removed.
* core: fast-path `instance.Resolve` when no named resolvers are configured. The
  dispatcher canonicalized the query name, split it into labels, and walked the domain
  hierarchy under a per-level read lock on every query — even for the common config that
  has only a default resolver and no rules. An atomic flag, set when the first named
  resolver is registered, now skips all of that and calls the default resolver directly;
  the hierarchy walk (when named resolvers do exist) slices the canonicalized name at
  label offsets instead of re-joining the label slice per level, removing the per-level
  allocation.
* recursive: surface the reason a strict-mode answer is classified bogus. A failed DNSSEC
  validation was mapped to the `Bogus` state but the explanatory error was discarded, so a
  strict-mode `SERVFAIL` had no operator-visible cause. The reason — query name, type, and
  error — is now logged at debug (gated behind `--log-level debug`, so the default level is
  not flooded). The missing-signature (insecure) case, which is served rather than
  SERVFAILed, stays silent.
* config: locate the offending entry on a rejected configuration. A malformed config
  produced a single opaque `Bad config` error. A diagnostic pass — run only when the
  loader rejects the file — now reports the first locatable cause: a non-object root, a
  section that should be an array but is not, or a `listeners`/`defaultResolver` entry that
  is missing its `type`, declares an unknown type, or carries an invalid config block,
  named by section and array index (for example, `config: listeners index 1: unknown type
  "bogusListener"`). The pass mirrors the loader's own accept/reject decisions, so it never
  reports a problem the loader would tolerate, and falls back to the original error when it
  cannot pin down a cause.
* cli: exit non-zero when startup fails. Starting with no config file and no discoverable
  `config.json` printed the usage text and exited 0, which a process supervisor reads as a
  clean exit — so a server that never started looked like one that ran and finished. A
  missing config is now a usage error (exit 2) and a named-but-unopenable or invalid config
  is a startup failure (exit 1); the missing-config message names the ways to point secDNS
  at a config.
* http-api: guard the `/resolve` endpoint against malformed replies. A reply from the
  resolver chain carrying a nil resource record in a section panicked the handler while
  building its JSON; nil records are now skipped, and a recover surfaces a clean `502`
  rather than crashing the request. Query names that are not representable as a DNS name
  (empty interior labels, labels over 63 octets) are rejected up front with `400`, in
  addition to the existing 255-octet length cap.
* dnsmasq: bound the configuration scanner. The line scanner used the default 64 KiB token
  limit, at which a longer line aborts the whole scan and silently drops every remaining
  entry; the line buffer is raised to 1 MiB. A runaway entry-count backstop — far above any
  real adblock list — reports a truncation error rather than truncating silently if the
  configured path points at the wrong file.

## v1.4.3 - 2026.06.04

Concurrency Correctness and Recursive-Resolver Stability

This release fixes data races in the concurrent and conditional-filter resolvers, hardens
the recursive resolver against premature failure and out-of-band glue amplification, and
activates a runtime log-level control. Configuration is backward-compatible.

* resolvers: fix a data race in concurrent fan-out. `concurrentNameServerList` launched a
  goroutine per child but passed all of them the same `*dns.Msg`; because the
  `filterOutAIfAAAAPresents`/`filterOutAAAAIfAPresents` resolvers (valid list members)
  mutate the query in place to probe the opposite record type, a child rewriting the
  question raced a sibling reading the shared message. The list now hands each child its
  own `query.Copy()`, and the two filters probe on a private copy instead of mutating the
  shared message in place.
* recursive: a single server's SERVFAIL/FORMERR no longer short-circuits the
  sibling-server loop. Previously NXDOMAIN, SERVFAIL, and FORMERR were grouped into one
  case that returned the first server's response immediately, so one flaky server turned
  every query routed through it into SERVFAIL. NXDOMAIN still returns immediately
  (definitive non-existence); a SERVFAIL/FORMERR is now remembered as a fallback while the
  loop tries the remaining servers, and is surfaced only after every server has failed.
* recursive: bound out-of-band glue resolution. Chasing glue for a glueless referral
  previously restarted iterative resolution at a fresh `maxDepth` budget per NS name with
  the NS list uncapped, so a chain of glueless referrals could recurse without a monotonic
  bound and amplify one client query into runaway upstream traffic. Glue lookups are now
  charged against the caller's remaining recursion depth (decremented down the tree, never
  reset), a depth-exhausted referral chases no glue, and the NS names chased per referral
  are de-duplicated and capped at six.
* logging: add a `--log-level` flag (and `SECDNS_LOG_LEVEL` environment variable) that sets
  verbosity to `trace`, `debug`, `info`, `warn`, `error`, or `off` (with `warning`,
  `quiet`, and `none`/`disabled` aliases); values are case-insensitive. The level machinery
  already existed but nothing called it, pinning output to the `warn` default and hiding
  every Info/Debug message. The flag takes precedence over the environment variable, an
  unrecognized value warns and keeps the default rather than aborting, and the level is
  applied before config load so config-load errors honor it. The loaded config source is
  now logged at info level.

## v1.4.2 - 2026.06.04

Cache Correctness and Performance

This release fixes a cache data-loss bug, removes the cache's per-hit lock contention,
and adds upstream connection reuse. Configuration is backward-compatible.

* cache: fix a data-loss bug where a refreshed entry could be deleted by a stale
  expiration-heap item left behind by an earlier (shorter) TTL — cleanup now acts only
  on the heap item whose expiry matches the entry's current expiry, so a re-cached entry
  is no longer evicted prematurely when serve-stale is disabled.
* cache: bound stale-refresh fan-out. Serving stale for a hot name previously spawned a
  goroutine per request (two, in fact — a redundant wrapper); refresh is now a single
  goroutine gated by the entry's prefetch flag, capping in-flight refresh at one per
  entry.
* cache: remove the exclusive lock taken on every cache hit. Each hit re-acquired the
  cache's writer lock solely to move the entry to the LRU front, serializing concurrent
  hits. Hits now set a CLOCK / second-chance "referenced" bit with a single atomic store
  (no lock), and eviction uses a bounded second-chance scan. Concurrent cache-hit
  throughput improves several-fold on multi-core hosts (about 5.7x at 12 cores in the
  parallel-hit benchmark).
* cache: bound the expiration heap. Frequent re-caching accumulated duplicate heap items;
  the heap is now rebuilt from the live entries once it exceeds about twice the entry
  count, keeping it bounded by the live entry count.
* nameServer: reuse TCP and DoT (tcp-tls) connections from a small bounded idle pool
  instead of dialing — and, for DoT, completing a TLS handshake — on every query. UDP is
  unchanged. Reuse is one outstanding query per connection and relies on the existing
  per-query random transaction ID to discard any stale response on a reused connection.

## v1.4.1 - 2026.06.04

DNSSEC Denial-of-Existence and Resolver Availability Hardening

This release completes the denial-of-existence rework promised in v1.4.0 and fixes a
critical defect that made `strict` validation reject every signed negative answer. It
also closes a chain-of-trust downgrade and removes a startup stall on hosts with a broken
address family. Configuration is backward-compatible and the shipped default policy
remains `permissive`.

* recursive: **fix a critical defect where `strict` validation SERVFAILed every signed
  NXDOMAIN/NODATA answer.** The RRSIG covering the SOA (always present in a negative
  authority section for negative caching) was collected as a denial proof record, leaving
  an orphan signature that failed strict verification. Only NSEC/NSEC3-covering RRSIGs are
  now treated as proof records; the SOA's own signature is still validated separately.
* recursive: require an authenticated DS-absence proof from a secure parent before
  treating a child delegation as insecure (RFC 4035 section 5.2, RFC 6840). A missing DS
  RRset is now backed by the parent's signed NSEC (NS set, DS/SOA clear) or NSEC3 (matching
  or opt-out span, RFC 5155 section 6) proof; otherwise the answer is Bogus, closing an
  on-path DS-stripping downgrade of a secure zone to unsigned.
* recursive: derive the NSEC NXDOMAIN closest encloser from the NSEC that actually covers
  the name and compare names in DNSSEC canonical order (RFC 4035 section 5.4 / RFC 4034
  section 6.1), so a single covering NSEC plus an apex-wildcard NSEC can no longer forge
  NXDOMAIN for a wildcard-answerable name.
* recursive: enforce the NSEC3 NXDOMAIN next-closer constraint (RFC 5155 section 8.3) —
  require a matching closest encloser, a covering NSEC3 for the next closer name, and a
  covering NSEC3 for the wildcard — instead of accepting any NSEC3 that covers the queried
  name.
* recursive: do not stall on a broken address family. The best-effort root probe ran
  synchronously on the first query and blocked on dead servers (e.g. unreachable IPv6) for
  the full timeout budget; it now runs in the background and probes roots concurrently.
  Server selection prefers the configured family (IPv4 by default) on a cold scoreboard,
  always keeps at least one server of each available family in the candidate set, and
  scores round-trip times in consistent units so a proven-fast server outranks an untried
  one.

## v1.4.0 - 2026.06.02

DNSSEC Validation Hardening

This release reworks the recursive resolver's DNSSEC validation around an explicit
security status and closes several forgery and availability defects. Configuration is
backward-compatible and the shipped default policy remains `permissive`; documentation
recommends `strict`, which is now functional. Further denial-of-existence hardening
(authenticated insecure-delegation proofs, NSEC/NSEC3 NXDOMAIN/NODATA correctness)
continues in a follow-up release.

* recursive: validate the terminal answer against an explicit Secure/Insecure/Bogus
  status. The AD bit is set only when the answer is Secure, the client requested DNSSEC
  (the DO or AD bit was set), CD is not set, and the whole Answer+Authority is authentic
  (RFC 4035 / RFC 6840). Unsigned (insecure) zones are served without AD instead of being
  SERVFAILed under `strict`; `strict` SERVFAILs only genuinely bogus answers. Adds the
  `honorClientCD` option (default `true`, RFC 4035 section 3.2.2).
* recursive: concurrent queries that differ only in their CD or DO bit no longer share a
  validation result — the singleflight key includes CD and DO, and the AD/SERVFAIL
  decision is stamped on a per-waiter copy.
* recursive: enforce signer bailiwick (RFC 4035 section 5.3.1) on every signature used,
  closing a cross-zone-signer forgery that `miekg/dns` `RRSIG.Verify` does not catch.
* recursive: bind the parent DS to the DNSKEY that actually signs the zone's DNSKEY
  RRset (RFC 4035 section 5.2), closing an append-extra-key forgery.
* recursive: treat a zone whose DS uses only an unsupported signing algorithm or digest
  type as Insecure (RFC 6840 section 5.2 / RFC 8624) instead of SERVFAIL.
* cache: fix a data race between prefetch reads and entry updates on cached entry fields.

## v1.3.11 - 2026.06.02

Security / Hardening

* nameServer: accept header-only error replies (FORMERR/SERVFAIL/REFUSED/NOTIMP that omit
  the question) so they are surfaced immediately instead of stalling until the query
  timeout; bound the response read loop against spoofed-datagram floods.
* dns64: do not advertise DNSSEC authentication for synthesized AAAA — drop the A RRset's
  RRSIGs from the answer and clear the AD bit (RFC 6147 section 5.5).
* dnsServer: truncate oversized UDP responses to the requestor's EDNS/512 size with the TC
  bit set, closing a reflection/amplification vector; synthesize SERVFAIL for a nil reply.
* httpAPIServer: add Read/Write/Idle/Header timeouts and an `http.MaxBytesReader` body limit
  (Slowloris and memory hardening); reject names longer than 255 octets.
* dnsServer: recover handler panics into SERVFAIL so a resolver-tree defect cannot crash the
  process.

## v1.3.10 - 2026.06.02

Bug Fixes

* recursive: build each `recursive` resolver from independent configuration instead of a shared
  default instance, and default `validateDNSSEC`/`qnameMinimize`/`ednsSize` when omitted. Configs
  that leave those keys out now load (including the documented minimal example), and a `strict`
  resolver no longer silently behaves as `permissive` when another recursive resolver is configured.
* nameServer: validate upstream responses against the query (transaction ID and question section,
  case-insensitive name per RFC 4343) and randomize the upstream transaction ID per query, so a
  spoofed or mismatched datagram is no longer accepted as the answer.
* dns64: guard queries with no question section (previously a panic), synthesize on copies of both
  the query and the upstream reply (no caller/upstream mutation), and only synthesize on a NOERROR
  answer with no AAAA records so `SERVFAIL`/`REFUSED`/`NXDOMAIN` are no longer masked.
* core: report the correct version (the constant was left at `1.3.8`).

## v1.3.9 - 2026.01.19

Bug Fixes

* HTTP API: validate numeric qtype/qclass inputs to avoid overflow when parsing numeric values.
* Cache: bound cache-control TTL override parsing to uint32 and ignore invalid values.

## v1.3.8 - 2025.12.07

Bug Fixes

* Rules: canonicalize rule keys and lookups so domain matching is case-insensitive (including literal quoted rules) across collection and dnsmasqConf providers; added regression tests.
* Core: ensure rule map deduplication is performed on canonical names to avoid duplicate entries that only differ by case.

## v1.3.7 - 2025.12.06

Changes

* Cache: add configurable upstream request limiting (`maxConcurrentRequests`, `maxQueuedRequests`, `requestQueueTimeout`) to prevent bursty misses/prefetches from flooding upstream resolvers; defaults set to 256/512/1s.
* DoH: document connection pool and concurrency defaults alongside existing tuning options.
* Bump version to 1.3.7.

## v1.3.6 - 2025.12.04

Bug Fixes

* DoH URL resolution now wraps IPv6 literals in brackets when no port is specified, preventing bad host lookups during HTTPS dial.

## v1.3.5 - 2025.12.03

Changes

* DoH upstream URL resolution now queries both A and AAAA records, allowing IPv6 endpoints to be discovered automatically.

## v1.3.4 - 2025.12.03

Changes

* Added regression tests to ensure ECS defaults are treated as strings for DoH, nameServer, recursive, and ecs resolvers.
* Config loader now includes the list of registered resolver names when a named resolver lookup fails, making misconfigurations easier to diagnose.

## v1.3.2 - 2025.12.03

Changes

* Removed the cache `warmupQueries` option; cache now relies on runtime traffic and prefetch to build entries.
* Moved the HTTP API server package to `internal/listeners/servers/http/api/server` to align with other listeners.
* Updated documentation and agent metadata for the 1.3.2 release, including HTTP API notes.

## v1.3.1 - 2025.12.01

Enhancements

* Recursive: fall back to TCP when UDP exchange fails, use embedded root hints when `rootServers` is omitted, and normalize ECS handling.
* Cache: key ECS responses by response scope and fall back to source prefix when scope is zero; tuned default config for recursive use.
* HTTP API: hide raw data by default; add `raw` and `simple` response options; simple mode filters to the requested qtype and returns parsed values; additional/authority now carry data when value is empty.

## v1.3.0 - 2025.11.30

New Features

* Add [recursive](resolvers/recursive.md) resolver: DNSSEC-validating recursion with root hints, adaptive nameserver ranking, singleflight, loop/referral/CNAME limits, authoritative NODATA short-circuiting, SOCKS5/bind support, and ECS passthrough/add/override/strip propagation.
* Add [ecs](resolvers/ecs.md) resolver: applies EDNS Client Subnet policy (passthrough/add/override/strip, including strip support on release) before delegating, so ECS variants can share downstream caches.

## v1.2.1 - 2025.11.27

New Features

* Add [httpAPIServer](listeners/http_api_server.md), an HTTP listener that exposes DNS resolution via `/resolve` endpoints accepting GET/POST (form or JSON) requests and responding with structured JSON payloads.
* Extend [cache](resolvers/cache.md) resolver with TTL jitter, per-domain statistics, EDNS cache-control hints, and configurable prefetch/stale-serving controls.

Enhancements

* Added descriptor options for cache prefetch, documented new usage patterns, and exposed per-domain stats APIs.

## v1.2.0 - 2025.11.08

New Feature

* Add high-performance DNS caching resolver with LRU (Least Recently Used) eviction policy, providing significant latency
  reduction and upstream load optimization.
* Support configurable cache size limits with automatic LRU eviction when maximum entries reached.
* Support TTL management with configurable min/max TTL overrides to prevent excessively short or long caching periods.
* Support negative caching (NXDOMAIN and NODATA) per RFC 2308 to reduce upstream queries for non-existent domains.
* Support background cleanup of expired cache entries with configurable cleanup intervals.
* Thread-safe implementation optimized for high-concurrency read operations with O(1) cache lookups and LRU operations.
* Add comprehensive cache statistics tracking (hits, misses, evictions, size, hit rate).
* Add detailed [cache resolver documentation](resolvers/cache.md) with configuration examples and best practices.

Performance

* Cache hit latency: ~585 ns (0.0006 ms) - nearly instant response from cache.
* LRU operations: O(1) constant time for add, remove, and move-to-front.
* Zero lock contention for concurrent cache reads using sync.RWMutex.
* Memory efficient: ~500-1000 bytes per cached entry depending on response size.

## v1.1.9 - 2025.11.07

New Feature

* Add EDNS Client Subnet (ECS) support as defined in RFC 7871 for [nameServer](resolvers/name_server.md) and
  [doh](resolvers/doh.md) resolvers. ECS enables geographic load balancing and optimized DNS responses by including client
  subnet information in queries.
* Support three ECS handling modes: `passthrough` (default, no modification), `add` (add ECS if not present), and
  `override` (always replace ECS with configured value).
* Support both IPv4 and IPv6 client subnets in CIDR notation.
* Add comprehensive [EDNS Client Subnet](edns_client_subnet.md) documentation with configuration examples and use cases.

## v1.1.8 - 2025.11.07

Bug Fixes

* Fix critical race conditions in [doh](resolvers/doh.md) and [nameServer](resolvers/name_server.md) resolvers
  using sync.Once for thread-safe client initialization.
* Fix race condition in core instance map using sync.RWMutex for concurrent reads/writes.
* Fix HTTP response body resource leak in [doh](resolvers/doh.md) resolver.
* Fix unbounded goroutine spawning in error handlers.
* Fix potential deadlock in [doh](resolvers/doh.md) error collector channel.

Enhancements

* Add EDNS0 support (UDPSize: 4096) to [nameServer](resolvers/name_server.md) resolver for handling large DNS responses
  over UDP (large TXT records, long CNAME chains).
* Add automatic TCP fallback when UDP responses are truncated, with graceful degradation if TCP fails.
* Optimize TCP fallback with client caching to eliminate repeated allocations (67% memory reduction for large-response
  workloads).
* Maintain full SOCKS5 proxy support in TCP fallback for all protocols (UDP, TCP, TCP-TLS).

Performance

* Zero race conditions detected with Go race detector.
* 99.95% latency improvement for TCP fallback client selection (2ms -> 0.001ms).
* Thread-safe with sync.Once providing minimal overhead (~1-5ns atomic load).

## v1.1.7 - 2025.11.07

Enhancement

* Enable [sequence](resolvers/sequence.md), [dns64](resolvers/dns64.md), and filter resolvers
  ([filterOutA](resolvers/filter_out_a.md), [filterOutAAAA](resolvers/filter_out_aaaa.md),
  [filterOutAIfAAAAPresents](resolvers/filter_out_a_if_aaaa_presents.md),
  [filterOutAAAAIfAPresents](resolvers/filter_out_aaaa_if_a_presents.md))
  to be used in [concurrentNameServerList](resolvers/concurrent_name_server_list.md)
  by implementing the nameserver.Resolver interface.

## v1.1.6 - 2024.11.13

New Feature

* Support conditional resource record filtering for A and AAAA by adding new
  resolvers [filterOutAIfAAAAPresents](resolvers/filter_out_a_if_aaaa_presents.md)
  and [filterOutAAAAIfAPresents](resolvers/filter_out_aaaa_if_a_presents.md).

Naming Fixes

* Rename resolver filterA to [filterOutA](resolvers/filter_out_a.md) for better comprehensibility.
* Rename resolver filterAAAA to [filterOutAAAA](resolvers/filter_out_aaaa.md) for better comprehensibility.

## v1.1.5 - 2022.02.05

New Features

* Add multiple addresses support for [address](resolvers/address.md) resolver.
* Support resource record filtering for A and AAAA by adding new resolvers [filterA](resolvers/filter_out_a.md)
  and [filterAAAA](resolvers/filter_out_aaaa.md).

Bug Fix

* Fix a bug in [address](resolvers/address.md) resolver which might cause error in type of answered resource records.

## v1.1.4 - 2021.07.22

New Feature

* Add SOCKS5 proxy support for [nameServer](resolvers/name_server.md) and [doh](resolvers/doh.md).

## v1.1.3 - 2021.07.20

New Feature

* Add an option in [doh](resolvers/doh.md) configuration to allow specifying a resolver for URL resolution.

Bug Fix

* Fix a bug in [doh](resolvers/doh.md) resolver which might cause infinite name resolution when domain names are used
  instead of IP addresses in URLs of DoH services.

## v1.1.2 - 2020.10.20

Bug Fix

* Fix a bug in [doh](resolvers/doh.md) resolver where queries don't fail when error occurs.

## v1.1.1 - 2020.10.19

Bug Fix

* Fix a bug in [nameServer](resolvers/name_server.md) resolver where UDP queries don't time out and fail when the server
  ignores the queries.

## v1.1.0 - 2020.03.26

New Feature

* Support DNS64 by adding a new [dns64](resolvers/dns64.md) resolver.

## v1.0.0 - 2020.03.07

Initial Release

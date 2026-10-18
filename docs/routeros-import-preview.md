# RouterOS DNS-static import preview

`go run ./cmd/routeros-dns-preview < dns-static.rsc` reads a DNS-static export from
standard input and writes a JSON preview. It never executes the export, contacts a
router, opens a record store or applies changes. **Every preview has `can_apply: false`.**
The source SHA-256 identifies input bytes; it is not an authenticity signature.

Use a DNS-static-only export. The accepted subset is a `/ip dns static` or
`/ip/dns/static` section followed by literal `add key=value` commands. Newlines and
semicolons separate commands. Comments beginning with `#` outside a quoted value are
ignored. Backslash-newline may join commands between tokens. Quoted values support
escaped quote, backslash, dollar, newline, carriage return, tab, space (`\_`) and
uppercase two-digit hexadecimal bytes. Decoded values must be valid UTF-8 without NUL.
String continuation, other escapes and more general scripting syntax are rejected.

Variables, expressions, command substitution, unrelated commands or sections, duplicate
properties and unknown properties fail the whole parse. Errors contain fixed categories
and source locations rather than the input. A syntax failure returns no partial preview.
The parser accepts at most 1 MiB, 4,096 entries, 16 KiB per token and 64 KiB per logical
command. The output contains record values and comments: treat it as operational data
and store it privately. It is not a redaction tool.

Entries retain source order, duplicate owners, decoded fields, disabled state and
comments. Missing fields remain missing. In particular, omitted type, TTL, disabled
and subdomain flags are diagnosed instead of guessing version-dependent defaults.
Integer TTL seconds and descending integer w/d/h/m/s components are checked without
rounding; other forms remain in the preview with a diagnostic. No TTL is changed.

The exact-record classification is only a structural candidate, not a compatibility
or apply guarantee. Regex, subdomain matching, forwarding, negative responses and
other record types remain visible with unsupported-semantics diagnostics. Disabled
entries are retained too; they are not silently dropped. The parser does not combine
RRsets, infer zones or SOA records, establish matching precedence, compare against a
current store, or report additions/replacements without a base snapshot.

A later importer needs a shared policy model and a revision-checked atomic apply.
Applying the exact-record subset of a mixed export would lose policy and is deliberately
not offered here. The exact-record cluster snapshot model is a separate, narrower
namespace; this preview is not convertible to a complete snapshot by discarding entries.

## Internal exact compiler

`routeros.CompileExact(reader, rulesetID)` is a pure internal API with profile
`secdns.routeros-exact-explicit.v1`. It compiles the entire submitted source or exposes
no candidate. The CLI, admin preview endpoint and page still call the original parser;
there is no compiler endpoint, apply button or record-store mutation.

The strict profile requires explicit uppercase `A`, `AAAA` or `CNAME`, exact integer
TTL seconds/components, `disabled=no` and `match-subdomain=no` on every entry. TTL0
and the uint32 maximum are preserved. Only `name`, `type`, `ttl`, `disabled`,
`match-subdomain`, optional `comment`, and the type's `address` or `cname` field are
allowed. Even an empty regexp or other extra field blocks the whole source. Omitted
defaults, disabled entries, FWD, NXDOMAIN and unsupported matching are never dropped
or filled. An empty export does not compile to an empty replacement.

The compiler reuses recordset validation for ASCII/A-label names, IP family/text and
canonical sorting. Surrounding whitespace and wildcard owners/targets are refused.
Repeated canonical owner/type keys are refused even with identical values; rows are
not merged, deduplicated or assigned a winning TTL. A+AAAA at one owner is supported;
CNAME coexistence, duplicates, self aliases and visible CNAME cycles are refused.
External targets remain unresolved. Source order, decoded fields/comments and
empty-versus-absent comments remain in the complete Preview.

Result accessors return owned copies. Only a complete success exposes canonical
Records, ContentJSON, ContentSHA256 and source-ordinal bindings aligned with those
records. Records have no expiration; TTL is a cache lifetime, not an expiration time.
No published lineage, revision, epoch or snapshot envelope is exposed. `CanApply()`
and the retained Preview's `can_apply` remain false. The original-byte source hash
and canonical content hash serve different purposes; neither authenticates a source
or authorizes an import. Comments and source order affect provenance, not content hash.

Invalid ruleset IDs fail with `ErrExactConfig` before reading input. Existing syntax,
read and parser-limit failures return ParseError with no partial report. A semantic
refusal returns `ErrNotExact` with the complete Preview and fixed source-located
blockers. Target bounds return `ErrExactLimit`; unexpected final canonical rejection
returns `ErrExactValidation`, with no candidate. Errors never echo source values.
Blockers sort by ordinal/code, with at most one primary or conflict blocker per entry
and one global blocker (bounded by `MaxCompileBlockers`, 8,193). Duplicate conflicts
reference the first occurrence; CNAME cycle blockers identify only cycle members.
No quadratic conflict-pair list or recursive chain walk is produced.

The existing parser's byte/entry/token/command bounds and recordset's canonical output
bounds apply. Callers own reader deadlines and concurrency limits. Success establishes
only representation under this narrow profile, not complete export capture, RouterOS
answer parity, policy migration or safe replacement of a live store. A mixed source
containing even one regexp rule cannot yield a supported subset. Revision-checked
apply and persistence of source annotations remain separate work.

## Validation

### Optional admin preview page

An admin listener with `ui: true` exposes `<base>/ui/import-preview/` in both legacy
and versioned modes. The records editor links to it in a separate tab so staged
records, unfinished forms and exact retry state remain in the original page.
Enter a token separately; credentials are kept only in that tab's memory. The
static shell contains no token or export. UI remains disabled by default and adds
no management-transport encryption.

Choose a file or paste DNS-static export text, then click **Preview export**. No
upload occurs before that explicit action. Files use their original bytes;
pasted text uses UTF-8 bytes of the textarea value, without trimming. The returned
hash identifies those submitted bytes before the parser's newline normalization.
Results retain entry order, duplicate owners, disabled entries and all diagnostics,
with 50 entries displayed per page. Missing source defaults are never filled.
An explicit disabled entry may still be a structural exact-record candidate;
classification does not establish applicability. No apply button or supported-subset
conversion exists. Source and results are not saved in browser storage.

The selected source is sent to the same-origin authenticated
`POST <base>/import/routeros/preview` route, available only when `ui` is enabled.
It accepts exactly one `Content-Type: application/octet-stream` header, with no
parameters, and no Content-Encoding or a single `identity` value. Compressed,
ambiguous and multipart requests are rejected. The route calls the existing parser
without reading or writing records or snapshots. A successful response uses the
existing Preview JSON model and always has `can_apply: false`.

The body limit is 1 MiB (413). Media/encoding rejection is 415; read and complete
parse failures are 400. Parse failures return only a fixed error code and diagnostic
line/column/category, never partial entries or the input fragment. Parser columns
are byte positions after its newline normalization. Unexpected/output-budget
failure returns 503. Serialization is capped at 32 MiB before success headers;
this per-request bound is not aggregate concurrency protection. Authentication is
checked before body reads; 401/403 clears the page token even if the response body
is malformed. Changing source/token or disconnecting invalidates old asynchronous
results. Retrying is explicit and only recomputes a preview.

### Synthetic checks

Run `go test ./internal/importers/routeros` for literal parsing, rejected expressions,
escaping, comments, order, omissions, TTL boundaries and size limits. Run
`go test ./internal/importers/routeros -fuzz FuzzParseNeverApplies -fuzztime 10s` for
bounded parser fuzzing. Fixtures are synthetic and require no network or listener.

The same package tests cover the exact compiler's fixed canonical golden, source
provenance, copy ownership, whole-source refusals and maximum 4,096-entry chains,
cycles and collisions. `go test ./internal/importers/routeros -fuzz
FuzzCompileExactNeverReturnsPartialCandidate -fuzztime 10s` checks the compiler's
no-partial-result invariant. The synthetic 141-entry test reproduces counts and an
unnamed regexp only; it contains no private inventory and makes no migration claim.

`node scripts/test-routeros-preview-state.cjs` tests bounded response validation and
request generations. `scripts/test-routeros-preview-browser.cjs` requires an existing
Playwright/Chromium installation and a dedicated synthetic localhost memory admin
listener with `ui: true` and token `local-browser-test-only`. It uses synthetic
exports and mocked editor failures; never point it at an operational admin instance.
`PLAYWRIGHT_MODULE`, `PREVIEW_TEST_URL`, `PREVIEW_SCREENSHOT` and
`PREVIEW_MOBILE_SCREENSHOT` select installed tooling, test endpoint and screenshots.
No dependency download is required. Handler tests also cover auth-before-read,
parser parity, size/media limits, output buffering and no store mutation.

The grammar subset follows the official [RouterOS scripting documentation](https://help.mikrotik.com/docs/spaces/ROS/pages/47579229/Scripting).
Field names and semantic distinctions come from [DNS-static documentation](https://help.mikrotik.com/docs/spaces/ROS/pages/37748767/DNS).
The [configuration management documentation](https://help.mikrotik.com/docs/spaces/ROS/pages/328155/Configuration+Management)
describes export files. This restricted parser does not claim to implement the complete
RouterOS scripting language or all export variants.

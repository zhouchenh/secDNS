# Exact-record snapshot foundation

`internal/recordset` implements the pure data model `secdns.exact-record-set.v1`.
It does not synchronize nodes, mutate a database, expose an API, elect an authority,
or apply a RouterOS export. It is a foundation for those later changes.

`New(rulesetID, lineageID, revision, records)` validates a proposal and returns an
immutable snapshot. `Parse` validates a wire envelope and its canonical content hash.
Neither operation reads the clock or performs I/O. A resolver can pin one snapshot
for an entire query instead of mixing generations during a CNAME chain.

## Wire contract

The envelope contains exactly `schema`, `ruleset_id`, `lineage_id`, `revision`,
`content_sha256`, and `records`. IDs contain 1–128 ASCII letters, digits, dots,
underscores or hyphens. Their case is significant. Revision is a positive uint64
encoded as a decimal **string**, without a sign or leading zero, to preserve its
full range in JavaScript. The authority assigns revisions; this package does not
decide whether a lineage or revision is authorized or newer.

Each record contains `name`, `type`, `values`, `ttl_seconds`, and optional
`expires_at`. Supported types are A, AAAA, CNAME and TXT. TTL is an exact uint32;
zero remains zero. There is no implicit TTL or expiry default. An empty record
list is valid and serializes as `[]`. Unknown fields, duplicate keys, alternative
field casing, null fields/elements, numeric revisions and trailing JSON are rejected.

Owners and CNAME targets are trimmed, lowercase FQDNs. This v1 namespace accepts
unescaped ASCII DNS presentation names, including underscore labels and root;
IDNs must use A-labels. Escaped names and non-ASCII names are rejected rather than
treated as alternate hash identities. IP values are trimmed and normalized;
IPv4-mapped values are accepted for A and rejected for AAAA. TXT strings retain
their exact valid UTF-8 contents, including empty strings, up to 255 bytes each.
CNAME has exactly one nonempty valid target. Duplicate normalized address values and
duplicate normalized owner/type RRsets fail validation. TXT values are ordered
chunks of one TXT resource record, matching the existing resolver; repeated chunks
and repeated empty strings are valid and preserved. They are not multiple TXT RRs.

A CNAME cannot share an owner with any other type in the snapshot, even when a
conflicting entry has expired. This decision is independent of local wall clock;
the authority must remove obsolete conflicting entries in the same proposal.
Cycles between otherwise valid CNAME entries are not rejected here; the existing
resolver's bounded chain completion remains responsible for their DNS behavior.

`expires_at` is an absolute RFC3339Nano string, normalized to UTC. Empty/omitted
means permanent. Explicit zero time and times outside UTC years 1–9999 are rejected.
Valid expired entries remain in the payload and content hash. `RecordsAt(now)` and
`Lookup(name,type,now)` hide them at or after expiry without mutating the snapshot.
Followers must not extend relative lifetimes or invent a revision during local GC.
Human edit APIs may enforce future-only timestamps separately.

## Canonical content and integrity

Content bytes are compact UTF-8 JSON with these fields in order: `schema`,
`ruleset_id`, `records`. Records are sorted bytewise by canonical owner, then type.
Record fields occur in order: `name`, `type`, `values`, `ttl_seconds`, and nonempty
`expires_at`. Values retain input order; v1 does not claim semantic equality for
permuted RRset values. Empty expiry is omitted. Integers use decimal notation.
JSON string escaping follows Go encoding/json: HTML-sensitive characters `<`, `>`
and `&`, plus U+2028/U+2029, are escaped; no indentation or terminal newline is added.
Golden tests pin these exact bytes for other implementations.

`content_sha256` is the lowercase hexadecimal SHA-256 of those bytes. Lineage and
revision are deliberately excluded: they identify an authority update, not record
content. A hash is not a signature or authentication proof. Future authenticated
replication must bind the complete envelope to its expected ruleset, authority and
lineage, reject rollback/conflicting revisions, and verify the digest.

All returned record/value slices and byte buffers are copies; no mutable index or
map is exposed. Metadata is returned by value. Concurrent reads and mutation of
caller-owned input/output copies cannot alter the snapshot. This package does not
itself publish a snapshot pointer or provide compare-and-swap transactions.

## Bounds and scope

At most 4 MiB of encoded envelope, 10,000 records, 64 values per RRset, 100,000 total
values, 255 bytes per value/name, and 128 bytes per ID are accepted. Parsing checks
wire size before decoding. Typed construction also checks aggregate input bytes
and final encoded size. Errors are fixed categories without record content.

This namespace does not express regex/subdomain matches, forwarding, NXDOMAIN
policies, disabled source entries, comments, DNS64/listener roles, or routing policy.
A lossless RouterOS preview cannot become a complete snapshot by dropping those
entries. A future policy namespace must version those semantics explicitly.

Run `go test -race ./internal/recordset` and
`go test ./internal/recordset -fuzz FuzzParse -fuzztime 10s`. All fixtures are
synthetic. Tests cover canonical bytes, revision precision, strict wire parsing,
TTL zero, expired entries, conflict rejection, ownership isolation and concurrent
reads. No production state or cluster transport is exercised.

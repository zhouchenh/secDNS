# DNS_PROTOCOL_SPECIFIC

Additional DNS/RFC-specific behavior errors and edge cases.

## Incorrect NXDOMAIN vs NODATA Differentiation
- **Context:** Authoritative answers for non-existent names/records
- **Symptom:** Resolvers treat some names as non-existent when only the record type is missing; negative caching misbehaves.
- **Root Cause:** Returning NXDOMAIN for existing names that lack the requested RR type instead of NOERROR with empty answer and proper SOA in authority.
- **Fix:** Implement correct negative response logic per RFC 2308; distinguish name non-existence from type non-existence.

## CNAME and Other Data Coexistence Mis-Handling
- **Context:** Authoritative zone answering
- **Symptom:** Zone load failures or protocol errors when a name has both CNAME and other RR types.
- **Root Cause:** Allowing CNAME to coexist with additional RRs at the same owner name, violating RFC 1034.
- **Fix:** Reject invalid zone data at load time; enforce that a CNAME owner has no other data (except DNSSEC RRSIGs).

## Broken Additional Section Processing
- **Context:** Authoritative and recursive answers
- **Symptom:** Missing glue A/AAAA records or including unrelated addresses; some clients need extra queries.
- **Root Cause:** Not adding in-bailiwick glue into additional section or adding out-of-bailiwick records without validation.
- **Fix:** Populate additional section only with in-bailiwick and relevant records; follow bailiwick rules when adding glue.

## Ignoring DNSSEC DO/CD Flags
- **Context:** Validating resolver / DNSSEC-aware authoritative
- **Symptom:** Unexpected SERVFAILs or validation behavior when clients request no validation.
- **Root Cause:** Always performing validation or always skipping it regardless of DO (DNSSEC OK) and CD (Checking Disabled) bits.
- **Fix:** Follow RFC 4035 behavior: honor DO/CD; allow clients to opt-out of validation while still returning DNSSEC records as requested.

## IDN / Punycode Handling Errors
- **Context:** Internationalized domain names
- **Symptom:** Inability to resolve IDN domains; inconsistent cache keys; duplicate entries.
- **Root Cause:** Mixing Unicode and punycode representations or partially decoding labels; using different forms as cache keys and zone keys.
- **Fix:** Normalize all internal keys to a single representation (usually punycode/ASCII); convert only at UI or API boundaries.

## Broken Negative Caching TTL Calculation
- **Context:** Recursive resolver cache
- **Symptom:** Negative answers cached much longer or shorter than intended; users see outdated NXDOMAIN.
- **Root Cause:** Ignoring SOA MINIMUM field and TTL rules for negative responses (RFC 2308); using arbitrary defaults.
- **Fix:** Follow negative caching rules strictly; compute TTL from SOA fields and cache accordingly with max/min bounds.


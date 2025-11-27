# DNS_PROTOCOL_SPECIFIC

Violations of RFCs or networking edge cases.

## UDP Truncation Mismatch
- **Context:** Large responses (DNSSEC/TXT)
- **Symptom:** Clients hanging or timing out; `SERVFAIL` on large records.
- **Root Cause:** Failing to set the `TC` (Truncated) bit when response > 512 bytes (or > EDNS buffer size), preventing TCP retry.
- **Fix:** Check `msg.Len()` against client's advertised EDNS buffer size; set `TC=1` if exceeded.

## IPv6/IPv4 Dual-Stack Logic Error
- **Context:** Binding listeners
- **Symptom:** Server fails to bind IPv4 port if IPv6 binds `[::]:53` without `IPV6_V6ONLY` set.
- **Root Cause:** Linux defaults to binding both v4 and v6 on a wildcard v6 listener, causing 'address already in use' for the v4 bind.
- **Fix:** Explicitly set socket option `syscall.IPV6_V6ONLY` to 1 or bind specific IPs.

## EDNS0 Buffer Size Mismatch
- **Context:** DNSSEC responses
- **Symptom:** Fragmented UDP packets dropped by middleboxes; intermittent resolution failures.
- **Root Cause:** Advertising large EDNS buffer (4096) but network path has lower MTU; no fallback logic.
- **Fix:** Implement EDNS buffer size negotiation; consider 1232-byte safe default per RFC 8020.

## Case Sensitivity in Domain Comparison
- **Context:** Zone lookups, caching
- **Symptom:** Cache misses for same domain; duplicate cache entries.
- **Root Cause:** Comparing domain names with `==` instead of case-insensitive comparison (DNS is case-insensitive per RFC 1035).
- **Fix:** Normalize to lowercase before comparison/storage; use `strings.EqualFold()` or pre-lowercase all keys.

## Incorrect TTL Handling
- **Context:** Caching, response generation
- **Symptom:** Stale records served; TTL=0 records cached indefinitely.
- **Root Cause:** Caching absolute TTL from response instead of computing expiration time; not decrementing TTL on cache hit.
- **Fix:** Store `expireAt = time.Now().Add(ttl)`; compute remaining TTL on retrieval.

## Missing QNAME Minimization
- **Context:** Recursive resolution
- **Symptom:** Privacy leak; full query name sent to all authoritative servers in chain.
- **Root Cause:** Sending full query name to root/TLD servers instead of minimal necessary labels.
- **Fix:** Implement RFC 7816 QNAME minimization in resolver logic.


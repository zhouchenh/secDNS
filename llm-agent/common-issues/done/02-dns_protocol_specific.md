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


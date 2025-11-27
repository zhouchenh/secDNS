# SECURITY

Vulnerabilities and attack surface issues.

## DNS Amplification Attack Vector
- **Context:** Open resolver configuration
- **Symptom:** Server used in DDoS attacks; high outbound traffic; abuse complaints.
- **Root Cause:** Responding to ANY queries from any source; no rate limiting; no response rate limiting (RRL).
- **Fix:** Implement RRL; restrict recursive queries to trusted networks; limit ANY responses.

## Cache Poisoning via Insufficient Validation
- **Context:** Response processing
- **Symptom:** Incorrect records cached; users redirected to malicious IPs.
- **Root Cause:** Caching additional/authority section records without validating they're in-bailiwick.
- **Fix:** Validate all cached records are within queried zone; implement DNSSEC validation.

## Zone Transfer Information Leak
- **Context:** AXFR handling
- **Symptom:** Entire zone contents exposed to unauthorized parties.
- **Root Cause:** AXFR enabled without IP-based ACL or TSIG authentication.
- **Fix:** Disable AXFR by default; implement TSIG; restrict by source IP.

## Insufficient Input Validation
- **Context:** Query parsing
- **Symptom:** Buffer overflow; panic; potential RCE.
- **Root Cause:** Trusting length fields in DNS packet without bounds checking.
- **Fix:** Validate all lengths against remaining buffer; use safe parsing libraries; fuzz test extensively.


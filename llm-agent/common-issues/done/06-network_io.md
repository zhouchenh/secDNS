# NETWORK_IO

Socket handling, connection management, and I/O errors.

## TCP Connection Exhaustion
- **Context:** TCP fallback handling
- **Symptom:** File descriptor exhaustion; 'too many open files' errors.
- **Root Cause:** Not closing TCP connections after response; no connection timeout; no limit on concurrent TCP connections.
- **Fix:** Set `SetDeadline()` on connections; implement connection pool with max size; defer `conn.Close()`.

## UDP Read Buffer Too Small
- **Context:** Receiving large EDNS packets
- **Symptom:** Truncated queries; unable to process DNSSEC-enabled requests.
- **Root Cause:** Using default 512-byte buffer for `ReadFromUDP()` when clients send larger EDNS-enabled queries.
- **Fix:** Allocate buffers matching max EDNS size (typically 4096 bytes); use `SO_RCVBUF` socket option.

## Ignoring Partial Writes
- **Context:** TCP response sending
- **Symptom:** Clients receive incomplete responses; protocol errors.
- **Root Cause:** Not checking return value of `Write()` for bytes written; assuming single write completes full message.
- **Fix:** Loop until all bytes written or use `io.WriteString()`; handle `io.ErrShortWrite`.

## Source Port Randomization Failure
- **Context:** Upstream queries (resolver mode)
- **Symptom:** Vulnerability to DNS cache poisoning attacks.
- **Root Cause:** Reusing same source port for all upstream queries; predictable transaction IDs.
- **Fix:** Let OS assign ephemeral ports; randomize TXID; validate response matches query.


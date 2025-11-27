# NETWORK_IO

Additional socket and I/O-level pitfalls that impact correctness and performance.

## Reusing Read Buffer After Returning to Pool
- **Context:** UDP read loop with buffer pool
- **Symptom:** Responses contain data from unrelated queries; random corruption.
- **Root Cause:** Storing pointers to a buffer returned to a pool and then reusing that buffer for another read before the first request completes.
- **Fix:** Copy data out of pooled buffer before returning it; or hand off exclusive buffer ownership to worker and allocate a new one for next read.

## Ignoring Remote Address on UDP Responses
- **Context:** UDP server implementation
- **Symptom:** Clients receive no responses; responses sent to wrong target.
- **Root Cause:** Using Write instead of WriteTo/WriteToUDP, or not preserving addr returned by ReadFromUDP when replying.
- **Fix:** Always respond using the net.Addr from ReadFromUDP; ensure per-packet association between request and reply address.

## Blocking DNS over TCP Accept Loop
- **Context:** High-connection-count TCP handling
- **Symptom:** Throughput plateau at low concurrency; high connection latency.
- **Root Cause:** Handling TCP connections serially in the same goroutine that calls Accept() instead of spawning goroutines or using a pool.
- **Fix:** Run Accept() in a loop and hand each connection to a separate goroutine or worker pool; apply sensible connection limits.

## No Per-Client Rate Limiting
- **Context:** Open recursive resolver / public authoritative
- **Symptom:** Single misbehaving client can saturate server; high packet loss for others.
- **Root Cause:** Accepting and processing unlimited queries per IP without shaping or quotas.
- **Fix:** Introduce token-bucket or leaky-bucket rate limiting per client or subnet; drop or downgrade clients exceeding limits.


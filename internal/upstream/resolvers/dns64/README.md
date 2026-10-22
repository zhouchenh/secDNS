# Optional speculative DNS64 A lookup

`speculativeA: true` starts an A lookup alongside the normal AAAA lookup. Default is false. Native AAAA, non-NOERROR responses and native lookup errors retain precedence; synthesis still requires successful no-AAAA and uses the same signature/AD stripping. `ignoreExistingAAAA` retains its existing direct-A behavior.

Extra A work can occur even for names with native AAAA or failing native lookups. At most 32 speculative A calls per DNS64 instance and 128 process-wide can be in flight. When either limit is full, resolution uses the original serial path. These limits cover speculative work, not normal caller-driven DNS requests.

The resolver interface has no cancellation. An unused A lookup may finish after the native answer was returned; it retains both capacity slots until completion. Its result channel is buffered so completion never waits for a consumer. Underlying resolver timeouts still govern completion; a stuck child retains its slot and later queries fall back to serial resolution. This option trades extra upstream traffic for overlapping AAAA/A latency and does not relax DNS64 semantics or guarantee health recovery time.

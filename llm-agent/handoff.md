# secDNS LLM Handoff

Use this as the quick-start context before making changes.

## Project Snapshot
- Purpose: DNS resolver proxy to bypass ISP poisoning; supports DoH, DoT, DNS64, SOCKS5, ECS, and rule-based routing.
- Code entry: `main.go` → `internal/core/instance.go` orchestrates listeners/resolvers configured via JSON.
- Key interfaces: `pkg/upstream/resolver` (`Resolve(*dns.Msg, depth int)`), `pkg/listeners/server`, `pkg/rules/provider`.
- Default branch for AI work: `dev-by-llm-agents`.

## Must-Know Docs
1. `README.md` – overview and build/test commands.
2. `docs/configuration.md` – JSON schema plus listener/resolver/rule object format.
3. `docs/resolvers/*.md`, especially:
   - `resolvers/name_server.md` & `resolvers/doh.md` (protocol + ECS options),
   - `resolvers/cache.md` (LRU cache configuration).
4. `docs/rules/*.md` – `collection` and `dnsmasqConf` providers.
5. Architecture bundle:
   - `ARCHITECTURE_ANALYSIS.md` – resolver patterns, depth handling, ECS, errors.
   - `ANALYSIS_SUMMARY.md` / `ANALYSIS_INDEX.md` – quick lookup + checklist.
6. Cache design:
   - `CACHE_DESIGN.md` – production-ready cache spec.
   - `CACHING_RESOLVER_DESIGN_GUIDE.md` – step-by-step implementation plan.

## LLM-Agent Resources
- `llm-agent/README.md` – workflow rules (branching, testing, context updates).
- `llm-agent/context.yaml` – living knowledge base (update after tasks).
- `llm-agent/reports/*.md` – prior deep dives:
  - `concurrency-analysis...` – race conditions in DoH and core instance.
  - `concurrent-nameserver-list-type...` – explains relaxing resolver type restriction.
  - `large-dns-response-handling.md` / `tcp-fallback-client-caching-optimization.md` – DoH/nameServer improvements.

## High-Priority Work (from `IMPROVEMENTS_ANALYSIS.md`)
1. Fix cache race in `get()` (lock scope) – `internal/upstream/resolvers/cache/types.go`.
2. Include ECS/EDNS0 data in cache keys (prevent wrong hits).
3. Close files in `internal/rules/providers/dnsmasq/conf/types.go` (FD leak).
4. Add nil-resolver guard in cache initialization.
5. Later: request coalescing, faster cleanup, configurable default TTLs, stale-while-revalidate/prefetch.

## Testing / Runbook
```bash
go build -o bin/secDNS main.go
./bin/secDNS -test -config config.json
./bin/secDNS -config config.json
```
No automated tests yet; add targeted unit tests when touching core logic.

## Next Steps for New Agents
1. Read `docs/configuration.md` and relevant resolver docs for any feature you touch.
2. Review the analysis + reports above before editing affected packages.
3. Prioritize Phase 1 fixes from `IMPROVEMENTS_ANALYSIS.md`; reference line numbers inside that file.
4. After changes: run `go test ./...` (if tests added) or manual verification, then update `llm-agent/context.yaml`.

Keep responses concise and cite files/lines per CLI instructions. Update this handoff if new architectural info emerges.

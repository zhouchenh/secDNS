# Agent Guide for secDNS

This is a neutral guide for all coding agents working on secDNS.

## Quick Start

**Project:** secDNS - DNS resolver proxy for bypassing DNS spoofing  
**Language:** Go 1.23+  
**Version:** 1.3.1  
**License:** AGPLv3  
**Current Branch:** `master` (stay on this branch unless the user requests otherwise)

## Important Context Files

- **This file:** High-level guide and instructions
- **context.yaml:** Primary project knowledge base (kept current)
- **config_guidance.yaml:** Prompts and rules for generating secDNS configs with users

## Project Overview

secDNS is a DNS resolver designed to help users bypass DNS spoofing (DNS cache poisoning) from ISPs. It acts as a local DNS proxy that can forward DNS queries to multiple upstream resolvers with various protocols (DoT, DoH, DNS).

## Architecture Quick Reference

### Entry Points
- `main.go:12` - Application entry point
- `internal/core/instance.go:28` - Core DNS orchestration
- `internal/config/loader.go:19` - Configuration system

### Key Components
1. **Listeners** (2): DNS server (UDP/TCP) and HTTP API `/resolve`
2. **Resolvers** (15): Protocol handlers, caching, filtering, ECS wrapper, DNS64, recursive, composition
3. **Rules** (2 providers): Domain-based routing logic

### Resolver Types
- `nameServer` / `doh`
- `address`, `alias`
- `sequence`, `concurrentNameServerList`
- `dns64`
- `ecs` (ECS add/override/passthrough/strip wrapper)
- `filterOutA`, `filterOutAAAA`, `filterOutAIfAAAAPresents`, `filterOutAAAAIfAPresents`
- `noAnswer`, `notExist`
- `cache` (LRU + TTL overrides, stale-while-revalidate, prefetch, per-domain stats)
- `recursive` (DNSSEC-validating, ECS-aware)

## Development Guidelines

### Branch Strategy
- Stay on the current branch unless the user directs otherwise.
- Never force-push or reset user work; avoid main/master unless requested.

### Before Starting Work
1. Read `context.yaml` for current project state
2. Check recent commits: `git log -5`
3. Check for TODOs in the codebase
4. Review relevant documentation in `docs/`

### After Completing Work
1. **Update context.yaml** with:
   - What was changed
   - Why it was changed
   - New files/functions added
   - Potential issues or technical debt
   - Next steps or related work needed
2. Commit with clear, descriptive messages
3. Update this file if architectural changes were made

### Code Standards
- Follow existing Go conventions in the codebase
- Use the descriptor pattern for new resolvers/listeners/providers
- Register new types in `internal/features/features.go`
- Add error handling consistently with existing patterns
- Use structured logging via `internal/logger`

## Testing

**Recommended Checks:**
```bash
go build -o bin/secDNS main.go
go test -mod=readonly ./...
```

**Manual Testing:**
- `./bin/secDNS -test -config config.json`
- `./bin/secDNS -config config.json`

**If Adding Tests:**
- Place in same directory as code with `_test.go` suffix
- Use standard Go testing package
- Test resolver logic, configuration parsing, and error cases

## Common Tasks

### Adding a New Resolver
1. Create `internal/upstream/resolvers/NEWTYPE/types.go`
2. Implement `Resolver` interface from `pkg/upstream/resolver`
3. Define `Descriptor` for configuration parsing
4. Register in `internal/features/features.go`
5. Add documentation in `docs/resolvers/NEWTYPE.md`
6. Update `context.yaml`

### Adding a New Listener
1. Create `internal/listeners/servers/NEWTYPE/types.go`
2. Implement `Server` interface from `pkg/listeners/server`
3. Define `Descriptor` for configuration
4. Register in `internal/features/features.go`
5. Add documentation in `docs/listeners/NEWTYPE.md`
6. Update `context.yaml`

### Modifying Configuration System
1. Update `internal/config/types.go` for new fields
2. Modify `internal/config/loader.go` if needed
3. Update example `config.json`
4. Document in `docs/configuration.md`
5. Update `context.yaml`

## File Organization

```
 secDNS/
 ├── main.go                           # Entry point
 ├── config.json                       # Example configuration
 ├── docs/                             # Documentation (26 files)
 ├── llm-agent/                        # Agent context (you are here)
 │   ├── README.md                     # This guide
 │   ├── context.yaml                  # Knowledge base and runbook
 │   └── config_guidance.yaml          # Config-generation guidance for LLM agents
 ├── pkg/                              # Public interfaces
 │   ├── common/
 │   ├── listeners/server/
 │   ├── rules/provider/
 │   └── upstream/resolver/
 └── internal/                         # Implementation
     ├── core/                         # DNS orchestration
     ├── config/                       # Configuration loading
     ├── features/                     # Module registration
     ├── logger/                       # Logging system
     ├── listeners/servers/            # Listener implementations
     ├── upstream/resolvers/           # Resolver implementations
     └── rules/providers/              # Rule provider implementations
```

## Dependencies

**Key Libraries:**
- `github.com/miekg/dns` - DNS protocol implementation
- `github.com/rs/zerolog` - Structured logging
- `github.com/txthinking/socks5` - SOCKS5 proxy support
- `github.com/zhouchenh/go-descriptor` - Type descriptor system

## Debugging Tips

### Enable Debug Logging
Modify logger configuration in `internal/logger/logger.go` to enable Debug level.

### Test Configuration Parsing
```bash
./secDNS -test -config config.json
```

### Common Issues
- **Loop detection:** Resolution depth exceeds max (64) - check for circular resolver references
- **Missing resolver:** Named resolver not found - ensure resolver is defined in config
- **Port binding:** Permission denied on port 53 - run with sudo or use port > 1024
- **TLS errors:** Certificate verification failed - check `tlsServerName` matches certificate

## Security Considerations

This is a DNS proxy tool designed for:
- Bypassing DNS spoofing/poisoning
- Educational purposes
- Personal/organizational use

When working on security features:
- Maintain DoT/DoH encryption support
- Preserve SOCKS5 authentication
- Don't introduce DNS query logging without explicit user consent
- Validate all user-controlled inputs (domains, IPs, ports)

## Resources

- **Project README:** `/README.md`
- **Documentation:** `/docs/` directory
- **Configuration Guide:** `/docs/configuration.md`
- **Version History:** `/docs/version_history.md`
- **Resolver Docs:** `/docs/resolvers/*.md`
- **Listener Docs:** `/docs/listeners/*.md`

## Questions or Clarifications?

If you need clarification on:
- Architecture decisions → Check `context.yaml` and recent commits
- User requirements → Ask the user directly
- Configuration format → Reference `config.json` and `docs/configuration.md`
- Implementation patterns → Look at existing resolver implementations

## Task Completion Checklist

Before marking any task as complete:
- [ ] Code changes implemented and tested
- [ ] `context.yaml` updated with changes
- [ ] Documentation updated if needed
- [ ] Commit message is clear and descriptive
- [ ] No obvious bugs or security issues introduced
- [ ] Followed existing code patterns
- [ ] Updated this README if architectural changes were made

---

**Last Updated:** 2025-12-01
**Updated By:** ChatGPT (doc/style alignment and config guidance)

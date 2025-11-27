# BUILD_DEPLOYMENT

Issues in how the binary is built, packaged, and shipped.

## CGO Dependency on Minimal Containers
- **Context:** DNS server using CGO (for BPF, system calls, etc.)
- **Symptom:** Binary fails to start or behaves differently in scratch/distroless images.
- **Root Cause:** Relying on glibc or other shared libs in production but testing with different environment locally.
- **Fix:** Prefer pure Go where possible; if CGO is required, test in same base image; use static linking when appropriate.

## Missing Runtime Kernel/Sysctl Tuning
- **Context:** High-scale deployments on Linux
- **Symptom:** Packet drops, ENOBUFS, and backlog overflows under load.
- **Root Cause:** Relying on OS defaults for net.core.rmem_max, net.core.wmem_max, net.core.somaxconn, etc.
- **Fix:** Document and apply recommended sysctl settings in deployment; verify via startup checks or preflight scripts.

## Inconsistent Build Flags Across Environments
- **Context:** Feature flags, race detector, and optimizations
- **Symptom:** Bugs only appear in production builds or only in debug builds; behavior differs across environments.
- **Root Cause:** Using different tags or build flags (-tags, -race, -trimpath) without tracking them.
- **Fix:** Standardize build pipeline; encode build flags in CI; embed build info (version, tags) into binary.


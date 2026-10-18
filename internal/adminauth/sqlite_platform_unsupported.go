//go:build !((darwin && !ios && (amd64 || arm64)) || (freebsd && (amd64 || arm64)) || (linux && !android && (386 || amd64 || arm || arm64 || loong64 || ppc64le || riscv64 || s390x)) || (windows && (386 || amd64 || arm64)))

package adminauth

const sqlitePlatformSupported = false

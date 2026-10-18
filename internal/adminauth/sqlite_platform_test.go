package adminauth

import (
	"encoding/json"
	"go/build"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuthSQLitePlatformMatchesRecordStore(t *testing.T) {
	for _, target := range strings.Fields("aix/ppc64 android/arm64 darwin/amd64 darwin/arm64 dragonfly/amd64 freebsd/386 freebsd/amd64 freebsd/arm freebsd/arm64 freebsd/riscv64 illumos/amd64 linux/386 linux/amd64 linux/arm linux/arm64 linux/loong64 linux/mips linux/mipsle linux/mips64 linux/mips64le linux/ppc64 linux/ppc64le linux/riscv64 linux/s390x netbsd/386 netbsd/amd64 netbsd/arm netbsd/arm64 openbsd/386 openbsd/amd64 openbsd/arm openbsd/arm64 openbsd/ppc64 openbsd/riscv64 plan9/386 plan9/amd64 plan9/arm solaris/amd64 windows/386 windows/amd64 windows/arm windows/arm64 ios/amd64 ios/arm64") {
		t.Run(target, func(t *testing.T) {
			ctx := build.Default
			p := strings.Split(target, "/")
			ctx.GOOS, ctx.GOARCH = p[0], p[1]
			ctx.CgoEnabled = false
			for _, name := range []string{"sqlite_platform_supported.go", "sqlite_platform_unsupported.go"} {
				got, e := ctx.MatchFile(".", name)
				if e != nil {
					t.Fatal(e)
				}
				want, e := ctx.MatchFile("../recordstore", name)
				if e != nil || got != want {
					t.Fatalf("boundary drift %s got=%v want=%v err=%v", name, got, want, e)
				}
			}
		})
	}
}
func TestUnsupportedAuthPlatformHasNoFilesystemEffects(t *testing.T) {
	if sqlitePlatformSupported {
		t.Skip("unsupported overlay only")
	}
	dir := t.TempDir()
	p, key := filepath.Join(dir, "auth.db"), filepath.Join(dir, "auth.key")
	calls := []func() error{
		func() error { return CreateKey(key) },
		func() error { _, e := Create(p, key, testIdentity, nil); return e },
		func() error { _, e := Open(p, key, testIdentity, nil); return e },
		func() error { return MigrateSchema1(p, key, testIdentity, nil) },
		func() error { return EnableHumanSchema(p, key, testIdentity, nil) },
		func() error {
			return EnablePasskeySchema(p, key, testIdentity, nil, "https://admin.invalid", "admin.invalid")
		},
	}
	for _, call := range calls {
		if e := call(); e != ErrUnsupportedPlatform {
			t.Fatal(e)
		}
	}
	entries, e := os.ReadDir(dir)
	if e != nil || len(entries) != 0 {
		t.Fatal("unsupported operation created files", e)
	}
	for _, file := range []string{p, key} {
		if e := os.WriteFile(file, []byte("existing private sentinel"), 0600); e != nil {
			t.Fatal(e)
		}
	}
	for _, call := range calls {
		if e := call(); e != ErrUnsupportedPlatform {
			t.Fatal(e)
		}
	}
	for _, file := range []string{p, key} {
		b, e := os.ReadFile(file)
		if e != nil || string(b) != "existing private sentinel" {
			t.Fatal("existing state changed", e)
		}
	}
}
func TestUnsupportedAuthPlatformOverlay(t *testing.T) {
	if !sqlitePlatformSupported {
		t.Skip("already unsupported")
	}
	dir := t.TempDir()
	stub := filepath.Join(dir, "unsupported.go")
	if e := os.WriteFile(stub, []byte("package adminauth\nconst sqlitePlatformSupported=false\n"), 0600); e != nil {
		t.Fatal(e)
	}
	pkg, e := os.Getwd()
	if e != nil {
		t.Fatal(e)
	}
	raw, e := json.Marshal(map[string]any{"Replace": map[string]string{filepath.Join(pkg, "sqlite_platform_supported.go"): stub}})
	if e != nil {
		t.Fatal(e)
	}
	overlay := filepath.Join(dir, "overlay.json")
	if e = os.WriteFile(overlay, raw, 0600); e != nil {
		t.Fatal(e)
	}
	command := exec.Command(filepath.Join(build.Default.GOROOT, "bin", "go"), "test", "-overlay", overlay, "-run", "^TestUnsupportedAuthPlatformHasNoFilesystemEffects$", "-count=1", ".")
	command.Env = append(os.Environ(), "CGO_ENABLED=0", "GOPROXY=off", "GOTOOLCHAIN=local")
	if out, e := command.CombinedOutput(); e != nil {
		t.Fatalf("unsupported refusal: %v\n%s", e, out)
	}
}

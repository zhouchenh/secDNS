package recordstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"go/build"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/zhouchenh/secDNS/internal/recordset"
)

func TestSQLitePlatformBuildTags(t *testing.T) {
	qualified := strings.Fields("darwin/amd64 darwin/arm64 freebsd/amd64 freebsd/arm64 linux/386 linux/amd64 linux/arm linux/arm64 linux/loong64 linux/ppc64le linux/riscv64 linux/s390x windows/386 windows/amd64 windows/arm64")
	want := map[string]bool{}
	for _, target := range qualified {
		want[target] = true
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	block := regexp.MustCompile(`(?s)platforms=\((.*?)\n\s*\)`).FindSubmatch(raw)
	if len(block) != 2 {
		t.Fatal("release platform list missing")
	}
	lines := regexp.MustCompile(`(?m)^\s*"([^"\r\n]+)"`).FindAllSubmatch(block[1], -1)
	if len(lines) != 46 {
		t.Fatalf("release asset list changed: %d, want 46", len(lines))
	}
	var targets []string
	for _, line := range lines {
		targets = append(targets, string(line[1]))
	}
	// Go treats Android as Linux and iOS as Darwin when matching constraints.
	targets = append(targets, "android/386", "android/amd64", "android/arm", "ios/amd64", "ios/arm64")
	for _, target := range targets {
		t.Run(target, func(t *testing.T) {
			parts := strings.Split(target, "/")
			context := build.Default
			context.GOOS, context.GOARCH = parts[0], parts[1]
			context.CgoEnabled = false
			supported, err := context.MatchFile(".", "sqlite_platform_supported.go")
			if err != nil {
				t.Fatal(err)
			}
			unsupported, err := context.MatchFile(".", "sqlite_platform_unsupported.go")
			if err != nil {
				t.Fatal(err)
			}
			if supported == unsupported || supported != want[parts[0]+"/"+parts[1]] {
				t.Fatalf("driver selection supported=%v unavailable=%v", supported, unsupported)
			}
		})
	}
}

func TestSQLitePlatformDriverRegistration(t *testing.T) {
	registered := false
	for _, name := range sql.Drivers() {
		registered = registered || name == "sqlite"
	}
	if registered != sqlitePlatformSupported {
		t.Fatalf("SQLite driver registered=%v, availability=%v", registered, sqlitePlatformSupported)
	}
}

func TestSQLitePlatformUnavailableNoFilesystemEffects(t *testing.T) {
	if sqlitePlatformSupported {
		t.Skip("exercised by the unavailable native overlay")
	}
	writer := Enrollment{RulesetID: "platform-test", LineageID: "platform-test"}
	follower := FollowerEnrollment{ClusterID: "platform-test", Kind: FollowerExactRecords, RulesetID: "platform-test", LineageID: "platform-test", AuthorityEpoch: "platform-test"}
	constructors := map[string]func(*testing.T, string) error{
		"legacy": func(t *testing.T, path string) error {
			s, err := OpenSQLite(path)
			if s != nil {
				s.Close()
				t.Fatal("legacy handle returned")
			}
			return err
		},
		"versioned": func(t *testing.T, path string) error {
			s, err := OpenVersionedSQLite(path, writer)
			if s != nil {
				s.Close()
				t.Fatal("versioned handle returned")
			}
			return err
		},
		"follower-create": func(t *testing.T, path string) error {
			s, err := CreateFollowerSQLite(path, follower)
			if s != nil {
				s.Close()
				t.Fatal("follower create handle returned")
			}
			return err
		},
		"follower-open": func(t *testing.T, path string) error {
			s, err := OpenFollowerSQLite(path, follower)
			if s != nil {
				s.Close()
				t.Fatal("follower open handle returned")
			}
			return err
		},
	}
	for name, open := range constructors {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			existing := filepath.Join(dir, "existing.db")
			const content = "pre-existing file must stay unchanged"
			if err := os.WriteFile(existing, []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
			for _, path := range []string{filepath.Join(dir, "new.db"), filepath.Join(dir, "missing", "new.db"), existing, "relative.db", ""} {
				if err := open(t, path); !errors.Is(err, ErrSQLiteUnsupported) {
					t.Fatalf("expected unsupported without path/DB handling: %v", err)
				}
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 1 || entries[0].Name() != "existing.db" {
				t.Fatalf("constructor created a file, sidecar or directory: %v %v", entries, err)
			}
			got, err := os.ReadFile(existing)
			if err != nil || string(got) != content {
				t.Fatalf("existing contents changed: %v", err)
			}
		})
	}
}

func TestSQLitePlatformMemoryStores(t *testing.T) {
	s := New()
	defer s.Close()
	if err := s.Set(Record{Name: "memory.invalid.", Type: dns.TypeA, Values: []string{"192.0.2.1"}, TTL: 0}); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Get("memory.invalid.", dns.TypeA); !ok {
		t.Fatal("legacy memory unavailable")
	}
	v, err := NewVersionedMemory(Enrollment{RulesetID: "memory", LineageID: "memory"})
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	if view, err := v.Acquire(); err != nil || view.Metadata().Revision != 1 {
		t.Fatal("versioned memory unavailable", err)
	}
	e := FollowerEnrollment{ClusterID: "memory", Kind: FollowerExactRecords, RulesetID: "memory", LineageID: "memory", AuthorityEpoch: "memory"}
	f, err := NewFollowerMemory(e)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	snapshot, err := recordset.New(e.RulesetID, e.LineageID, 7, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := snapshot.MarshalJSON()
	if result, err := f.Accept(e, raw); err != nil || result.Outcome != "initial" || result.State.Snapshot.Revision != 7 {
		t.Fatal("follower memory unavailable", err)
	}
}

// Exercise the real unavailable constructors on the native host without exposing
// a public feature flag or requiring execution of a foreign-platform binary.
func TestSQLitePlatformUnavailableBuild(t *testing.T) {
	if !sqlitePlatformSupported {
		t.Skip("already an unavailable build")
	}
	dir := t.TempDir()
	stub := filepath.Join(dir, "unavailable.go")
	if err := os.WriteFile(stub, []byte("package recordstore\nconst sqlitePlatformSupported = false\n"), 0600); err != nil {
		t.Fatal(err)
	}
	pkg, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(map[string]any{"Replace": map[string]string{filepath.Join(pkg, "sqlite_platform_supported.go"): stub}})
	if err != nil {
		t.Fatal(err)
	}
	overlay := filepath.Join(dir, "overlay.json")
	if err = os.WriteFile(overlay, data, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "test", "-overlay", overlay, "-run", "^TestSQLitePlatform(UnavailableNoFilesystemEffects|MemoryStores|DriverRegistration)$", "-count=1", "-timeout=30s", ".")
	cmd.WaitDelay = time.Second
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("unavailable variant failed: %v\n%s", err, output)
	}
}

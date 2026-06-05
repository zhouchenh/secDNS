package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zhouchenh/secDNS/internal/core"
)

const validConfigJSON = `{
  "listeners": [{"type": "dnsServer", "config": {"listen": "127.0.0.1", "port": 5353, "protocol": "udp"}}],
  "resolvers": {"noAnswer": {"default": {}}},
  "rules": [],
  "defaultResolver": {"type": "noAnswer", "config": {}}
}`

const invalidConfigJSON = `{
  "listeners": [{"type": "bogusListener", "config": {}}],
  "defaultResolver": {"type": "noAnswer", "config": {}}
}`

// writeTemp writes content to a uniquely named file in t.TempDir() and returns its path.
func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	return path
}

// isolateConfigEnv points the config-discovery env vars at empty temp locations and
// chdir's into an empty dir, so the no-config path is deterministic regardless of the
// host or the test binary's location.
func isolateConfigEnv(t *testing.T) {
	t.Helper()
	empty := t.TempDir()
	t.Setenv(core.EnvKey("config", "file", "path"), filepath.Join(empty, "absent.json"))
	t.Setenv(core.EnvKey("config", "dir", "path"), empty)

	prev, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(empty); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(prev) })
}

func TestRunExitCodes(t *testing.T) {
	t.Run("version exits ok", func(t *testing.T) {
		if code := run("", true, false, ""); code != exitOK {
			t.Fatalf("version: got exit %d, want %d", code, exitOK)
		}
	})

	t.Run("no config exits non-zero", func(t *testing.T) {
		isolateConfigEnv(t)
		if code := run("", false, false, ""); code != exitNoConfig {
			t.Fatalf("missing config: got exit %d, want %d (a missing config must not exit 0)", code, exitNoConfig)
		}
	})

	t.Run("named missing file exits startup-failure", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "does-not-exist.json")
		if code := run(missing, false, false, ""); code != exitStartup {
			t.Fatalf("named missing file: got exit %d, want %d", code, exitStartup)
		}
	})

	t.Run("invalid config exits startup-failure", func(t *testing.T) {
		path := writeTemp(t, "invalid.json", invalidConfigJSON)
		if code := run(path, false, true, ""); code != exitStartup {
			t.Fatalf("invalid config: got exit %d, want %d", code, exitStartup)
		}
	})

	t.Run("valid config with --test exits ok", func(t *testing.T) {
		path := writeTemp(t, "valid.json", validConfigJSON)
		if code := run(path, false, true, ""); code != exitOK {
			t.Fatalf("valid --test config: got exit %d, want %d", code, exitOK)
		}
	})
}

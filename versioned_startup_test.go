package main

import (
	"context"
	"encoding/json"
	"github.com/zhouchenh/secDNS/internal/recordstore"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestVersionedTestModeDoesNotBindOrOpen(t *testing.T) {
	if os.Getenv("SECDNS_VERSIONED_STARTUP_TEST") != "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestVersionedTestModeDoesNotBindOrOpen$", "-test.count=1")
		command.Env = append(os.Environ(), "SECDNS_VERSIONED_STARTUP_TEST=1")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("startup child: %v %s", err, output)
		}
		return
	}

	dir := t.TempDir()
	db := filepath.Join(dir, "records.db")
	cfg := map[string]any{"versionedRecordStores": map[string]any{"default": map[string]string{"backend": "sqlite", "sqlitePath": db, "rulesetId": "r", "lineageId": "l"}}, "listeners": []any{map[string]any{"type": "httpAdminServer", "config": map[string]any{"token": "synthetic-only", "ui": true}}}, "defaultResolver": map[string]any{"type": "authoritative", "config": map[string]any{}}}
	raw, e := json.Marshal(cfg)
	if e != nil {
		t.Fatal(e)
	}
	path := writeTemp(t, "config.json", string(raw))
	if code := run(path, false, true, ""); code != exitOK {
		t.Fatal(code)
	}
	files, e := os.ReadDir(dir)
	if e != nil || len(files) != 0 {
		t.Fatal("test mode wrote database", e)
	}
	cleanup, e := recordstore.PrepareBindings(nil, map[string]recordstore.VersionedConfig{"default": {Backend: "sqlite", SQLitePath: db, RulesetID: "r", LineageID: "l"}})
	if e != nil {
		t.Fatal("descriptor shadowed configured default", e)
	}
	t.Cleanup(func() { _ = cleanup() })
	if recordstore.GetOrCreate("") != nil {
		t.Fatal("default versioned mode bypass")
	}
}
func TestVersionedStartupFailurePrecedesListener(t *testing.T) {
	cfg := map[string]any{"versionedRecordStores": map[string]any{t.Name(): map[string]string{"backend": "sqlite", "sqlitePath": filepath.Join(t.TempDir(), "missing", "db"), "rulesetId": "r", "lineageId": "l"}}, "listeners": []any{map[string]any{"type": "dnsServer", "config": map[string]any{"listen": "127.0.0.1", "port": 0, "protocol": "udp"}}}, "defaultResolver": map[string]any{"type": "noAnswer", "config": map[string]any{}}}
	raw, e := json.Marshal(cfg)
	if e != nil {
		t.Fatal(e)
	}
	path := writeTemp(t, "config.json", string(raw))
	if code := run(path, false, false, ""); code != exitStartup {
		t.Fatal(code)
	}
}

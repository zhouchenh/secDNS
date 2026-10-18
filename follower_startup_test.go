package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestFollowerTestModeDoesNotOpenDatabaseOrNetwork(t *testing.T) {
	if os.Getenv("SECDNS_FOLLOWER_STARTUP_TEST") != "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestFollowerTestModeDoesNotOpenDatabaseOrNetwork$", "-test.count=1")
		command.Env = append(os.Environ(), "SECDNS_FOLLOWER_STARTUP_TEST=1")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("startup child: %v %s", err, output)
		}
		return
	}
	dir := t.TempDir()
	database := filepath.Join(dir, "follower.db")
	config := map[string]any{
		"followerRecordStores": map[string]any{"default": map[string]any{
			"sqlitePath": database, "createIfMissing": true, "clusterId": "cluster", "kind": "exact-records", "rulesetId": "rules", "lineageId": "lineage", "authorityEpoch": "epoch", "nodeId": "node", "authorityUrl": "https://authority.invalid/admin", "token": "reader-token-0123456789abcdef-0001",
		}},
		"listeners":       []any{map[string]any{"type": "dnsServer", "config": map[string]any{"listen": "127.0.0.1", "port": 0, "protocol": "udp"}}},
		"defaultResolver": map[string]any{"type": "authoritative", "config": map[string]any{}},
	}
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	path := writeTemp(t, "config.json", string(raw))
	if code := run(path, false, true, ""); code != exitOK {
		t.Fatal(code)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatal("test mode touched follower database", err, entries)
	}
}

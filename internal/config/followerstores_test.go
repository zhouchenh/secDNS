package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/zhouchenh/secDNS/internal/recordstore"
	"github.com/zhouchenh/secDNS/internal/snapshotfollower"
)

func followerConfigJSON(t *testing.T, path string) []byte {
	t.Helper()
	value := map[string]any{
		"followerRecordStores": map[string]any{"replica": map[string]any{
			"sqlitePath": path, "createIfMissing": true, "clusterId": "cluster", "kind": "exact-records", "rulesetId": "rules", "lineageId": "lineage", "authorityEpoch": "epoch", "nodeId": "node", "authorityUrl": "https://authority.invalid/admin", "token": "reader-token-0123456789abcdef-0001",
		}},
		"versionedRecordStores": map[string]any{"writer": map[string]any{"backend": "memory", "rulesetId": "rules", "lineageId": "lineage"}},
		"listeners": []any{map[string]any{"type": "httpAdminServer", "config": map[string]any{
			"token": "admin", "store": "writer", "snapshotReaders": []any{map[string]any{"nodeId": "node", "token": "reader-token-0123456789abcdef-0001"}},
		}}},
		"defaultResolver": map[string]any{"type": "authoritative", "config": map[string]any{"store": "replica"}},
	}
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestFollowerConfigStrictNoIOAndTopology(t *testing.T) {
	database := filepath.Join(t.TempDir(), "follower.db")
	raw := followerConfigJSON(t, database)
	legacy, err := ParseRecordStores(raw)
	if err != nil {
		t.Fatal(err)
	}
	versioned, err := ParseVersionedRecordStores(raw, legacy)
	if err != nil {
		t.Fatal(err)
	}
	followers, err := ParseFollowerRecordStores(raw, legacy, versioned)
	if err != nil || len(followers) != 1 || followers["replica"].Enrollment.Kind != recordstore.FollowerExactRecords {
		t.Fatal(err, followers)
	}
	if _, err = os.Stat(database); !os.IsNotExist(err) {
		t.Fatal("syntax validation touched follower database", err)
	}
	if err = ValidateStoreListenerTopology(raw, versioned, followers); err != nil {
		t.Fatal(err)
	}
	if err = ValidateConfig(bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
}

func TestFollowerConfigRejectsInvalidAndAdminBinding(t *testing.T) {
	database := filepath.Join(t.TempDir(), "follower.db")
	raw := followerConfigJSON(t, database)
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		t.Fatal(err)
	}
	bad := root["followerRecordStores"].(map[string]any)["replica"].(map[string]any)
	bad["authorityUrl"] = "http://authority.invalid/admin"
	encoded, _ := json.Marshal(root)
	if _, err := ParseFollowerRecordStores(encoded, nil, nil); !errors.Is(err, ErrFollowerConfig) {
		t.Fatal("plain HTTP authority accepted", err)
	}

	raw = followerConfigJSON(t, database)
	root = map[string]any{}
	_ = json.Unmarshal(raw, &root)
	listener := root["listeners"].([]any)[0].(map[string]any)["config"].(map[string]any)
	listener["store"] = "replica"
	delete(listener, "snapshotReaders")
	encoded, _ = json.Marshal(root)
	versioned, _ := ParseVersionedRecordStores(encoded, nil)
	followers, _ := ParseFollowerRecordStores(encoded, nil, versioned)
	if !errors.Is(ValidateStoreListenerTopology(encoded, versioned, followers), ErrFollowerConfig) {
		t.Fatal("admin listener admitted follower store")
	}
}

func TestFollowerTopologyNormalizesExplicitDefaultStore(t *testing.T) {
	listener := func(readers bool) []any {
		config := map[string]any{"store": ""}
		if readers {
			config["snapshotReaders"] = []any{map[string]any{"nodeId": "node", "token": "reader-token-0123456789abcdef-0001"}}
		}
		return []any{map[string]any{"type": "httpAdminServer", "config": config}}
	}
	encode := func(value map[string]any) []byte {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	followerRaw := encode(map[string]any{"listeners": listener(false)})
	if !errors.Is(ValidateStoreListenerTopology(followerRaw, nil, map[string]snapshotfollower.Config{recordstore.DefaultName: {}}), ErrFollowerConfig) {
		t.Fatal("explicit empty store bypassed default follower refusal")
	}
	writerRaw := encode(map[string]any{"listeners": listener(true)})
	if err := ValidateStoreListenerTopology(writerRaw, map[string]recordstore.VersionedConfig{recordstore.DefaultName: {}}, nil); err != nil {
		t.Fatal("explicit empty store did not bind default versioned reader", err)
	}
}

func TestFollowerTopologySeparatesSnapshotCredentialsAcrossListeners(t *testing.T) {
	database := filepath.Join(t.TempDir(), "follower.db")
	decode := func() map[string]any {
		t.Helper()
		var root map[string]any
		if err := json.Unmarshal(followerConfigJSON(t, database), &root); err != nil {
			t.Fatal(err)
		}
		return root
	}
	encode := func(root map[string]any) []byte {
		t.Helper()
		raw, err := json.Marshal(root)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	const shared = "reader-token-0123456789abcdef-0001"

	t.Run("reader cannot equal another listener admin", func(t *testing.T) {
		root := decode()
		root["recordStores"] = map[string]any{"legacy": map[string]any{"sqlitePath": filepath.Join(filepath.Dir(database), "legacy-reader-admin.db")}}
		root["listeners"] = append(root["listeners"].([]any), map[string]any{
			"type":   "httpAdminServer",
			"config": map[string]any{"token": shared, "store": "legacy"},
		})
		if err := ValidateConfig(bytes.NewReader(encode(root))); !errors.Is(err, ErrFollowerConfig) {
			t.Fatal("cross-listener reader/admin token equality accepted", err)
		}
	})

	t.Run("reader cannot be reused across stores", func(t *testing.T) {
		root := decode()
		root["versionedRecordStores"].(map[string]any)["other"] = map[string]any{"backend": "memory", "rulesetId": "other-rules", "lineageId": "other-lineage"}
		root["listeners"] = append(root["listeners"].([]any), map[string]any{
			"type": "httpAdminServer",
			"config": map[string]any{
				"token": "second-admin", "store": "other",
				"snapshotReaders": []any{map[string]any{"nodeId": "other-node", "token": shared}},
			},
		})
		if err := ValidateConfig(bytes.NewReader(encode(root))); !errors.Is(err, ErrFollowerConfig) {
			t.Fatal("snapshot reader token reused across stores", err)
		}
	})

	t.Run("legacy admin token reuse remains compatible", func(t *testing.T) {
		root := decode()
		root["recordStores"] = map[string]any{"legacy": map[string]any{"sqlitePath": filepath.Join(filepath.Dir(database), "legacy-admin-reuse.db")}}
		root["listeners"] = append(root["listeners"].([]any), map[string]any{
			"type":   "httpAdminServer",
			"config": map[string]any{"token": "admin", "store": "legacy"},
		})
		if err := ValidateConfig(bytes.NewReader(encode(root))); err != nil {
			t.Fatal("admin-only token reuse rejected", err)
		}
	})
}

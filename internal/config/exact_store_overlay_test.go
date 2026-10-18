package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zhouchenh/secDNS/internal/recordstore"
)

func overlayConfigMap(t *testing.T, sqlitePath string) map[string]any {
	t.Helper()
	return map[string]any{
		"versionedRecordStores": map[string]any{"owned": map[string]any{
			"backend": "sqlite", "sqlitePath": sqlitePath, "rulesetId": "rules", "lineageId": "lineage",
		}},
		"listeners": []any{map[string]any{
			"type": "dnsServer", "resolver": "overlay",
			"config": map[string]any{"listen": "127.0.0.1", "port": 11553, "protocol": "udp"},
		}},
		"resolvers": map[string]any{
			"address": map[string]any{"ordinary": "192.0.2.10"},
			"exactStoreOverlay": map[string]any{"overlay": map[string]any{
				"store": "owned", "completeCNAME": true, "negativeTTL": 60, "fallback": "ordinary",
			}},
		},
		"rules":           []any{},
		"defaultResolver": "overlay",
	}
}

func encodeOverlayConfig(t *testing.T, value map[string]any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestExactStoreOverlayConfigValidatesWithoutStorageIO(t *testing.T) {
	database := filepath.Join(t.TempDir(), "owned.db")
	raw := encodeOverlayConfig(t, overlayConfigMap(t, database))
	legacy, err := ParseRecordStores(raw)
	if err != nil {
		t.Fatal(err)
	}
	versioned, err := ParseVersionedRecordStores(raw, legacy)
	if err != nil {
		t.Fatal(err)
	}
	followers, err := ParseFollowerRecordStores(raw, legacy, versioned)
	if err != nil {
		t.Fatal(err)
	}
	if err = ValidateExactStoreOverlayTopology(raw, legacy, versioned, followers); err != nil {
		t.Fatal(err)
	}
	if err = ValidateConfig(bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	if matches, err := filepath.Glob(database + "*"); err != nil || len(matches) != 0 {
		t.Fatal("config validation touched exact store", err, matches)
	}
}

func TestExactStoreOverlayConfigRejectsWrongModesAndGraphs(t *testing.T) {
	newConfig := func() map[string]any { return overlayConfigMap(t, filepath.Join(t.TempDir(), "owned.db")) }

	legacy := newConfig()
	delete(legacy, "versionedRecordStores")
	legacy["recordStores"] = map[string]any{"owned": map[string]any{"sqlitePath": filepath.Join(t.TempDir(), "legacy.db")}}
	if err := ValidateConfig(bytes.NewReader(encodeOverlayConfig(t, legacy))); !errors.Is(err, ErrExactStoreOverlayConfig) {
		t.Fatal("legacy mutable store admitted", err)
	}

	missing := newConfig()
	missing["resolvers"].(map[string]any)["exactStoreOverlay"].(map[string]any)["overlay"].(map[string]any)["store"] = "missing"
	if err := ValidateConfig(bytes.NewReader(encodeOverlayConfig(t, missing))); !errors.Is(err, ErrExactStoreOverlayConfig) {
		t.Fatal("missing store admitted", err)
	}

	cycle := newConfig()
	cycle["resolvers"].(map[string]any)["exactStoreOverlay"].(map[string]any)["overlay"].(map[string]any)["fallback"] = "overlay"
	if err := ValidateConfig(bytes.NewReader(encodeOverlayConfig(t, cycle))); !errors.Is(err, ErrResolverCycle) {
		t.Fatal("overlay fallback cycle admitted", err)
	}

	unknownFallback := newConfig()
	unknownFallback["resolvers"].(map[string]any)["exactStoreOverlay"].(map[string]any)["overlay"].(map[string]any)["fallback"] = "missing-resolver"
	if err := ValidateConfig(bytes.NewReader(encodeOverlayConfig(t, unknownFallback))); err == nil {
		t.Fatal("missing fallback admitted")
	}

	unknownSetting := newConfig()
	unknownSetting["resolvers"].(map[string]any)["exactStoreOverlay"].(map[string]any)["overlay"].(map[string]any)["unknown"] = true
	if err := ValidateConfig(bytes.NewReader(encodeOverlayConfig(t, unknownSetting))); err == nil {
		t.Fatal("unknown overlay setting admitted")
	}
}

func TestExactStoreOverlayInlineTopologyAndLegacyOmission(t *testing.T) {
	database := filepath.Join(t.TempDir(), "owned.db")
	config := overlayConfigMap(t, database)
	delete(config, "resolvers")
	config["listeners"].([]any)[0].(map[string]any)["resolver"] = map[string]any{
		"type": "exactStoreOverlay",
		"config": map[string]any{
			"store": "owned", "fallback": map[string]any{"type": "address", "config": "192.0.2.20"},
		},
	}
	config["defaultResolver"] = map[string]any{"type": "address", "config": "192.0.2.30"}
	if err := ValidateConfig(bytes.NewReader(encodeOverlayConfig(t, config))); err != nil {
		t.Fatal("inline overlay rejected", err)
	}

	legacy := `{"listeners":[{"type":"dnsServer","config":{"listen":"127.0.0.1","port":11553,"protocol":"udp"}}],"rules":[],"defaultResolver":{"type":"address","config":"192.0.2.1"},"unrelated":{"type":"exactStoreOverlay","config":{"store":"not-a-store"}}}`
	if err := ValidateConfig(strings.NewReader(legacy)); err != nil {
		t.Fatal("unrelated legacy metadata changed behavior", err)
	}
}

func TestExactStoreOverlayTopologyAcceptsFollowerMode(t *testing.T) {
	database := filepath.Join(t.TempDir(), "follower.db")
	value := overlayConfigMap(t, database)
	delete(value, "versionedRecordStores")
	value["followerRecordStores"] = map[string]any{"owned": map[string]any{
		"sqlitePath": database, "createIfMissing": true,
		"clusterId": "cluster", "kind": recordstore.FollowerExactRecords, "rulesetId": "rules", "lineageId": "lineage", "authorityEpoch": "epoch",
		"nodeId": "node", "authorityUrl": "https://authority.invalid/admin", "token": "reader-token-0123456789abcdef-0001",
	}}
	raw := encodeOverlayConfig(t, value)
	if err := ValidateConfig(bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	if matches, err := filepath.Glob(database + "*"); err != nil || len(matches) != 0 {
		t.Fatal("follower overlay validation touched storage", err, matches)
	}
}

func TestExactStoreOverlaySourcePoliciesRejectSharedFallbackCache(t *testing.T) {
	value := overlayConfigMap(t, filepath.Join(t.TempDir(), "owned.db"))
	value["listeners"] = []any{map[string]any{
		"type": "dnsServer", "sourcePolicyRole": "normal",
		"config": map[string]any{"listen": "127.0.0.1", "port": 11553, "protocol": "udp"},
	}}
	value["resolvers"] = map[string]any{
		"cache": map[string]any{"shared": map[string]any{
			"resolver": map[string]any{"type": "address", "config": "192.0.2.10"}, "maxEntries": 32,
		}},
		"exactStoreOverlay": map[string]any{
			"ordinary": map[string]any{"store": "owned", "fallback": "shared"},
			"special":  map[string]any{"store": "owned", "fallback": "shared"},
		},
	}
	value["sourcePolicy"] = map[string]any{
		"sourceSets": []any{map[string]any{"id": "special-clients", "members": []any{map[string]any{"prefix": "127.0.0.2/32"}}}},
		"rules":      []any{map[string]any{"listenerRole": "normal", "sourceSet": "special-clients", "resolver": "special"}},
		"defaults":   []any{map[string]any{"listenerRole": "normal", "resolver": "ordinary"}},
	}
	value["defaultResolver"] = "ordinary"
	if configured, err := LoadConfig(bytes.NewReader(encodeOverlayConfig(t, value))); !errors.Is(err, ErrSharedSourcePolicyCache) || configured != nil {
		t.Fatal("shared fallback cache admitted", err)
	}
}

func TestExactStoreOverlayRejectsOuterCache(t *testing.T) {
	value := overlayConfigMap(t, filepath.Join(t.TempDir(), "owned.db"))
	value["resolvers"].(map[string]any)["cache"] = map[string]any{"stale-outer": map[string]any{
		"resolver": "overlay", "maxEntries": 32,
	}}
	value["defaultResolver"] = "stale-outer"
	if configured, err := LoadConfig(bytes.NewReader(encodeOverlayConfig(t, value))); !errors.Is(err, ErrExactStoreOverlayCachePlacement) || configured != nil {
		t.Fatal("outer cache admitted across exact-store revisions", err)
	}
}

package recordstore

import (
	"path/filepath"
	"testing"
)

func TestBindingsModesAndTombstones(t *testing.T) {
	n := t.Name()
	t.Cleanup(func() { registryMu.Lock(); delete(versionedRegistry, n); registryMu.Unlock() })
	cleanup, e := PrepareBindings(nil, map[string]VersionedConfig{n: {Backend: "memory", RulesetID: "r", LineageID: "l"}})
	if e != nil {
		t.Fatal(e)
	}
	legacy, v := Binding(n)
	if legacy != nil || v == nil || GetOrCreate(n) != nil {
		t.Fatal("legacy shadow")
	}
	if e = cleanup(); e != nil {
		t.Fatal(e)
	}
	legacy, closed := Binding(n)
	if legacy != nil || closed != v || GetOrCreate(n) != nil {
		t.Fatal("closed mode lost")
	}
	if _, e = closed.Acquire(); e != ErrClosed {
		t.Fatal(e)
	}
	if _, e = PrepareBindings(nil, map[string]VersionedConfig{n: {Backend: "memory", RulesetID: "r", LineageID: "l"}}); e == nil {
		t.Fatal("rebound closed mode")
	}
}
func TestBindingsFailedPreparationPublishesNothing(t *testing.T) {
	a, z := t.Name()+"a", t.Name()+"z"
	t.Cleanup(func() {
		registryMu.Lock()
		delete(versionedRegistry, a)
		delete(versionedRegistry, z)
		registryMu.Unlock()
	})
	entries := map[string]VersionedConfig{a: {Backend: "memory", RulesetID: "r", LineageID: "l"}, z: {Backend: "sqlite", SQLitePath: filepath.Join(t.TempDir(), "missing", "db"), RulesetID: "r", LineageID: "l"}}
	if _, e := PrepareBindings(nil, entries); e == nil {
		t.Fatal("expected failure")
	}
	registryMu.Lock()
	_, ghost := versionedRegistry[a]
	registryMu.Unlock()
	if ghost {
		t.Fatal("published partial mode")
	}
	delete(entries, z)
	cleanup, e := PrepareBindings(nil, entries)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = cleanup() })
}
func TestBindingsRejectCollisionsAndSchemaOne(t *testing.T) {
	p := filepath.Join(t.TempDir(), "legacy.db")
	s, e := OpenSQLite(p)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	c := VersionedConfig{Backend: "sqlite", SQLitePath: p, RulesetID: "r", LineageID: "l"}
	if e = ValidateBindings(map[string]string{"one": p}, map[string]VersionedConfig{"two": c}); e == nil {
		t.Fatal("path collision")
	}
	if e = ValidateBindings(map[string]string{"one": p}, map[string]VersionedConfig{"one": {Backend: "memory", RulesetID: "r", LineageID: "l"}}); e == nil {
		t.Fatal("name collision")
	}
	if _, e = PrepareBindings(nil, map[string]VersionedConfig{t.Name(): c}); e != ErrMigrationRequired {
		t.Fatalf("schema1 opened: %v", e)
	}
}

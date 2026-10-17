package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func persistedConfig(t *testing.T, path string) string {
	t.Helper()
	var cfg map[string]interface{}
	json.Unmarshal([]byte(validConfigJSON), &cfg)
	cfg["recordStores"] = map[string]interface{}{"default": map[string]string{"sqlitePath": path}}
	raw, _ := json.Marshal(cfg)
	return writeTemp(t, "config.json", string(raw))
}
func TestPersistenceCheckDoesNotOpenDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent-parent", "db")
	cfg := persistedConfig(t, path)
	if code := run(cfg, false, true, ""); code != exitOK {
		t.Fatal("syntax check failed")
	}
	if _, e := os.Stat(filepath.Dir(path)); !os.IsNotExist(e) {
		t.Fatal("check created files")
	}
	if code := run(cfg, false, false, ""); code != exitStartup {
		t.Fatal("failed database allowed startup")
	}
}
func TestPersistenceCheckRejectsSchemaWithoutFiles(t *testing.T) {
	cfg := persistedConfig(t, "relative.db")
	if code := run(cfg, false, true, ""); code != exitStartup {
		t.Fatal("check ignored invalid persistence schema")
	}
}

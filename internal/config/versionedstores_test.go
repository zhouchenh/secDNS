package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestVersionedConfigStrictAndNoIO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.db")
	raw, _ := json.Marshal(map[string]any{"versionedRecordStores": map[string]any{"default": map[string]string{"backend": "sqlite", "sqlitePath": path, "rulesetId": "r", "lineageId": "l"}}})
	stores, e := ParseVersionedRecordStores(raw, nil)
	if e != nil || len(stores) != 1 {
		t.Fatal(e)
	}
	if _, e = os.Stat(path); !os.IsNotExist(e) {
		t.Fatal("parse performed I/O")
	}
	for _, bad := range []string{`{"versionedRecordStores":null}`, `{"versionedRecordStores":{},"versionedRecordStores":{}}`, `{"versionedRecordStores":{"x":{"backend":"memory","rulesetId":"r","lineageId":"l","sqlitePath":""}}}`, `{"versionedRecordStores":{"x":{"backend":"memory","rulesetId":"r","lineageId":null}}}`, `{"versionedRecordStores":{"x":{"backend":"memory","rulesetId":"r","lineageId":"l","allowSchema1Migration":true}}}`} {
		if _, e := ParseVersionedRecordStores([]byte(bad), nil); e == nil {
			t.Fatal("accepted invalid config")
		}
	}
}

package config

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestRecordStoresStrictSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db")
	b, _ := json.Marshal(path)
	good := `{"recordStores":{"default":{"sqlitePath":` + string(b) + `}}}`
	v, e := ParseRecordStores([]byte(good))
	if e != nil || v["default"] != path {
		t.Fatal("valid config")
	}
	for _, bad := range []string{
		`{"recordStores":null}`, `{"recordStores":[]}`, `{"recordStores":{"default":null}}`, `{"recordStores":{"default":{"sqlitePath":3}}}`, `{"recordStores":{"default":{"sqlitePath":null}}}`, `{"recordStores":{"default":{"sqlitePath":"relative.db"}}}`, `{"recordStores":{"default":{"sqlitePath":"file::memory:"}}}`, `{"recordStores":{"default":{"sqlitePath":` + string(b) + `,"seed":[]}}}`, `{"recordStores":{},"recordStores":{}}`, `{"recordStores":{"default":{"sqlitePath":` + string(b) + `},"default":{"sqlitePath":` + string(b) + `}}}`, `{"recordStores":{"default":{"sqlitePath":` + string(b) + `,"sqlitePath":` + string(b) + `}}}`, `{"recordStores":{"a":{"sqlitePath":` + string(b) + `},"b":{"sqlitePath":` + string(b) + `}}}`,
	} {
		if _, e := ParseRecordStores([]byte(bad)); e == nil {
			t.Fatal("invalid persistence config accepted")
		}
	}
}

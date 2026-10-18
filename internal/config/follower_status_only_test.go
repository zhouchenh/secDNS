package config

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestFollowerStatusOnlyConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-created.db")
	makeConfig := func() map[string]any {
		var root map[string]any
		if e := json.Unmarshal(followerConfigJSON(t, path), &root); e != nil {
			t.Fatal(e)
		}
		delete(root, "versionedRecordStores")
		l := root["listeners"].([]any)[0].(map[string]any)
		l["config"] = map[string]any{"listen": "127.0.0.1", "port": 18055, "path": "/owned-static", "token": "admin", "ui": true, "followerStatusOnly": true}
		l["followerStatusStores"] = []string{"replica"}
		return root
	}
	for _, bad := range []string{"", "missing", "unknown", "empty", "store", "snapshotReaders", "sourcePolicyExplain", "null", "string", "duplicate"} {
		t.Run(bad, func(t *testing.T) {
			root := makeConfig()
			l := root["listeners"].([]any)[0].(map[string]any)
			c := l["config"].(map[string]any)
			switch bad {
			case "missing":
				delete(l, "followerStatusStores")
			case "unknown":
				l["followerStatusStores"] = []string{"unknown"}
			case "empty":
				l["followerStatusStores"] = []string{}
			case "store":
				c["store"] = ""
			case "snapshotReaders":
				c["snapshotReaders"] = []any{}
			case "sourcePolicyExplain":
				c["sourcePolicyExplain"] = false
			case "null":
				c["followerStatusOnly"] = nil
			case "string":
				c["followerStatusOnly"] = "true"
			}
			b, _ := json.Marshal(root)
			if bad == "duplicate" {
				b = bytes.Replace(b, []byte(`"followerStatusOnly":true`), []byte(`"followerStatusOnly":false,"followerStatusOnly":true`), 1)
			}
			e := ValidateConfig(bytes.NewReader(b))
			if (e == nil) != (bad == "") {
				t.Fatalf("unexpected validation: %v", e)
			}
		})
	}
	if _, e := os.Stat(path); !os.IsNotExist(e) {
		t.Fatal("opened follower database", e)
	}
}

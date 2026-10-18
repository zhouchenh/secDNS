package config

import (
	"bytes"
	"encoding/json"
	"github.com/zhouchenh/secDNS/internal/snapshotfollower"
	"os"
	"path/filepath"
	"testing"
)

func TestFollowerStatusConfigAllowlistAndNoIO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "follower.db")
	var root map[string]any
	if e := json.Unmarshal(followerConfigJSON(t, path), &root); e != nil {
		t.Fatal(e)
	}
	listener := root["listeners"].([]any)[0].(map[string]any)
	for _, names := range []any{[]string{"replica"}, []string{"missing"}, []string{"replica", "replica"}, []string{}, "replica", nil} {
		listener["followerStatusStores"] = names
		raw, _ := json.Marshal(root)
		e := ValidateConfig(bytes.NewReader(raw))
		valid := false
		if n, ok := names.([]string); ok {
			valid = len(n) == 1 && n[0] == "replica"
		}
		if (e == nil) != valid {
			t.Fatalf("allowlist %v: %v", names, e)
		}
		if valid {
			instance, e := LoadConfig(bytes.NewReader(raw))
			if e != nil {
				t.Fatal(e)
			}
			binder, ok := instance.(interface {
				BindFollowerStatus(map[string]*snapshotfollower.Worker) error
			})
			if !ok || binder.BindFollowerStatus(nil) == nil {
				t.Fatal("missing runtime reader admitted")
			}
		}
	}
	if _, e := os.Stat(path); !os.IsNotExist(e) {
		t.Fatal("status parsing touched store", e)
	}
	listener["followerStatusStores"] = []string{"replica"}
	raw, _ := json.Marshal(root)
	raw = bytes.Replace(raw, []byte(`"followerStatusStores":["replica"]`), []byte(`"followerStatusStores":["replica"],"followerStatusStores":["replica"]`), 1)
	if ValidateConfig(bytes.NewReader(raw)) == nil {
		t.Fatal("duplicate allowlist accepted")
	}
}

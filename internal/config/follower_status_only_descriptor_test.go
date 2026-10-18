package config

import (
	"encoding/json"
	"path/filepath"
	"testing"

	admin "github.com/zhouchenh/secDNS/internal/listeners/servers/http/admin/server"
)

func TestReviewerDescriptorPopulatesFollowerStatusOnly(t *testing.T) {
	var data any
	var root map[string]any
	if err := json.Unmarshal(followerConfigJSON(t, filepath.Join(t.TempDir(), "follower.db")), &root); err != nil {
		t.Fatal(err)
	}
	delete(root, "versionedRecordStores")
	listener := root["listeners"].([]any)[0].(map[string]any)
	listener["followerStatusStores"] = []string{"replica"}
	listener["config"] = map[string]any{
		"listen": "127.0.0.1", "port": 18055, "path": "/owned-static",
		"token": "synthetic-admin", "ui": true, "followerStatusOnly": true,
	}
	b, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &data); err != nil {
		t.Fatal(err)
	}
	raw, successes, failures := Descriptor().Describe(data)
	if successes == 0 || failures != 0 {
		t.Fatalf("descriptor failed: success=%d failure=%d", successes, failures)
	}
	cfg := raw.(*Config)
	h := cfg.Listeners[0].(*admin.HTTPAdminServer)
	if !h.FollowerStatusOnly {
		t.Fatal("followerStatusOnly JSON was not populated into HTTPAdminServer; runtime would take writer-admin path")
	}
}

package config

import (
	"bytes"
	"encoding/json"
	"github.com/zhouchenh/secDNS/internal/adminauth"
	"os"
	"strings"
	"testing"
)

func TestRecordGatewayLoadedConfigPreservesAuth(t *testing.T) {
	raw, _, def := authFixture(t)
	raw["defaultResolver"] = map[string]any{"type": "authoritative", "config": map[string]any{}}
	listener := raw["listeners"].([]any)[0].(map[string]any)
	listener["type"] = "httpAdminServer"
	listener["config"] = map[string]any{"listen": "127.0.0.1", "port": 19053, "path": "/admin", "token": "synthetic-local-token", "ui": true, "recordAuthorityURL": "http://127.0.0.1:18055/owned-static", "recordAuthorityToken": strings.Repeat("x", 32)}
	if e := adminauth.CreateKey(def.KeyPath); e != nil {
		t.Fatal(e)
	}
	s, e := adminauth.Create(def.Path, def.KeyPath, def.Identity(), nil)
	if e != nil {
		t.Fatal(e)
	}
	s.Close()
	encoded, _ := json.Marshal(raw)
	instance, e := LoadConfig(bytes.NewReader(encoded))
	if e != nil {
		t.Fatal(e)
	}
	ai, ok := instance.(*authInstance)
	if !ok || len(ai.bindings) != 1 {
		t.Fatal("auth binding lost")
	}
	if ai.bindings[0].server.RecordAuthorityURL != "http://127.0.0.1:18055/owned-static" {
		t.Fatal("descriptor dropped gateway")
	}
	cleanup, e := ai.PrepareAdminAuth()
	if e != nil {
		t.Fatal(e)
	}
	if e = cleanup(); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(def.Path); e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"no-auth", "no-origin", "store", "null", "duplicate"} {
		t.Run(kind, func(t *testing.T) {
			var r map[string]any
			json.Unmarshal(encoded, &r)
			l := r["listeners"].([]any)[0].(map[string]any)
			c := l["config"].(map[string]any)
			switch kind {
			case "no-auth":
				delete(l, "authStore")
				delete(l, "publicOrigin")
				delete(r, "adminAuthStores")
			case "no-origin":
				delete(l, "publicOrigin")
			case "store":
				c["store"] = "local"
			case "null":
				c["recordAuthorityToken"] = nil
			}
			b, _ := json.Marshal(r)
			if kind == "duplicate" {
				b = bytes.Replace(b, []byte(`"recordAuthorityURL":`), []byte(`"recordAuthorityURL":"http://127.0.0.1:1/admin","recordAuthorityURL":`), 1)
			}
			if ValidateConfig(bytes.NewReader(b)) == nil {
				t.Fatal("invalid gateway accepted")
			}
		})
	}
}

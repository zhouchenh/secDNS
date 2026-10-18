package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/zhouchenh/secDNS/internal/adminauth"
	admin "github.com/zhouchenh/secDNS/internal/listeners/servers/http/admin/server"
	"github.com/zhouchenh/secDNS/pkg/listeners/server"
)

func authFixture(t *testing.T) (map[string]interface{}, *Config, adminauth.Definition) {
	t.Helper()
	d := t.TempDir()
	os.Chmod(d, 0700)
	def := adminauth.Definition{Path: filepath.Join(d, "auth.db"), KeyPath: filepath.Join(d, "key"), RealmID: "realm", NodeID: "node", DisplayName: "Test"}
	encoded, _ := json.Marshal(def)
	var value interface{}
	json.Unmarshal(encoded, &value)
	raw := map[string]interface{}{"adminAuthStores": map[string]interface{}{"local": value}, "listeners": []interface{}{map[string]interface{}{"authStore": "local", "publicOrigin": "https://admin.invalid"}}}
	c := &Config{Listeners: []server.Server{&admin.HTTPAdminServer{Token: "legacy"}}}
	return raw, c, def
}
func TestAdminAuthValidationNoIO(t *testing.T) {
	raw, c, d := authFixture(t)
	bindings, e := parseAdminBindings(raw, c)
	if e != nil || len(bindings) != 1 {
		t.Fatal(e)
	}
	if _, e = os.Stat(d.Path); !os.IsNotExist(e) {
		t.Fatal("validation created database")
	}
	i := &authInstance{bindings: bindings}
	if _, e = i.PrepareAdminAuth(); e != adminauth.ErrUnavailable {
		t.Fatal("missing store created", e)
	}
	if _, e = os.Stat(d.Path); !os.IsNotExist(e) {
		t.Fatal("startup created database")
	}
}
func TestAdminAuthBindingRefusals(t *testing.T) {
	for _, kind := range []string{"unknown", "record-alias", "duplicate-use", "bad-origin", "unused"} {
		t.Run(kind, func(t *testing.T) {
			raw, c, d := authFixture(t)
			entries := raw["listeners"].([]interface{})
			listener := entries[0].(map[string]interface{})
			switch kind {
			case "unknown":
				listener["authStore"] = "missing"
			case "record-alias":
				raw["versionedRecordStores"] = map[string]interface{}{"records": map[string]interface{}{"path": d.Path}}
			case "duplicate-use":
				raw["listeners"] = append(entries, listener)
				c.Listeners = append(c.Listeners, &admin.HTTPAdminServer{Token: "other"})
			case "bad-origin":
				listener["publicOrigin"] = "http://admin.invalid"
			case "unused":
				delete(listener, "authStore")
				delete(listener, "publicOrigin")
			}
			if _, e := parseAdminBindings(raw, c); e == nil {
				t.Fatal("accepted", kind)
			}
		})
	}
}
func TestAdminAuthStartupAndPartialFailureCleanup(t *testing.T) {
	raw, c, d := authFixture(t)
	if e := adminauth.CreateKey(d.KeyPath); e != nil {
		t.Fatal(e)
	}
	store, e := adminauth.Create(d.Path, d.KeyPath, d.Identity(), nil)
	if e != nil {
		t.Fatal(e)
	}
	store.Close()
	bindings, e := parseAdminBindings(raw, c)
	if e != nil {
		t.Fatal(e)
	}
	bad := bindings[0]
	bad.definition.Path = filepath.Join(filepath.Dir(d.Path), "missing.db")
	bad.server = &admin.HTTPAdminServer{}
	i := &authInstance{bindings: append(bindings, bad)}
	if _, e = i.PrepareAdminAuth(); e != adminauth.ErrUnavailable {
		t.Fatal(e)
	}
	// Partial failure must release the exclusive handle, not leave it locked.
	reopened, e := adminauth.Open(d.Path, d.KeyPath, d.Identity(), nil)
	if e != nil {
		t.Fatal(e)
	}
	reopened.Close()
	i.bindings = bindings
	cleanup, e := i.PrepareAdminAuth()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = adminauth.Open(d.Path, d.KeyPath, d.Identity(), nil); e == nil {
		t.Fatal("exclusive ownership lost")
	}
	if e = cleanup(); e != nil {
		t.Fatal(e)
	}
	reopened, e = adminauth.Open(d.Path, d.KeyPath, d.Identity(), nil)
	if e != nil {
		t.Fatal(e)
	}
	reopened.Close()
}

func TestAdminAuthDuplicateBindings(t *testing.T) {
	for _, raw := range []string{
		`{"adminAuthStores":{},"adminAuthStores":{}}`,
		`{"adminAuthStores":{"a":{},"a":{}}}`,
		`{"adminAuthStores":{"a":{"path":"x","path":"y"}}}`,
		`{"listeners":[{"authStore":"a","authStore":"b"}]}`,
		`{"listeners":[{"publicOrigin":"https://a.invalid","publicOrigin":"https://b.invalid"}]}`,
	} {
		if validateAdminAuthSyntax([]byte(raw)) == nil {
			t.Fatal("duplicate accepted")
		}
	}
}

func TestAdminAuthSingleRealmOnly(t *testing.T) {
	raw, c, d := authFixture(t)
	d.Path = filepath.Join(filepath.Dir(d.Path), "other.db")
	d.KeyPath = filepath.Join(filepath.Dir(d.KeyPath), "other.key")
	d.RealmID = "other"
	d.NodeID = "other-node"
	encoded, _ := json.Marshal(d)
	var value interface{}
	json.Unmarshal(encoded, &value)
	raw["adminAuthStores"].(map[string]interface{})["other"] = value
	raw["listeners"] = append(raw["listeners"].([]interface{}), map[string]interface{}{"authStore": "other", "publicOrigin": "https://other.invalid"})
	c.Listeners = append(c.Listeners, &admin.HTTPAdminServer{Token: "other-legacy"})
	if _, e := parseAdminBindings(raw, c); e == nil {
		t.Fatal("multiple independently valid realms admitted")
	}
}

func TestPasskeyRPBindingValidation(t *testing.T) {
	for _, rp := range []any{"invalid", 42, "admin.invalid:443", ""} {
		raw, c, _ := authFixture(t)
		raw["listeners"].([]interface{})[0].(map[string]interface{})["passkeyRPID"] = rp
		if _, e := parseAdminBindings(raw, c); e == nil {
			t.Fatal("invalid RP accepted", rp)
		}
	}
	raw, c, _ := authFixture(t)
	raw["listeners"].([]interface{})[0].(map[string]interface{})["passkeyRPID"] = "admin.invalid"
	b, e := parseAdminBindings(raw, c)
	if e != nil || b[0].passkeyRP != "admin.invalid" {
		t.Fatal(e)
	}
	if e := validateAdminAuthSyntax([]byte(`{"listeners":[{"passkeyRPID":"a","passkeyRPID":"b"}]}`)); e == nil {
		t.Fatal("duplicate RP binding")
	}
}

package main

import (
	"bytes"
	"encoding/json"
	"github.com/zhouchenh/secDNS/internal/adminauth"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestOfflineAgentLifecycle(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	d := adminauth.Definition{Path: filepath.Join(dir, "auth.db"), KeyPath: filepath.Join(dir, "key"), RealmID: "realm", NodeID: "node", DisplayName: "Test"}
	raw, _ := json.Marshal(d)
	definition := filepath.Join(dir, "definition.json")
	os.WriteFile(definition, raw, 0600)
	invoke := func(args ...string) (int, string) {
		t.Helper()
		var out, stderr bytes.Buffer
		code := run(append([]string{"-definition", definition}, args...), &out, &stderr)
		if bytes.Contains(stderr.Bytes(), []byte("sdna_")) {
			t.Fatal("secret in error")
		}
		return code, out.String()
	}
	if code, _ := invoke("-operation", "create"); code != 0 {
		t.Fatal(code)
	}
	if code, _ := invoke("-operation", "create"); code == 0 {
		t.Fatal("existing store replaced")
	}
	if code, _ := invoke("-operation", "issue-agent", "-name", "", "-scopes", "ui:view"); code == 0 {
		t.Fatal("invalid name")
	}
	code, out := invoke("-operation", "issue-agent", "-name", "test", "-scopes", "ui:view,records:read")
	if code != 0 {
		t.Fatal("invalid request left bootstrap", code)
	}
	var result struct {
		ID    string `json:"credential_id"`
		Token string `json:"credential"`
	}
	if json.Unmarshal([]byte(out), &result) != nil || result.ID == "" || result.Token == "" {
		t.Fatal("issuance output")
	}
	s, e := adminauth.Open(d.Path, d.KeyPath, d.Identity(), nil)
	if e != nil {
		t.Fatal(e)
	}
	a, e := s.Verify(result.Token, "realm", "node", time.Now())
	if e != nil || !a.Allows(adminauth.RecordsRead) || a.Allows(adminauth.RecordsWrite) {
		t.Fatal("scope", e)
	}
	s.Close()
	if code, _ := invoke("-operation", "revoke-agent", "-credential-id", result.ID); code != 0 {
		t.Fatal(code)
	}
	s, e = adminauth.Open(d.Path, d.KeyPath, d.Identity(), nil)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if _, e = s.Verify(result.Token, "realm", "node", time.Now()); e != adminauth.ErrDenied {
		t.Fatal(e)
	}
}

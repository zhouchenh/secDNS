package adminauth

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStrictReopenCorruption(t *testing.T) {
	cases := map[string]string{
		"version":     "PRAGMA user_version=3",
		"application": "PRAGMA application_id=0",
		"trigger":     "CREATE TRIGGER unexpected AFTER INSERT ON audit BEGIN SELECT 1; END",
		"scope":       "UPDATE credentials SET scopes='[\"auth:manage\"]'",
		"scope_order": "UPDATE credentials SET scopes='[\"records:read\",\"records:read\"]'",
		"blob":        "UPDATE credentials SET name=CAST('reader' AS BLOB)",
		"nul_tail":    "UPDATE credentials SET name='reader'||char(0)||printf('%0500d',0)",
		"timestamp":   "UPDATE credentials SET created=-1",
		"realm":       "UPDATE realm SET node='different'",
	}
	for name, stmt := range cases {
		t.Run(name, func(t *testing.T) {
			s, path, key := testStore(t)
			issue(t, s)
			s.Close()
			db, e := sql.Open("sqlite", path)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = db.Exec(stmt); e != nil {
				t.Fatal(e)
			}
			db.Close()
			if _, e = Open(path, key, testIdentity, nil); e == nil {
				t.Fatal("corrupt state admitted")
			}
		})
	}
}
func TestCreateOpenNeverResetAndKeyBounds(t *testing.T) {
	s, path, key := testStore(t)
	s.Close()
	before, e := os.ReadFile(key)
	if e != nil {
		t.Fatal(e)
	}
	if e = CreateKey(key); e != ErrExists {
		t.Fatal(e)
	}
	after, _ := os.ReadFile(key)
	if string(before) != string(after) {
		t.Fatal("key replaced")
	}
	missing := filepath.Join(filepath.Dir(path), "missing.db")
	if _, e = Open(missing, key, testIdentity, nil); e == nil {
		t.Fatal("missing opened")
	}
	if _, e = os.Stat(missing); !os.IsNotExist(e) {
		t.Fatal("open created database")
	}
	empty := filepath.Join(filepath.Dir(path), "empty.db")
	if e = os.WriteFile(empty, nil, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = Create(empty, key, testIdentity, nil); e != ErrExists {
		t.Fatal(e)
	}
	for _, n := range []int{0, 31, 33, 4096} {
		p := filepath.Join(filepath.Dir(path), fmt.Sprintf("key-%d", n))
		if e = os.WriteFile(p, make([]byte, n), 0600); e != nil {
			t.Fatal(e)
		}
		if _, e = Open(path, p, testIdentity, nil); e == nil {
			t.Fatal("invalid key size admitted")
		}
	}
}
func TestGrantCancellationAndStoreRedaction(t *testing.T) {
	s, _, _ := testStore(t)
	g, e := s.CreateBootstrap(BootstrapEnvelope{Scopes: []Scope{RecordsRead}}, testNow)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.CancelBootstrapLocal(testNow); e != nil {
		t.Fatal(e)
	}
	if _, _, e = s.BootstrapIssueAgent(g, CredentialRequest{Name: "reader", Scopes: []Scope{RecordsRead}}, testNow); e != ErrDenied {
		t.Fatal(e)
	}
	if _, e = s.CreateBootstrap(BootstrapEnvelope{Scopes: []Scope{RecordsRead}}, testNow); e != nil {
		t.Fatal(e)
	}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		out := fmt.Sprintf(format, s)
		if !strings.Contains(out, "redacted") {
			t.Fatal("store formatting exposes internal state")
		}
	}
}

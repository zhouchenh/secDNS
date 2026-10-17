package server

import (
	"github.com/zhouchenh/secDNS/internal/recordstore"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPersistentMutationErrorsNotSuccess(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	s, e := recordstore.OpenSQLite(filepath.Join(dir, "db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	h := &HTTPAdminServer{Token: testToken, store: s}
	body := `{"name":"host.example.","type":"A","values":["192.0.2.1"],"ttl_seconds":300}`
	if r := do(h, http.MethodPost, "/admin/records", testToken, body); r.Code != 200 {
		t.Fatal("durable set")
	}
	s.Close()
	if r := do(h, http.MethodPost, "/admin/records", testToken, body); r.Code != 503 {
		t.Fatal("failed set reported success")
	}
	if r := do(h, http.MethodDelete, "/admin/records/host.example./A", testToken, ""); r.Code != 503 {
		t.Fatal("failed delete reported success")
	}
}
func TestExpiryOverflowRejected(t *testing.T) {
	v := int64(1<<63 - 1)
	_, e := (&setRequest{Name: "host.example.", Type: "A", Values: []string{"192.0.2.1"}, ExpiresInSeconds: &v}).toRecord(time.Now())
	if e == nil {
		t.Fatal("overflow accepted")
	}
}

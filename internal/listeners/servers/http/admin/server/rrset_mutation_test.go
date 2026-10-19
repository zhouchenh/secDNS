package server

import (
	"encoding/json"
	"github.com/zhouchenh/secDNS/internal/adminauth"
	"github.com/zhouchenh/secDNS/internal/recordset"
	"github.com/zhouchenh/secDNS/internal/recordstore"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const rrsetBody = `{"expected":{"ruleset_id":"r","lineage_id":"l","revision":"1"},"operation_id":"op","action":"upsert","record":{"name":"x.invalid.","type":"A","values":["192.0.2.1"],"ttl_seconds":0}}`

func bindRRsetTest(t *testing.T, h *HTTPAdminServer) {
	t.Helper()
	v, e := recordstore.NewVersionedMemory(recordstore.Enrollment{RulesetID: "r", LineageID: "l"})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { v.Close() })
	h.versioned = v
}
func TestRRsetHTTPContract(t *testing.T) {
	h := &HTTPAdminServer{Token: testToken}
	bindRRsetTest(t, h)
	first := do(h, "POST", "/admin/snapshot/rrset", testToken, rrsetBody)
	if first.Code != 200 {
		t.Fatal(first.Code, first.Body.String())
	}
	replay := do(h, "POST", "/admin/snapshot/rrset", testToken, rrsetBody)
	if replay.Body.String() != first.Body.String() {
		t.Fatal("receipt replay changed")
	}
	if w := do(h, "POST", "/admin/snapshot/rrset", testToken, strings.Replace(rrsetBody, `"op"`, `"stale"`, 1)); w.Code != 409 {
		t.Fatal(w.Code)
	}
	for _, bad := range []string{`{"expected":null}`, strings.Replace(rrsetBody, `"action":"upsert"`, `"action":"upsert","action":"delete"`, 1), strings.Replace(rrsetBody, `"revision":"1"`, `"revision":null`, 1), strings.Replace(rrsetBody, `x.invalid.`, `\ud800`, 1), strings.TrimSuffix(rrsetBody, "}") + `,"unknown":"never-echo-this"}`} {
		w := do(h, "POST", "/admin/snapshot/rrset", testToken, bad)
		if w.Code != 400 || strings.Contains(w.Body.String(), "never-echo-this") {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	if w := do(h, "POST", "/admin/snapshot/rrset", testToken, strings.Repeat(" ", recordset.MaxBytes+1)); w.Code != 413 {
		t.Fatal(w.Code)
	}
	del := `{"expected":{"ruleset_id":"r","lineage_id":"l","revision":"2"},"operation_id":"del","action":"delete","key":{"name":"X.INVALID","type":"a"}}`
	if w := do(h, "POST", "/admin/snapshot/rrset", testToken, del); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	view, _ := h.versioned.Acquire()
	if len(view.Records()) != 0 || view.Metadata().Revision != 3 {
		t.Fatal("delete not applied")
	}
	legacy := &HTTPAdminServer{Token: testToken}
	w := httptest.NewRecorder()
	q := httptest.NewRequest("POST", "/admin/snapshot/rrset", nil)
	q.Body = noRead{t}
	legacy.routes().ServeHTTP(w, q)
	if w.Code != 404 {
		t.Fatal("legacy gained route", w.Code)
	}
}
func TestRRsetScopedWriteBeforeBodyAndSessionCSRF(t *testing.T) {
	for _, scope := range []adminauth.Scope{adminauth.RecordsRead, adminauth.UIView} {
		h, token := agentTestServer(t, []adminauth.Scope{scope})
		bindRRsetTest(t, h)
		h.SnapshotReaders = []SnapshotReader{{NodeID: "reader", Token: "synthetic-reader-token"}}
		for _, auth := range []string{"", "bad", token, h.SnapshotReaders[0].Token} {
			q := httptest.NewRequest("POST", "/admin/snapshot/rrset", nil)
			if auth != "" {
				q.Header.Set("Authorization", "Bearer "+auth)
			}
			q.Body = noRead{t}
			w := httptest.NewRecorder()
			h.routes().ServeHTTP(w, q)
			if w.Code != 401 && w.Code != 403 {
				t.Fatal(w.Code)
			}
		}
	}
	h, token := agentTestServer(t, []adminauth.Scope{adminauth.UIView, adminauth.RecordsWrite})
	bindRRsetTest(t, h)
	// A write-only API agent does not require records:read.
	if w := do(h, "POST", "/admin/snapshot/rrset", token, rrsetBody); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	mux := h.routes()
	request := func(path string, body string) *http.Request {
		q := httptest.NewRequest("POST", "https://secdns.aircloud.pro/admin/"+path, strings.NewReader(body))
		q.Header.Set("Origin", h.agent.origin)
		q.Header.Set("Sec-Fetch-Site", "same-origin")
		q.Header.Set("Content-Type", "application/json")
		return q
	}
	q := request("auth/agent-session", "")
	q.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, q)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	cookies := w.Result().Cookies()
	var metadata map[string]any
	if e := json.Unmarshal(w.Body.Bytes(), &metadata); e != nil {
		t.Fatal(e)
	}
	csrf := metadata["csrf"].(string)
	for _, bad := range []string{"csrf", "origin", "fetch", "mixed"} {
		q = request("snapshot/rrset", "")
		q.AddCookie(cookies[0])
		q.Header.Set("X-SecDNS-CSRF", csrf)
		switch bad {
		case "csrf":
			q.Header.Del("X-SecDNS-CSRF")
		case "origin":
			q.Header.Set("Origin", "https://other.invalid")
		case "fetch":
			q.Header.Set("Sec-Fetch-Site", "cross-site")
		case "mixed":
			q.Header.Set("Authorization", "Bearer "+token)
		}
		q.Body = noRead{t}
		w = httptest.NewRecorder()
		mux.ServeHTTP(w, q)
		if w.Code != 401 && w.Code != 403 {
			t.Fatal(bad, w.Code)
		}
	}
	body := strings.Replace(strings.Replace(rrsetBody, `"revision":"1"`, `"revision":"2"`, 1), `"op"`, `"session"`, 1)
	q = request("snapshot/rrset", body)
	q.AddCookie(cookies[0])
	q.Header.Set("X-SecDNS-CSRF", csrf)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, q)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
}

func TestRRsetHTTPSQLiteRequiresOfflineMigration(t *testing.T) {
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(dir, "records.db")
	enrollment := recordstore.Enrollment{RulesetID: "r", LineageID: "l"}
	s, e := recordstore.OpenVersionedSQLite(path, enrollment)
	if e != nil {
		t.Fatal(e)
	}
	h := &HTTPAdminServer{Token: testToken}
	h.versioned = s
	w := do(h, "POST", "/admin/snapshot/rrset", testToken, rrsetBody)
	if w.Code != 409 || !strings.Contains(w.Body.String(), "rrset_schema_required") {
		t.Fatal(w.Code, w.Body.String())
	}
	s.Close()
	if e = recordstore.EnableRRsetMutationsSQLite(path, enrollment); e != nil {
		t.Fatal(e)
	}
	s, e = recordstore.OpenVersionedSQLite(path, enrollment)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	h.versioned = s
	w = do(h, "POST", "/admin/snapshot/rrset", testToken, rrsetBody)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
}

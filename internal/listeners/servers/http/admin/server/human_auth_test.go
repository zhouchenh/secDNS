package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zhouchenh/secDNS/internal/adminauth"
)

func humanTestServer(t *testing.T) (*HTTPAdminServer, string) {
	t.Helper()
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	path, key := filepath.Join(dir, "auth.db"), filepath.Join(dir, "auth.key")
	if e := adminauth.CreateKey(key); e != nil {
		t.Fatal(e)
	}
	id := adminauth.Identity{RealmID: "human-test", NodeID: "test-node", DisplayName: "Synthetic realm"}
	s, e := adminauth.Create(path, key, id, nil)
	if e != nil {
		t.Fatal(e)
	}
	s.Close()
	if e = adminauth.EnableHumanSchema(path, key, id, nil); e != nil {
		t.Fatal(e)
	}
	s, e = adminauth.Open(path, key, id, nil)
	if e != nil {
		t.Fatal(e)
	}
	h := &HTTPAdminServer{Path: "/admin", Token: "synthetic-legacy", AgentAuthConfigured: true}
	h.BindAgentAuth(s, "https://example.invalid")
	grant, e := s.CreateHumanGrant(false, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { h.ClearAgentAuth(); s.Close() })
	return h, grant
}
func TestHumanHTTPOriginAndStrictBody(t *testing.T) {
	h, _ := humanTestServer(t)
	mux := h.routes()
	for _, body := range []string{`{"username":"a","username":"b","password":"abc"}`, `{"username":"a","password":"abc","extra":"x"}`, `[]`, string(bytes.Repeat([]byte("x"), 8193))} {
		r := httptest.NewRequest("POST", "/admin/auth/login/password", bytes.NewBufferString(body))
		r.Header.Set("Origin", h.agent.origin)
		r.Header.Set("Sec-Fetch-Site", "same-origin")
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != 400 {
			t.Fatal(w.Code)
		}
	}
	r := httptest.NewRequest("POST", "/admin/auth/setup/begin", nil)
	r.Header.Set("Origin", "http://example.invalid")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.Header.Set("Content-Type", "application/json")
	r.Body = noRead{t}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal(w.Code)
	}
	r = httptest.NewRequest("POST", "/admin/auth/password", nil)
	r.Header.Set("Authorization", "Bearer synthetic-legacy")
	r.Body = noRead{t}
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("legacy reached security body", w.Code)
	}
	r = httptest.NewRequest("GET", "/admin/auth/state", nil)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	var state map[string]any
	json.Unmarshal(w.Body.Bytes(), &state)
	if state["human_access"] != true || state["setup_required"] != true {
		t.Fatal("setup state")
	}
	if _, ok := state["username"]; ok {
		t.Fatal("identity disclosure")
	}
	_ = http.MethodGet
}

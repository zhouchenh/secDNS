package server

import (
	"encoding/json"
	"github.com/zhouchenh/secDNS/internal/adminauth"
	"github.com/zhouchenh/secDNS/internal/snapshotfollower"
	listenerserver "github.com/zhouchenh/secDNS/pkg/listeners/server"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func statusOnlyServer(t *testing.T) *HTTPAdminServer {
	t.Helper()
	// Exercise the actual registered listener descriptor, also used by the browser fixture.
	var data any
	if e := json.Unmarshal([]byte(`{"type":"httpAdminServer","config":{"listen":"127.0.0.1","port":18055,"token":"synthetic-admin","path":"/owned-static","followerStatusOnly":true,"ui":true}}`), &data); e != nil {
		t.Fatal(e)
	}
	d, ok := listenerserver.GetServerDescriptorByTypeName("httpAdminServer")
	if !ok {
		t.Fatal("listener descriptor missing")
	}
	raw, successes, failures := d.Describe(data.(map[string]any)["config"])
	if successes == 0 || failures != 0 {
		t.Fatalf("listener decode: %d/%d", successes, failures)
	}
	h := raw.(*HTTPAdminServer)
	if !h.FollowerStatusOnly {
		t.Fatal("configured status-only mode lost")
	}
	h.ConfigureFollowerStatus([]string{"replica"})
	if e := h.BindFollowerStatus(map[string]func() snapshotfollower.Status{"replica": func() snapshotfollower.Status {
		return snapshotfollower.Status{NodeID: "test-node", ConnectionState: "starting", StoreState: "not_ready"}
	}}); e != nil {
		t.Fatal(e)
	}
	return h
}
func TestFollowerStatusOnlyRoutes(t *testing.T) {
	h := statusOnlyServer(t)
	if e := h.prepareRecordBinding(); e != nil {
		t.Fatal(e)
	}
	if h.store != nil || h.versioned != nil {
		t.Fatal("record store bound")
	}
	mux := h.routes()
	for _, path := range []string{"/records", "/records/example/A", "/snapshot", "/snapshot/rrset", "/snapshot/events", "/preview", "/routeros/preview", "/source-policy/explain", "/auth/state", "/auth/session", "/auth/agent-session", "/auth/human/login", "/auth/human/setup", "/ui/app.js", "/ui/state.js", "/auth/agent.js"} {
		for _, method := range []string{"GET", "POST", "DELETE", "PUT", "PATCH"} {
			r := httptest.NewRequest(method, "/owned-static"+path, nil)
			r.Header.Set("Authorization", "Bearer "+h.Token)
			r.Body = noRead{t}
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)
			if w.Code != 404 {
				t.Fatalf("%s %s registered: %d", method, path, w.Code)
			}
		}
	}
	for _, method := range []string{"POST", "DELETE", "PUT", "PATCH"} {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(method, "/owned-static/followers", nil))
		if w.Code != 405 {
			t.Fatal("status mutation registered", w.Code)
		}
	}
	for _, path := range []string{"/ui", "/ui/"} {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest("GET", "/owned-static"+path, nil))
		if w.Code != 303 || w.Header().Get("Location") != "/owned-static/ui/followers/" {
			t.Fatal("landing", w.Code)
		}
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/owned-static/ui/followers/", nil))
	b := w.Body.String()
	if w.Code != 200 || strings.Contains(b, "Record workspace") || strings.Contains(b, "../../auth/") || !strings.Contains(b, "Read-only local status") {
		t.Fatal("misleading status page", w.Code)
	}
	h.UI = false
	w = httptest.NewRecorder()
	h.routes().ServeHTTP(w, httptest.NewRequest("GET", "/owned-static/ui/followers/", nil))
	if w.Code != 404 {
		t.Fatal("UI off exposed assets")
	}
}
func TestFollowerStatusOnlyAuthorization(t *testing.T) {
	for _, scope := range []adminauth.Scope{adminauth.RecordsRead, adminauth.RecordsWrite, adminauth.UIView} {
		h, token := agentTestServer(t, []adminauth.Scope{scope})
		h.FollowerStatusOnly = true
		h.ConfigureFollowerStatus([]string{"replica"})
		_ = h.BindFollowerStatus(map[string]func() snapshotfollower.Status{"replica": func() snapshotfollower.Status {
			return snapshotfollower.Status{ConnectionState: "starting", StoreState: "not_ready"}
		}})
		for _, bearer := range []string{"", "reader-token-0123456789abcdef-0001", h.Token, token} {
			r := httptest.NewRequest("GET", "/admin/followers", nil)
			r.Body = noRead{t}
			if bearer != "" {
				r.Header.Set("Authorization", "Bearer "+bearer)
			}
			w := httptest.NewRecorder()
			h.routes().ServeHTTP(w, r)
			allowed := bearer == h.Token || bearer == token && scope == adminauth.RecordsRead
			if (w.Code == 200) != allowed {
				t.Fatalf("scope %s code %d", scope, w.Code)
			}
		}
		r := httptest.NewRequest("GET", "/admin/followers", nil)
		r.Header.Set("Authorization", "Bearer "+h.Token)
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: "invalid"})
		w := httptest.NewRecorder()
		h.routes().ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatal("mixed cookie/bearer admitted")
		}
	}
}
func TestFollowerStatusOnlyStartupRefusesInvalid(t *testing.T) {
	for _, mutate := range []func(*HTTPAdminServer){func(h *HTTPAdminServer) { h.Store = "parked" }, func(h *HTTPAdminServer) { h.SourcePolicyExplain = true }, func(h *HTTPAdminServer) {
		h.SnapshotReaders = []SnapshotReader{{"reader", "reader-token-0123456789abcdef-0001"}}
	}, func(h *HTTPAdminServer) { h.followerStatusNames = nil }, func(h *HTTPAdminServer) { h.followerStatus = nil }} {
		h := statusOnlyServer(t)
		mutate(h)
		if h.prepareRecordBinding() == nil {
			t.Fatal("invalid startup accepted")
		}
		if h.store != nil || h.versioned != nil {
			t.Fatal("binding before refusal")
		}
	}
}

func TestFollowerStatusOnlyExistingSession(t *testing.T) {
	h, bearer := agentTestServer(t, []adminauth.Scope{adminauth.UIView, adminauth.RecordsRead})
	h.FollowerStatusOnly = true
	h.ConfigureFollowerStatus([]string{"replica"})
	_ = h.BindFollowerStatus(map[string]func() snapshotfollower.Status{"replica": func() snapshotfollower.Status {
		return snapshotfollower.Status{ConnectionState: "starting", StoreState: "not_ready"}
	}})
	cookie, _, _, err := h.agent.sessions.Exchange(bearer, "realm", "node", h.agent.now())
	if err != nil {
		t.Fatal(err)
	}
	for _, site := range []string{"same-origin", "cross-site", ""} {
		r := httptest.NewRequest("GET", "/admin/followers", nil)
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: cookie})
		r.Header.Set("Sec-Fetch-Site", site)
		r.Header.Set("Origin", h.agent.origin)
		w := httptest.NewRecorder()
		h.routes().ServeHTTP(w, r)
		if (w.Code == 200) != (site == "same-origin") {
			t.Fatal("cookie boundary", site, w.Code)
		}
	}
}

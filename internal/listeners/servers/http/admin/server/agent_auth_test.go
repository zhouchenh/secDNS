package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zhouchenh/secDNS/internal/adminauth"
	"github.com/zhouchenh/secDNS/internal/recordstore"
)

func agentTestServer(t *testing.T, permissions []adminauth.Scope) (*HTTPAdminServer, string) {
	t.Helper()
	d := t.TempDir()
	os.Chmod(d, 0700)
	key := filepath.Join(d, "key")
	if e := adminauth.CreateKey(key); e != nil {
		t.Fatal(e)
	}
	s, e := adminauth.Create(filepath.Join(d, "auth.db"), key, adminauth.Identity{RealmID: "realm", NodeID: "node", DisplayName: "Test"}, nil)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	now := time.Now()
	grant, e := s.CreateBootstrap(adminauth.BootstrapEnvelope{Scopes: permissions}, now)
	if e != nil {
		t.Fatal(e)
	}
	token, _, e := s.BootstrapIssueAgent(grant, adminauth.CredentialRequest{Name: "test-agent", Scopes: permissions}, now)
	if e != nil {
		t.Fatal(e)
	}
	h := &HTTPAdminServer{Token: "legacy-value", AgentAuthConfigured: true}
	h.BindAgentAuth(s, "https://secdns.aircloud.pro")
	return h, token
}

type noRead struct{ t *testing.T }

func (n noRead) Read([]byte) (int, error) { n.t.Error("unauthorized body read"); return 0, io.EOF }
func (noRead) Close() error               { return nil }
func TestAgentRouteScopeAndAmbiguity(t *testing.T) {
	h, token := agentTestServer(t, []adminauth.Scope{adminauth.UIView, adminauth.RecordsRead})
	handler := h.withScopes(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }, false, adminauth.RecordsWrite)
	for _, header := range []string{"", "Bearer bad", "Bearer " + token} {
		r := httptest.NewRequest("POST", "https://secdns.aircloud.pro/admin/snapshot", nil)
		r.Header.Set("Authorization", header)
		r.Body = noRead{t}
		w := httptest.NewRecorder()
		handler(w, r)
		if w.Code == 204 {
			t.Fatal("write admitted")
		}
	}
	r := httptest.NewRequest("GET", "/admin/snapshot", nil)
	r.Header.Set("Authorization", "Bearer legacy-value")
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: "invalid"})
	r.Body = noRead{t}
	w := httptest.NewRecorder()
	h.withScopes(func(w http.ResponseWriter, r *http.Request) { t.Fatal("ambiguous admitted") }, true, adminauth.RecordsRead)(w, r)
	if w.Code != 403 {
		t.Fatal(w.Code)
	}
	r = httptest.NewRequest("GET", "/admin/snapshot", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	h.withScopes(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }, true, adminauth.RecordsRead)(w, r)
	if w.Code != 204 {
		t.Fatal(w.Code)
	}
	w = httptest.NewRecorder()
	h.withScopes(func(w http.ResponseWriter, r *http.Request) { t.Fatal("event scope missing") }, true, adminauth.RecordsRead, adminauth.SnapshotEvents)(w, r)
	if w.Code != 403 {
		t.Fatal(w.Code)
	}
}
func TestAgentExchangeCookieCSRFAndLogout(t *testing.T) {
	h, token := agentTestServer(t, []adminauth.Scope{adminauth.UIView, adminauth.RecordsRead})
	mux := http.NewServeMux()
	h.agentRoutes(mux, "/admin")
	request := func(method, path string) *http.Request {
		r := httptest.NewRequest(method, "https://secdns.aircloud.pro/admin/"+path, nil)
		r.Header.Set("Origin", h.agent.origin)
		r.Header.Set("Sec-Fetch-Site", "same-origin")
		r.Header.Set("Content-Type", "application/json")
		return r
	}
	r := request("POST", "auth/agent-session")
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatal("cookie")
	}
	cookie := cookies[0]
	if !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/" || cookie.Domain != "" || cookie.Value == token {
		t.Fatal("unsafe cookie")
	}
	if strings.Contains(w.Body.String(), token) {
		t.Fatal("bearer response leak")
	}
	var result map[string]any
	json.Unmarshal(w.Body.Bytes(), &result)
	if result["record_role"] != "writable_authority" {
		t.Fatal("missing server-derived record role")
	}
	sessionRequest := request("GET", "auth/session")
	sessionRequest.AddCookie(cookie)
	sessionResponse := httptest.NewRecorder()
	mux.ServeHTTP(sessionResponse, sessionRequest)
	var sessionMetadata map[string]any
	json.Unmarshal(sessionResponse.Body.Bytes(), &sessionMetadata)
	if sessionResponse.Code != 200 || sessionMetadata["record_role"] != "writable_authority" {
		t.Fatal("session record role")
	}
	csrf := result["csrf"].(string)
	for _, bad := range []string{"csrf", "origin", "fetch"} {
		r = request("POST", "auth/logout")
		r.AddCookie(cookie)
		r.Header.Set("X-SecDNS-CSRF", csrf)
		switch bad {
		case "csrf":
			r.Header.Del("X-SecDNS-CSRF")
		case "origin":
			r.Header.Set("Origin", "https://other.invalid")
		case "fetch":
			r.Header.Set("Sec-Fetch-Site", "cross-site")
		}
		r.Body = noRead{t}
		w = httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code == 200 {
			t.Fatal(bad)
		}
	}
	r = request("POST", "auth/logout")
	r.AddCookie(cookie)
	r.Header.Set("X-SecDNS-CSRF", csrf)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	r = request("GET", "auth/session")
	r.AddCookie(cookie)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal(w.Code)
	}
}

func TestAgentLegacyPrefixAndUnavailable(t *testing.T) {
	h, _ := agentTestServer(t, []adminauth.Scope{adminauth.UIView})
	h.Token = "sdna_configured-legacy-token"
	request := httptest.NewRequest("POST", "/admin", nil)
	request.Header.Set("Authorization", "Bearer "+h.Token)
	response := httptest.NewRecorder()
	h.withScopes(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }, false, adminauth.RecordsWrite)(response, request)
	if response.Code != 204 {
		t.Fatalf("legacy prefix refused: %d", response.Code)
	}
	h.SnapshotReaders = []SnapshotReader{{NodeID: "reader", Token: "sdna_configured-reader-token"}}
	request.Header.Set("Authorization", "Bearer "+h.SnapshotReaders[0].Token)
	response = httptest.NewRecorder()
	h.withScopes(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }, true, adminauth.RecordsRead)(response, request)
	if response.Code != 204 {
		t.Fatalf("reader prefix refused: %d", response.Code)
	}
	response = httptest.NewRecorder()
	h.withScopes(func(w http.ResponseWriter, r *http.Request) { t.Fatal("reader wrote") }, false, adminauth.RecordsWrite)(response, request)
	if response.Code != 403 {
		t.Fatal(response.Code)
	}
}
func TestAgentAllScopeIntersections(t *testing.T) {
	for _, requested := range []adminauth.Scope{adminauth.UIView, adminauth.RecordsRead, adminauth.RecordsWrite, adminauth.SnapshotEvents, adminauth.RouterOSPreview, adminauth.SourcePolicyExplain, adminauth.AuditRead} {
		t.Run(string(requested), func(t *testing.T) {
			h, token := agentTestServer(t, []adminauth.Scope{requested})
			for _, needed := range []adminauth.Scope{adminauth.RecordsRead, adminauth.RecordsWrite, adminauth.RouterOSPreview, adminauth.SourcePolicyExplain} {
				r := httptest.NewRequest("POST", "/admin", nil)
				r.Header.Set("Authorization", "Bearer "+token)
				r.Body = noRead{t}
				w := httptest.NewRecorder()
				h.withScopes(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }, false, needed)(w, r)
				expected := 403
				if needed == requested {
					expected = 204
				}
				if w.Code != expected {
					t.Fatalf("%s: %d", needed, w.Code)
				}
			}
			r := httptest.NewRequest("GET", "/admin/events", nil)
			r.Header.Set("Authorization", "Bearer "+token)
			w := httptest.NewRecorder()
			h.withScopes(func(w http.ResponseWriter, r *http.Request) { t.Fatal("single scope admitted events") }, true, adminauth.RecordsRead, adminauth.SnapshotEvents)(w, r)
			if w.Code != 403 {
				t.Fatal(w.Code)
			}
		})
	}
}

func TestAgentActualRoutesRejectBeforeBodyRead(t *testing.T) {
	h, token := agentTestServer(t, []adminauth.Scope{adminauth.UIView})
	h.Path = "/admin"
	h.UI = true
	h.SourcePolicyExplain = true
	v, e := recordstore.NewVersionedMemory(recordstore.Enrollment{RulesetID: "r", LineageID: "l"})
	if e != nil {
		t.Fatal(e)
	}
	defer v.Close()
	h.versioned = v
	handler := h.routes()
	for _, path := range []string{"/snapshot", "/records", "/import/routeros/preview", "/source-policy/explain"} {
		r := httptest.NewRequest("POST", "/admin"+path, nil)
		r.Header.Set("Authorization", "Bearer "+token)
		r.Body = noRead{t}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatalf("%s: %d", path, w.Code)
		}
	}
	r := httptest.NewRequest("GET", "/admin/snapshot", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("X-SecDNS-Legacy-Access", "1")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal("agent accepted as legacy", w.Code)
	}
}

func TestDeniedMutationDoesNotRefreshSession(t *testing.T) {
	for _, allowed := range []bool{false, true} {
		t.Run(map[bool]string{false: "denied", true: "allowed"}[allowed], func(t *testing.T) {
			permissions := []adminauth.Scope{adminauth.UIView, adminauth.RecordsRead}
			if allowed {
				permissions = append(permissions, adminauth.RecordsWrite)
			}
			h, bearer := agentTestServer(t, permissions)
			now := time.Now()
			h.agent.now = func() time.Time { return now }
			token, csrf, _, e := h.agent.sessions.Exchange(bearer, "realm", "node", now)
			if e != nil {
				t.Fatal(e)
			}
			now = now.Add(14 * time.Minute)
			r := httptest.NewRequest("POST", "https://secdns.aircloud.pro/admin/snapshot", nil)
			r.Header.Set("Origin", h.agent.origin)
			r.Header.Set("Sec-Fetch-Site", "same-origin")
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("X-SecDNS-CSRF", csrf)
			r.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
			r.Body = noRead{t}
			w := httptest.NewRecorder()
			h.withScopes(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }, false, adminauth.RecordsWrite)(w, r)
			expected := 403
			if allowed {
				expected = 204
			}
			if w.Code != expected {
				t.Fatal(w.Code)
			}
			_, e = h.agent.sessions.Authenticate(token, "", false, false, now.Add(time.Minute))
			if !allowed && e != adminauth.ErrDenied {
				t.Fatal("denied mutation extended idle", e)
			}
			if allowed && e != nil {
				t.Fatal("permitted activity did not refresh", e)
			}
		})
	}
}
func TestVersionedBlockedCRUDUsesMethodScope(t *testing.T) {
	for _, scope := range []adminauth.Scope{adminauth.RecordsRead, adminauth.RecordsWrite} {
		t.Run(string(scope), func(t *testing.T) {
			h, token := agentTestServer(t, []adminauth.Scope{scope})
			h.Path = "/admin"
			v, e := recordstore.NewVersionedMemory(recordstore.Enrollment{RulesetID: "r", LineageID: "l"})
			if e != nil {
				t.Fatal(e)
			}
			defer v.Close()
			h.versioned = v
			for _, method := range []string{"GET", "POST", "DELETE"} {
				path := "/admin/records"
				if method == "DELETE" {
					path += "/name/A"
				}
				r := httptest.NewRequest(method, path, nil)
				r.Header.Set("Authorization", "Bearer "+token)
				r.Body = noRead{t}
				w := httptest.NewRecorder()
				h.routes().ServeHTTP(w, r)
				expected := 403
				if method == "GET" && scope == adminauth.RecordsRead || method != "GET" && scope == adminauth.RecordsWrite {
					expected = 409
				}
				if w.Code != expected {
					t.Fatalf("%s got %d want %d", method, w.Code, expected)
				}
			}
		})
	}
}

func TestAgentExchangeMissingUIViewIsScopeDenial(t *testing.T) {
	h, token := agentTestServer(t, []adminauth.Scope{adminauth.RecordsRead})
	mux := http.NewServeMux()
	h.agentRoutes(mux, "/admin")
	r := httptest.NewRequest("POST", "/admin/auth/agent-session", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Origin", h.agent.origin)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.Header.Set("Content-Type", "application/json")
	r.Body = noRead{t}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 403 || !strings.Contains(w.Body.String(), "scope_required") {
		t.Fatal(w.Code, w.Body.String())
	}
	if len(w.Result().Cookies()) != 0 {
		t.Fatal("scope denial set session")
	}
}

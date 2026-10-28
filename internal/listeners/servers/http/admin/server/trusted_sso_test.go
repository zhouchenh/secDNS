package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// Synthetic values only. Assertions below check none of them reach logs or bodies.
const (
	ssoTestSecret = "synthetic-sso-header-secret-0123456789abcdefghijklmnop"
	ssoTestUser   = "owner-sso-synthetic"
	ssoTestRole   = "secdns-console:access"
)

type ssoLogRecord struct {
	accepted bool
	reason   string
}

type ssoLogs struct {
	mu      sync.Mutex
	records []ssoLogRecord
}

func (l *ssoLogs) add(accepted bool, reason string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.records = append(l.records, ssoLogRecord{accepted, reason})
}
func (l *ssoLogs) last() ssoLogRecord {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.records) == 0 {
		return ssoLogRecord{reason: "<none>"}
	}
	return l.records[len(l.records)-1]
}

func ssoTestConfig(t *testing.T) *TrustedSSO {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sso-header-secret")
	if e := os.WriteFile(path, []byte(ssoTestSecret+"\n"), 0600); e != nil {
		t.Fatal(e)
	}
	c, ok := ParseTrustedSSO(map[string]interface{}{
		"headerSecretFile": filepath.ToSlash(path),
		"secretHeader":     "X-Secdns-SSO-Secret",
		"userHeader":       "X-Secdns-SSO-User",
		"rolesHeader":      "X-Secdns-SSO-Roles",
		"requiredRole":     ssoTestRole,
		"allowedUsers":     []interface{}{ssoTestUser},
		"mapsTo":           "owner",
	})
	if !ok {
		t.Fatal("valid trustedSSO refused")
	}
	return c
}

// ssoTestServer has an enrolled owner, nginx as the loopback trusted proxy and
// a loaded SSO secret.
func ssoTestServer(t *testing.T, enrolled bool) (*HTTPAdminServer, *ssoLogs) {
	t.Helper()
	var h *HTTPAdminServer
	if enrolled {
		h, _ = nodeTestSetup(t)
	} else {
		h, _ = humanTestServer(t)
	}
	h.TrustedProxySources = []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	h.TrustedSSO = ssoTestConfig(t)
	if e := h.LoadTrustedSSOSecret(); e != nil {
		t.Fatal(e)
	}
	logs := &ssoLogs{}
	h.trustedSSOLogger = logs.add
	return h, logs
}

func ssoRequest(h *HTTPAdminServer, method, path, body string) *http.Request {
	r := httptest.NewRequest(method, "https://example.invalid/admin"+path, strings.NewReader(body))
	r.RemoteAddr = "127.0.0.1:49152"
	r.Header.Set("Origin", h.agent.origin)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.Header.Set("Content-Type", "application/json")
	setForwardedTuple(r, "example.invalid", "203.0.113.7")
	r.Header.Set("X-Secdns-SSO-Secret", ssoTestSecret)
	r.Header.Set("X-Secdns-SSO-User", ssoTestUser)
	r.Header.Set("X-Secdns-SSO-Roles", "role:other,"+ssoTestRole+", role:x")
	return r
}

func serve(h *HTTPAdminServer, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.routes().ServeHTTP(w, r)
	return w
}

func assertNoSSOLeak(t *testing.T, where string, values ...string) {
	t.Helper()
	for _, v := range values {
		for _, secret := range []string{ssoTestSecret, ssoTestUser} {
			if strings.Contains(v, secret) {
				t.Fatalf("%s leaked an SSO value", where)
			}
		}
	}
}

func TestTrustedSSOValidAssertionIssuesNormalOwnerSession(t *testing.T) {
	h, logs := ssoTestServer(t, true)
	before, e := h.agent.store.AuditLocal(100)
	if e != nil {
		t.Fatal(e)
	}
	w := serve(h, ssoRequest(h, "POST", "/auth/login/sso", `{}`))
	if w.Code != 200 {
		t.Fatalf("valid assertion = %d %s", w.Code, w.Body.String())
	}
	if rec := logs.last(); !rec.accepted || rec.reason != "" {
		t.Fatalf("accepted login not logged: %+v", rec)
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != sessionCookie || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode || cookies[0].Path != "/" || cookies[0].Value == "" {
		t.Fatalf("session cookie attributes: %+v", cookies)
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("session response cacheable")
	}
	var out map[string]any
	if e := json.Unmarshal(w.Body.Bytes(), &out); e != nil || out["principal_type"] != "human" || out["csrf"] == "" || out["display_name"] != "Test owner" {
		t.Fatalf("session body: %v %v", e, out)
	}
	assertNoSSOLeak(t, "response", w.Body.String(), w.Header().Get("Set-Cookie"))

	// The cookie authenticates like any owner session: read with the cookie only,
	// mutate only with the CSRF value.
	csrf := out["csrf"].(string)
	r := ssoRequest(h, "GET", "/auth/session", "")
	r.Header.Del("Content-Type")
	r.AddCookie(cookies[0])
	if got := serve(h, r); got.Code != 200 {
		t.Fatalf("SSO session not usable: %d %s", got.Code, got.Body.String())
	}
	r = ssoRequest(h, "POST", "/auth/activity", "")
	r.AddCookie(cookies[0])
	if got := serve(h, r); got.Code != 401 {
		t.Fatalf("mutation without CSRF = %d", got.Code)
	}
	r = ssoRequest(h, "POST", "/auth/activity", "")
	r.AddCookie(cookies[0])
	r.Header.Set("X-SecDNS-CSRF", csrf)
	if got := serve(h, r); got.Code != 200 {
		t.Fatalf("mutation with CSRF = %d %s", got.Code, got.Body.String())
	}

	// Not a recent authentication: credential management needs password+TOTP.
	r = ssoRequest(h, "POST", "/auth/totp/begin", `{}`)
	r.AddCookie(cookies[0])
	r.Header.Set("X-SecDNS-CSRF", csrf)
	if got := serve(h, r); got.Code != 403 || !strings.Contains(got.Body.String(), "recent_authentication_required") {
		t.Fatalf("SSO session treated as recent: %d %s", got.Code, got.Body.String())
	}

	// Durable audit uses the release-compatible owner login action.
	events, e := h.agent.store.AuditLocal(100)
	if e != nil || len(events) != len(before)+1 || events[0].Action != "human_login" || events[0].CredentialID == "" {
		t.Fatalf("audit: %v %d->%d", e, len(before), len(events))
	}
	// The assertion still validates after a session exists; a second exchange is
	// refused only because a cookie is present (no session fixation or swap).
	r = ssoRequest(h, "POST", "/auth/login/sso", `{}`)
	r.AddCookie(cookies[0])
	if got := serve(h, r); got.Code != 403 || !strings.Contains(got.Body.String(), "ambiguous_credentials") {
		t.Fatalf("exchange with cookie = %d %s", got.Code, got.Body.String())
	}
}

func TestTrustedSSOHeaderValidationMatrix(t *testing.T) {
	cases := []struct {
		name, reason string
		mutate       func(*http.Request)
	}{
		{"spoofed-from-outside", "peer", func(r *http.Request) { r.RemoteAddr = "198.51.100.9:49152" }},
		{"spoofed-from-facade-address", "peer", func(r *http.Request) { r.RemoteAddr = "100.91.1.47:443" }},
		{"loopback-not-listed", "peer", func(r *http.Request) { r.RemoteAddr = "127.0.0.2:49152" }},
		{"ipv6-loopback-not-listed", "peer", func(r *http.Request) { r.RemoteAddr = "[::1]:49152" }},
		{"wrong-secret", "secret", func(r *http.Request) { r.Header.Set("X-Secdns-SSO-Secret", ssoTestSecret+"x") }},
		{"secret-prefix", "secret", func(r *http.Request) { r.Header.Set("X-Secdns-SSO-Secret", ssoTestSecret[:32]) }},
		{"missing-secret", "secret", func(r *http.Request) { r.Header.Del("X-Secdns-SSO-Secret") }},
		{"duplicate-secret", "secret", func(r *http.Request) { r.Header.Add("X-Secdns-SSO-Secret", ssoTestSecret) }},
		{"missing-user", "user", func(r *http.Request) { r.Header.Del("X-Secdns-SSO-User") }},
		{"empty-user", "user", func(r *http.Request) { r.Header.Set("X-Secdns-SSO-User", "") }},
		{"duplicate-user", "user", func(r *http.Request) { r.Header.Add("X-Secdns-SSO-User", ssoTestUser) }},
		{"user-list", "user", func(r *http.Request) { r.Header.Set("X-Secdns-SSO-User", ssoTestUser+",other") }},
		{"padded-user", "user", func(r *http.Request) { r.Header.Set("X-Secdns-SSO-User", " "+ssoTestUser) }},
		{"unknown-user", "user_not_allowed", func(r *http.Request) { r.Header.Set("X-Secdns-SSO-User", "someone-else") }},
		{"case-changed-user", "user_not_allowed", func(r *http.Request) { r.Header.Set("X-Secdns-SSO-User", strings.ToUpper(ssoTestUser)) }},
		{"missing-role-header", "role", func(r *http.Request) { r.Header.Del("X-Secdns-SSO-Roles") }},
		{"wrong-role", "role", func(r *http.Request) { r.Header.Set("X-Secdns-SSO-Roles", "role:secdns-console:read") }},
		{"role-substring", "role", func(r *http.Request) { r.Header.Set("X-Secdns-SSO-Roles", ssoTestRole+"x") }},
		{"empty-role-entry", "role", func(r *http.Request) { r.Header.Set("X-Secdns-SSO-Roles", ssoTestRole+",,") }},
		{"duplicate-role-header", "role", func(r *http.Request) { r.Header.Add("X-Secdns-SSO-Roles", ssoTestRole) }},
		{"unexpected-sso-header", "unexpected_header", func(r *http.Request) { r.Header.Set("X-Secdns-SSO-Email", "x@example.invalid") }},
		{"only-user-header", "secret", func(r *http.Request) {
			r.Header.Del("X-Secdns-SSO-Secret")
			r.Header.Del("X-Secdns-SSO-Roles")
		}},
		{"missing-forwarded-tuple", "forwarded", func(r *http.Request) { r.Header.Del("X-Forwarded-For") }},
		{"wrong-forwarded-host", "forwarded", func(r *http.Request) { r.Header.Set("X-Forwarded-Host", "other.invalid") }},
	}
	routes := []struct{ method, path, body string }{
		{"POST", "/auth/login/sso", `{}`},
		{"POST", "/auth/login/password", `{"username":"owner","password":"A synthetic long password phrase 8472!"}`},
		{"GET", "/auth/state", ""},
		{"GET", "/auth/session", ""},
		{"GET", "/ui/", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h, logs := ssoTestServer(t, true)
			before, e := h.agent.store.AuditLocal(100)
			if e != nil {
				t.Fatal(e)
			}
			for _, route := range routes {
				r := ssoRequest(h, route.method, route.path, route.body)
				c.mutate(r)
				w := serve(h, r)
				if w.Code != 403 || !strings.Contains(w.Body.String(), "sso_rejected") {
					t.Fatalf("%s %s: invalid assertion not refused: %d %s", route.method, route.path, w.Code, w.Body.String())
				}
				if len(w.Result().Cookies()) != 0 {
					t.Fatalf("%s: refusal set a cookie", route.path)
				}
				if rec := logs.last(); rec.accepted || rec.reason != c.reason {
					t.Fatalf("%s: logged %+v, want reason %q", route.path, rec, c.reason)
				}
				assertNoSSOLeak(t, "refusal", w.Body.String())
			}
			if events, e := h.agent.store.AuditLocal(100); e != nil || len(events) != len(before) {
				t.Fatalf("refused assertions changed audit: %v %d->%d", e, len(before), len(events))
			}
		})
	}
}

func TestTrustedSSOAbsentHeadersKeepBreakGlassLogin(t *testing.T) {
	h, logs := ssoTestServer(t, true)
	strip := func(r *http.Request) *http.Request {
		r.Header.Del("X-Secdns-SSO-Secret")
		r.Header.Del("X-Secdns-SSO-User")
		r.Header.Del("X-Secdns-SSO-Roles")
		return r
	}
	w := serve(h, strip(ssoRequest(h, "POST", "/auth/login/sso", `{}`)))
	if w.Code != 401 || !strings.Contains(w.Body.String(), "sso_required") || len(w.Result().Cookies()) != 0 {
		t.Fatalf("exchange without assertion = %d %s", w.Code, w.Body.String())
	}
	w = serve(h, strip(ssoRequest(h, "POST", "/auth/login/password", `{"username":"owner","password":"A synthetic long password phrase 8472!"}`)))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "challenge") {
		t.Fatalf("break-glass password step = %d %s", w.Code, w.Body.String())
	}
	r := strip(ssoRequest(h, "GET", "/auth/state", ""))
	w = serve(h, r)
	var state map[string]any
	json.Unmarshal(w.Body.Bytes(), &state)
	if w.Code != 200 || state["human_access"] != true || state["sso_login"] != false {
		t.Fatalf("state without assertion = %d %v", w.Code, state)
	}
	// Direct loopback break-glass (no forwarded tuple, no SSO headers) is not
	// affected by the gate.
	r = httptest.NewRequest("GET", "https://example.invalid/admin/auth/state", nil)
	r.RemoteAddr = "127.0.0.1:40000"
	if w = serve(h, r); w.Code != 200 {
		t.Fatalf("direct state = %d", w.Code)
	}
	if rec := logs.last(); rec.reason != "<none>" {
		t.Fatalf("absent headers were logged: %+v", rec)
	}
}

func TestTrustedSSOStateAdvertisesOnlyValidAssertion(t *testing.T) {
	h, _ := ssoTestServer(t, true)
	w := serve(h, ssoRequest(h, "GET", "/auth/state", ""))
	var state map[string]any
	json.Unmarshal(w.Body.Bytes(), &state)
	if w.Code != 200 || state["sso_login"] != true {
		t.Fatalf("state with valid assertion = %d %v", w.Code, state)
	}
	assertNoSSOLeak(t, "state", w.Body.String())

	// Before owner setup the assertion cannot create an owner.
	h, logs := ssoTestServer(t, false)
	w = serve(h, ssoRequest(h, "GET", "/auth/state", ""))
	state = nil
	json.Unmarshal(w.Body.Bytes(), &state)
	if state["setup_required"] != true || state["sso_login"] != false {
		t.Fatalf("state before setup = %v", state)
	}
	w = serve(h, ssoRequest(h, "POST", "/auth/login/sso", `{}`))
	if w.Code != 401 || len(w.Result().Cookies()) != 0 {
		t.Fatalf("SSO exchange before setup = %d %s", w.Code, w.Body.String())
	}
	if rec := logs.last(); rec.accepted || rec.reason != "owner_session" {
		t.Fatalf("pre-setup refusal logged %+v", rec)
	}
}

func TestTrustedSSOExchangeKeepsBrowserProtections(t *testing.T) {
	for _, c := range []struct {
		name   string
		code   int
		mutate func(*http.Request)
	}{
		{"no-origin", 403, func(r *http.Request) { r.Header.Del("Origin") }},
		{"foreign-origin", 403, func(r *http.Request) { r.Header.Set("Origin", "https://attacker.invalid") }},
		{"cross-site", 403, func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }},
		{"form-post", 403, func(r *http.Request) { r.Header.Set("Content-Type", "application/x-www-form-urlencoded") }},
		{"authorization", 403, func(r *http.Request) { r.Header.Set("Authorization", "Bearer sdna_synthetic") }},
		{"empty-body", 400, func(r *http.Request) { r.Body = http.NoBody }},
	} {
		t.Run(c.name, func(t *testing.T) {
			h, _ := ssoTestServer(t, true)
			r := ssoRequest(h, "POST", "/auth/login/sso", `{}`)
			c.mutate(r)
			w := serve(h, r)
			if w.Code != c.code || len(w.Result().Cookies()) != 0 {
				t.Fatalf("%s = %d %s", c.name, w.Code, w.Body.String())
			}
		})
	}
	h, _ := ssoTestServer(t, true)
	w := serve(h, ssoRequest(h, "POST", "/auth/login/sso", `{"user":"owner"}`))
	if w.Code != 400 || len(w.Result().Cookies()) != 0 {
		t.Fatalf("body with identity field = %d", w.Code)
	}
	w = serve(h, ssoRequest(h, "GET", "/auth/login/sso", ""))
	if w.Code != 405 {
		t.Fatalf("GET exchange = %d", w.Code)
	}
}

func TestTrustedSSODefaultOffIgnoresHeaders(t *testing.T) {
	h, _ := nodeTestSetup(t)
	h.TrustedProxySources = []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	w := serve(h, ssoRequest(h, "POST", "/auth/login/sso", `{}`))
	if w.Code == 200 || len(w.Result().Cookies()) != 0 {
		t.Fatalf("SSO exchange exists without configuration: %d", w.Code)
	}
	r := ssoRequest(h, "POST", "/auth/login/password", `{"username":"owner","password":"A synthetic long password phrase 8472!"}`)
	r.RemoteAddr = "198.51.100.9:49152"
	if w = serve(h, r); w.Code != 200 {
		t.Fatalf("headers changed default-off login: %d %s", w.Code, w.Body.String())
	}
	w = serve(h, ssoRequest(h, "GET", "/auth/state", ""))
	if strings.Contains(w.Body.String(), "sso_login") {
		t.Fatal("state advertises SSO without configuration")
	}
}

func TestTrustedSSOUnloadedSecretFailsClosed(t *testing.T) {
	h, logs := ssoTestServer(t, true)
	h.TrustedSSO.loaded = false
	w := serve(h, ssoRequest(h, "POST", "/auth/login/sso", `{}`))
	if w.Code != 403 || logs.last().reason != "unavailable" {
		t.Fatalf("unloaded secret = %d %+v", w.Code, logs.last())
	}
	var got error
	h.Serve(nil, func(e error) { got = e })
	if got != ErrTrustedSSO {
		t.Fatalf("Serve without a loaded SSO secret: %v", got)
	}
}

func TestTrustedSSOParseRefusals(t *testing.T) {
	base := func() map[string]interface{} {
		return map[string]interface{}{
			"headerSecretFile": "/etc/secdns-admin/sso-header-secret",
			"secretHeader":     "X-Secdns-SSO-Secret",
			"userHeader":       "X-Secdns-SSO-User",
			"rolesHeader":      "X-Secdns-SSO-Roles",
			"requiredRole":     ssoTestRole,
			"allowedUsers":     []interface{}{"zhouchenh"},
			"mapsTo":           "owner",
		}
	}
	if _, ok := ParseTrustedSSO(base()); !ok {
		t.Fatal("valid configuration refused")
	}
	for name, mutate := range map[string]func(map[string]interface{}){
		"missing":       func(m map[string]interface{}) { delete(m, "mapsTo") },
		"extra":         func(m map[string]interface{}) { m["optional"] = true },
		"prefix":        func(m map[string]interface{}) { m["userHeader"] = "X-Auth-Request-User" },
		"bare-prefix":   func(m map[string]interface{}) { m["userHeader"] = "X-Secdns-SSO-" },
		"header-chars":  func(m map[string]interface{}) { m["userHeader"] = "X-Secdns-SSO-User_" },
		"same-header":   func(m map[string]interface{}) { m["rolesHeader"] = "x-secdns-sso-secret" },
		"relative":      func(m map[string]interface{}) { m["headerSecretFile"] = "secret" },
		"dotdot":        func(m map[string]interface{}) { m["headerSecretFile"] = "/etc/../secret" },
		"maps-to":       func(m map[string]interface{}) { m["mapsTo"] = "Owner" },
		"role-space":    func(m map[string]interface{}) { m["requiredRole"] = "a b" },
		"role-empty":    func(m map[string]interface{}) { m["requiredRole"] = "" },
		"users-string":  func(m map[string]interface{}) { m["allowedUsers"] = "zhouchenh" },
		"users-empty":   func(m map[string]interface{}) { m["allowedUsers"] = []interface{}{} },
		"users-dup":     func(m map[string]interface{}) { m["allowedUsers"] = []interface{}{"a", "a"} },
		"users-number":  func(m map[string]interface{}) { m["allowedUsers"] = []interface{}{1.0} },
		"user-long":     func(m map[string]interface{}) { m["allowedUsers"] = []interface{}{strings.Repeat("u", 255)} },
		"secret-number": func(m map[string]interface{}) { m["headerSecretFile"] = 1.0 },
	} {
		m := base()
		mutate(m)
		if _, ok := ParseTrustedSSO(m); ok {
			t.Fatalf("%s accepted", name)
		}
	}
	if _, ok := ParseTrustedSSO(nil); ok {
		t.Fatal("null accepted")
	}
}

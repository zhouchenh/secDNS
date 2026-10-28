package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/zhouchenh/secDNS/internal/adminauth"
	"time"
)

// Synthetic values only. Assertions below check none of them reach logs or bodies.
const (
	ssoTestSecret = "synthetic-sso-header-secret-0123456789abcdefghijklmnop"
	ssoTestUser   = "0f6a1c3e-5b2d-4e8f-9a7c-synthetic0001" // stands for the IdP subject (sub)
	ssoTestName   = "owner-sso-synthetic"                   // secondary preferred_username match
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
		"usernameHeader":   "X-Secdns-SSO-Username",
		"allowedUsernames": []interface{}{ssoTestName},
		"tokenHeaders":     []interface{}{"X-Secdns-SSO-Id-Token", "X-Secdns-SSO-Access-Token"},
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
	h.ListenUnix = "/run/secdns-admin-test/console.sock"
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
	// as accepted on the private unix-socket listener (see markUnixPeer)
	r = r.WithContext(context.WithValue(r.Context(), unixPeerKey{}, true))
	r.RemoteAddr = "@"
	r.Header.Set("Origin", h.agent.origin)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.Header.Set("Content-Type", "application/json")
	setForwardedTuple(r, "example.invalid", "203.0.113.7")
	r.Header.Set("X-Secdns-SSO-Secret", ssoTestSecret)
	r.Header.Set("X-Secdns-SSO-User", ssoTestUser)
	r.Header.Set("X-Secdns-SSO-Username", ssoTestName)
	r.Header.Set("X-Secdns-SSO-Roles", "role:other,"+ssoTestRole+", role:x")
	r.Header.Set("X-Secdns-SSO-Id-Token", "Bearer "+ssoTestJWT(map[string]any{"sub": ssoTestUser, "preferred_username": ssoTestName}))
	r.Header.Set("X-Secdns-SSO-Access-Token", ssoTestJWT(map[string]any{"sub": ssoTestUser, "azp": "secdns-console"}))
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
		for _, secret := range []string{ssoTestSecret, ssoTestUser, ssoTestName} {
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

	// Without a fresh auth_time the SSO session is not recent.
	r = ssoRequest(h, "POST", "/auth/sessions/revoke-others", `{}`)
	r.AddCookie(cookies[0])
	r.Header.Set("X-SecDNS-CSRF", csrf)
	if got := serve(h, r); got.Code != 403 || !strings.Contains(got.Body.String(), "recent_authentication_required") {
		t.Fatalf("SSO session treated as recent: %d %s", got.Code, got.Body.String())
	}
	// Credential management is break-glass only on the SSO path.
	r = ssoRequest(h, "POST", "/auth/totp/begin", `{}`)
	r.AddCookie(cookies[0])
	r.Header.Set("X-SecDNS-CSRF", csrf)
	if got := serve(h, r); got.Code != 403 || !strings.Contains(got.Body.String(), "break_glass_only") {
		t.Fatalf("TOTP replacement offered on the SSO path: %d %s", got.Code, got.Body.String())
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
		{"spoofed-from-outside", "peer", tcpPeer("198.51.100.9:49152")},
		{"spoofed-from-facade-address", "peer", tcpPeer("100.91.1.47:443")},
		{"tcp-loopback-listed-proxy", "peer", tcpPeer("127.0.0.1:49152")},
		{"tcp-loopback-not-listed", "peer", tcpPeer("127.0.0.2:49152")},
		{"tcp-ipv6-loopback", "peer", tcpPeer("[::1]:49152")},
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
		{"role-in-other-case", "role", func(r *http.Request) { r.Header.Set("X-Secdns-SSO-Roles", strings.ToUpper(ssoTestRole)) }},
		{"missing-username", "username", func(r *http.Request) { r.Header.Del("X-Secdns-SSO-Username") }},
		{"impersonated-id-token", "rejected_claim", setToken("X-Secdns-SSO-Id-Token", map[string]any{"sub": ssoTestUser, "impersonator": map[string]any{"id": "admin-id", "username": "admin"}})},
		{"missing-id-token", "token", func(r *http.Request) { r.Header.Del("X-Secdns-SSO-Id-Token") }},
		{"duplicate-access-token", "token", func(r *http.Request) {
			r.Header.Add("X-Secdns-SSO-Access-Token", r.Header.Get("X-Secdns-SSO-Access-Token"))
		}},
		{"token-subject-mismatch", "token_subject", setToken("X-Secdns-SSO-Access-Token", map[string]any{"sub": "someone-else"})},
		{"duplicate-username", "username", func(r *http.Request) { r.Header.Add("X-Secdns-SSO-Username", ssoTestName) }},
		{"wrong-username", "username_not_allowed", func(r *http.Request) { r.Header.Set("X-Secdns-SSO-Username", "zhouchenh-renamed") }},
		{"username-in-user-header", "user_not_allowed", func(r *http.Request) { r.Header.Set("X-Secdns-SSO-User", ssoTestName) }},
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

// tcpPeer turns a request into one accepted on a TCP listener.
func tcpPeer(remote string) func(*http.Request) {
	return func(r *http.Request) {
		*r = *r.WithContext(context.Background())
		r.RemoteAddr = remote
	}
}

func TestTrustedSSORoleListToleratesUnrelatedEntries(t *testing.T) {
	h, _ := ssoTestServer(t, true)
	for _, roles := range []string{
		ssoTestRole,
		"Group With Spaces," + ssoTestRole,
		"rôle:ünïcode, ,," + ssoTestRole + ",x y z",
	} {
		r := ssoRequest(h, "GET", "/auth/state", "")
		r.Header.Set("X-Secdns-SSO-Roles", roles)
		w := serve(h, r)
		if w.Code != 200 || !strings.Contains(w.Body.String(), `"sso_login":true`) {
			t.Fatalf("roles %q: %d %s", roles, w.Code, w.Body.String())
		}
	}
}

func TestTrustedSSOAbsentHeadersKeepBreakGlassLogin(t *testing.T) {
	h, logs := ssoTestServer(t, true)
	strip := func(r *http.Request) *http.Request {
		r.Header.Del("X-Secdns-SSO-Secret")
		r.Header.Del("X-Secdns-SSO-User")
		r.Header.Del("X-Secdns-SSO-Username")
		r.Header.Del("X-Secdns-SSO-Roles")
		r.Header.Del("X-Secdns-SSO-Id-Token")
		r.Header.Del("X-Secdns-SSO-Access-Token")
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
			"tokenHeaders":     []interface{}{"X-Secdns-SSO-Id-Token"},
		}
	}
	if _, ok := ParseTrustedSSO(base()); !ok {
		t.Fatal("valid configuration refused")
	}
	for name, mutate := range map[string]func(map[string]interface{}){
		"missing":        func(m map[string]interface{}) { delete(m, "mapsTo") },
		"extra":          func(m map[string]interface{}) { m["optional"] = true },
		"prefix":         func(m map[string]interface{}) { m["userHeader"] = "X-Auth-Request-User" },
		"bare-prefix":    func(m map[string]interface{}) { m["userHeader"] = "X-Secdns-SSO-" },
		"header-chars":   func(m map[string]interface{}) { m["userHeader"] = "X-Secdns-SSO-User_" },
		"same-header":    func(m map[string]interface{}) { m["rolesHeader"] = "x-secdns-sso-secret" },
		"relative":       func(m map[string]interface{}) { m["headerSecretFile"] = "secret" },
		"dotdot":         func(m map[string]interface{}) { m["headerSecretFile"] = "/etc/../secret" },
		"maps-to":        func(m map[string]interface{}) { m["mapsTo"] = "Owner" },
		"role-space":     func(m map[string]interface{}) { m["requiredRole"] = "a b" },
		"role-empty":     func(m map[string]interface{}) { m["requiredRole"] = "" },
		"users-string":   func(m map[string]interface{}) { m["allowedUsers"] = "zhouchenh" },
		"users-empty":    func(m map[string]interface{}) { m["allowedUsers"] = []interface{}{} },
		"users-dup":      func(m map[string]interface{}) { m["allowedUsers"] = []interface{}{"a", "a"} },
		"users-number":   func(m map[string]interface{}) { m["allowedUsers"] = []interface{}{1.0} },
		"user-long":      func(m map[string]interface{}) { m["allowedUsers"] = []interface{}{strings.Repeat("u", 255)} },
		"secret-number":  func(m map[string]interface{}) { m["headerSecretFile"] = 1.0 },
		"username-only":  func(m map[string]interface{}) { m["usernameHeader"] = "X-Secdns-SSO-Username" },
		"usernames-only": func(m map[string]interface{}) { m["allowedUsernames"] = []interface{}{"zhouchenh"} },
		"username-same-header": func(m map[string]interface{}) {
			m["usernameHeader"] = "X-Secdns-SSO-User"
			m["allowedUsernames"] = []interface{}{"zhouchenh"}
		},
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

func unixTestClient(path string) *http.Client {
	return &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", path)
	}}}
}

func TestListenUnixServesAndMarksPeer(t *testing.T) {
	h, logs := ssoTestServer(t, true)
	dir := filepath.Join(t.TempDir(), "run")
	if e := os.Mkdir(dir, 0750); e != nil {
		t.Fatal(e)
	}
	os.Chmod(dir, 0750)
	h.ListenUnix = filepath.ToSlash(filepath.Join(dir, "console.sock"))
	listener, e := h.listenUnix()
	if e != nil {
		t.Fatal(e)
	}
	srv := h.httpServer()
	go srv.Serve(listener)
	t.Cleanup(func() { srv.Close() })
	info, e := os.Stat(filepath.Join(dir, "console.sock"))
	if e != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0660 {
		t.Fatalf("socket mode: %v %v", e, info)
	}
	client := unixTestClient(filepath.Join(dir, "console.sock"))
	do := func(r *http.Request) (*http.Response, string) {
		r.RequestURI, r.URL.Scheme = "", "http" // plain HTTP over the socket; Host stays the public name
		resp, e := client.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		defer resp.Body.Close()
		b := new(strings.Builder)
		buf := make([]byte, 4096)
		for {
			n, err := resp.Body.Read(buf)
			b.Write(buf[:n])
			if err != nil {
				break
			}
		}
		return resp, b.String()
	}
	strip := func(r *http.Request) *http.Request { *r = *r.WithContext(context.Background()); return r }
	resp, body := do(strip(ssoRequest(h, "GET", "/auth/state", "")))
	if resp.StatusCode != 200 || !strings.Contains(body, `"sso_login":true`) {
		t.Fatalf("state over unix socket: %d %s", resp.StatusCode, body)
	}
	resp, body = do(strip(ssoRequest(h, "POST", "/auth/login/sso", `{}`)))
	if resp.StatusCode != 200 || !strings.Contains(body, `"principal_type":"human"`) || len(resp.Cookies()) != 1 {
		t.Fatalf("exchange over unix socket: %d %s", resp.StatusCode, body)
	}
	// Break-glass over the socket: no SSO headers, password step works.
	r := strip(ssoRequest(h, "POST", "/auth/login/password", `{"username":"owner","password":"A synthetic long password phrase 8472!"}`))
	for _, k := range []string{"X-Secdns-Sso-Secret", "X-Secdns-Sso-User", "X-Secdns-Sso-Username", "X-Secdns-Sso-Roles", "X-Secdns-Sso-Id-Token", "X-Secdns-Sso-Access-Token"} {
		r.Header.Del(k)
	}
	if resp, body = do(r); resp.StatusCode != 200 || !strings.Contains(body, "challenge") {
		t.Fatalf("break-glass over unix socket: %d %s", resp.StatusCode, body)
	}
	// The same assertion over TCP (even loopback) is refused.
	tcp := httptest.NewServer(h.routes())
	t.Cleanup(tcp.Close)
	r = strip(ssoRequest(h, "GET", "/auth/state", ""))
	r.URL.Scheme, r.URL.Host, r.RequestURI = "http", strings.TrimPrefix(tcp.URL, "http://"), ""
	tr, e := http.DefaultClient.Do(r)
	if e != nil {
		t.Fatal(e)
	}
	tr.Body.Close()
	if tr.StatusCode != 403 || logs.last().reason != "peer" {
		t.Fatalf("assertion over TCP: %d %+v", tr.StatusCode, logs.last())
	}
}

func TestListenUnixRefusesUnsafeLocation(t *testing.T) {
	h := &HTTPAdminServer{}
	base := t.TempDir()
	mk := func(name string, mode os.FileMode) string {
		d := filepath.Join(base, name)
		os.Mkdir(d, 0700)
		os.Chmod(d, mode)
		return d
	}
	for name, path := range map[string]string{
		"world-accessible-dir": filepath.Join(mk("w", 0755), "s.sock"),
		"group-writable-dir":   filepath.Join(mk("g", 0770), "s.sock"),
		"missing-dir":          filepath.Join(base, "absent", "s.sock"),
		"relative":             "s.sock",
	} {
		h.ListenUnix = filepath.ToSlash(path)
		if l, e := h.listenUnix(); e == nil {
			l.Close()
			t.Fatalf("%s accepted", name)
		}
	}
	d := mk("ok", 0750)
	regular := filepath.Join(d, "file.sock")
	os.WriteFile(regular, []byte("x"), 0600)
	h.ListenUnix = filepath.ToSlash(regular)
	if l, e := h.listenUnix(); e == nil {
		l.Close()
		t.Fatal("existing regular file replaced")
	}
	link := filepath.Join(base, "link")
	if os.Symlink(d, link) == nil {
		h.ListenUnix = filepath.ToSlash(filepath.Join(link, "s.sock"))
		if l, e := h.listenUnix(); e == nil {
			l.Close()
			t.Fatal("symlinked directory accepted")
		}
	}
	// A stale socket from an earlier run is replaced.
	h.ListenUnix = filepath.ToSlash(filepath.Join(d, "s.sock"))
	l, e := h.listenUnix()
	if e != nil {
		t.Fatal(e)
	}
	if ul, ok := l.(*net.UnixListener); ok {
		ul.SetUnlinkOnClose(false)
	}
	l.Close()
	if l, e = h.listenUnix(); e != nil {
		t.Fatalf("stale socket not replaced: %v", e)
	}
	l.Close()
	for _, bad := range []string{"", "/", "/run/../x.sock", "/run/a/", "/" + strings.Repeat("a", 120)} {
		if ValidListenUnixPath(bad) {
			t.Fatalf("path %q accepted", bad)
		}
	}
}

// ssoTestJWT builds an unsigned token shape: the edge verified the real
// signature; the console only reads the payload over the trusted channel.
func ssoTestJWT(claims map[string]any) string {
	payload, _ := json.Marshal(claims)
	return "eyJhbGciOiJSUzI1NiJ9." + base64.RawURLEncoding.EncodeToString(payload) + ".c2lnbmF0dXJl"
}

func setToken(header string, claims map[string]any) func(*http.Request) {
	return func(r *http.Request) { r.Header.Set(header, ssoTestJWT(claims)) }
}

func TestTrustedSSORejectsImpersonatedTokens(t *testing.T) {
	impersonated := []any{
		map[string]any{"id": "admin-id", "username": "admin"},
		nil,
		map[string]any{},
		"",
		false,
	}
	for _, header := range []string{"X-Secdns-SSO-Id-Token", "X-Secdns-SSO-Access-Token"} {
		for i, value := range impersonated {
			h, logs := ssoTestServer(t, true)
			before, _ := h.agent.store.AuditLocal(100)
			r := ssoRequest(h, "POST", "/auth/login/sso", `{}`)
			setToken(header, map[string]any{"sub": ssoTestUser, "impersonator": value})(r)
			w := serve(h, r)
			if w.Code != 403 || !strings.Contains(w.Body.String(), "sso_rejected") || len(w.Result().Cookies()) != 0 {
				t.Fatalf("%s value %d: impersonated token not refused: %d %s", header, i, w.Code, w.Body.String())
			}
			if rec := logs.last(); rec.accepted || rec.reason != "rejected_claim" {
				t.Fatalf("%s value %d: logged %+v", header, i, rec)
			}
			assertNoSSOLeak(t, "impersonation refusal", w.Body.String())
			if strings.Contains(w.Body.String(), "admin") {
				t.Fatal("claim value echoed")
			}
			after, _ := h.agent.store.AuditLocal(100)
			if len(after) != len(before) {
				t.Fatal("refused impersonation reached the audit/session path")
			}
		}
	}
	// The normal owner token still gets a session.
	h, logs := ssoTestServer(t, true)
	w := serve(h, ssoRequest(h, "POST", "/auth/login/sso", `{}`))
	if w.Code != 200 || len(w.Result().Cookies()) != 1 || !logs.last().accepted {
		t.Fatalf("owner token: %d %s", w.Code, w.Body.String())
	}
}

func TestTrustedSSOUnreadableTokensFailClosed(t *testing.T) {
	sub := base64.RawURLEncoding.EncodeToString
	for name, raw := range map[string]string{
		"empty":         "",
		"bearer-only":   "Bearer ",
		"two-parts":     "a." + sub([]byte(`{"sub":"x"}`)),
		"four-parts":    "a." + sub([]byte(`{"sub":"x"}`)) + ".b.c",
		"empty-payload": "a..b",
		"bad-base64":    "a.!!!.b",
		"not-json":      "a." + sub([]byte("not json")) + ".b",
		"json-array":    "a." + sub([]byte(`["sub"]`)) + ".b",
		"json-null":     "a." + sub([]byte(`null`)) + ".b",
		"trailing-data": "a." + sub([]byte(`{"sub":"`+ssoTestUser+`"}{}`)) + ".b",
		"no-sub":        ssoTestJWT(map[string]any{"azp": "secdns-console"}),
		"numeric-sub":   ssoTestJWT(map[string]any{"sub": 42}),
		"oversized":     "a." + strings.Repeat("A", 13<<10) + ".b",
	} {
		h, logs := ssoTestServer(t, true)
		r := ssoRequest(h, "GET", "/auth/state", "")
		r.Header.Set("X-Secdns-SSO-Id-Token", raw)
		w := serve(h, r)
		if w.Code != 403 || logs.last().accepted || (logs.last().reason != "token" && logs.last().reason != "token_subject") {
			t.Fatalf("%s: %d %s %+v", name, w.Code, w.Body.String(), logs.last())
		}
	}
	// Without configured token headers (or reject claims) nothing is accepted.
	h, logs := ssoTestServer(t, true)
	h.TrustedSSO.TokenHeaders = nil
	r := ssoRequest(h, "GET", "/auth/state", "")
	r.Header.Del("X-Secdns-SSO-Id-Token")
	r.Header.Del("X-Secdns-SSO-Access-Token")
	if w := serve(h, r); w.Code != 403 || logs.last().reason != "token" {
		t.Fatalf("no token headers configured: %d %+v", w.Code, logs.last())
	}
}

func TestTrustedSSORejectClaimsConfigurable(t *testing.T) {
	c := ssoTestConfig(t)
	if len(c.RejectClaims) != 1 || c.RejectClaims[0] != "impersonator" {
		t.Fatalf("default reject claims: %v", c.RejectClaims)
	}
	h, logs := ssoTestServer(t, true)
	h.TrustedSSO.RejectClaims = []string{"impersonator", "act"}
	r := ssoRequest(h, "GET", "/auth/state", "")
	setToken("X-Secdns-SSO-Access-Token", map[string]any{"sub": ssoTestUser, "act": map[string]any{"sub": "admin"}})(r)
	if w := serve(h, r); w.Code != 403 || logs.last().reason != "rejected_claim" {
		t.Fatalf("custom reject claim: %d %+v", w.Code, logs.last())
	}
	base := func() map[string]interface{} {
		return map[string]interface{}{
			"headerSecretFile": "/etc/secdns-admin/sso-header-secret", "secretHeader": "X-Secdns-SSO-Secret",
			"userHeader": "X-Secdns-SSO-User", "rolesHeader": "X-Secdns-SSO-Roles", "requiredRole": ssoTestRole,
			"allowedUsers": []interface{}{"u"}, "mapsTo": "owner", "tokenHeaders": []interface{}{"X-Secdns-SSO-Id-Token"},
		}
	}
	m := base()
	m["rejectClaims"] = []interface{}{"impersonator", "act"}
	if got, ok := ParseTrustedSSO(m); !ok || len(got.RejectClaims) != 2 {
		t.Fatal("explicit reject claims refused")
	}
	for name, mutate := range map[string]func(map[string]interface{}){
		"no-token-headers":    func(m map[string]interface{}) { delete(m, "tokenHeaders") },
		"empty-token-headers": func(m map[string]interface{}) { m["tokenHeaders"] = []interface{}{} },
		"three-token-headers": func(m map[string]interface{}) {
			m["tokenHeaders"] = []interface{}{"X-Secdns-SSO-A", "X-Secdns-SSO-B", "X-Secdns-SSO-C"}
		},
		"token-header-prefix":  func(m map[string]interface{}) { m["tokenHeaders"] = []interface{}{"Authorization"} },
		"token-header-reused":  func(m map[string]interface{}) { m["tokenHeaders"] = []interface{}{"X-Secdns-SSO-User"} },
		"empty-reject-claims":  func(m map[string]interface{}) { m["rejectClaims"] = []interface{}{} },
		"reject-claims-string": func(m map[string]interface{}) { m["rejectClaims"] = "impersonator" },
	} {
		m := base()
		mutate(m)
		if _, ok := ParseTrustedSSO(m); ok {
			t.Fatalf("%s accepted", name)
		}
	}
}

func TestTrustedSSOSessionExposesFixedSignOut(t *testing.T) {
	h, _ := ssoTestServer(t, true)
	w := serve(h, ssoRequest(h, "POST", "/auth/login/sso", `{}`))
	var out map[string]any
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out["sso"] != true || out["sign_out_url"] != "/oauth2/sign_out?rd=%2F" {
		t.Fatalf("SSO session lacks the fixed sign-out: %d %v", w.Code, out)
	}
	cookie := w.Result().Cookies()[0]
	session := func(c *http.Cookie, mutate func(*http.Request)) map[string]any {
		r := ssoRequest(h, "GET", "/auth/session", "")
		r.Header.Del("Content-Type")
		if mutate != nil {
			mutate(r)
		}
		r.AddCookie(c)
		w := serve(h, r)
		var m map[string]any
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &m) != nil {
			t.Fatalf("session read: %d %s", w.Code, w.Body.String())
		}
		return m
	}
	// request data cannot change the URL (e.g. a crafted rd or Referer)
	m := session(cookie, func(r *http.Request) {
		r.URL.RawQuery = "rd=https://evil.example/"
		r.Header.Set("Referer", "https://evil.example/")
	})
	if m["sso"] != true || m["sign_out_url"] != SSOSignOutURL || SSOSignOutURL != "/oauth2/sign_out?rd=%2F" {
		t.Fatalf("SSO session read: %v", m)
	}
	// A break-glass password+TOTP session (no SSO headers) keeps today's behaviour.
	h2, owner := nodeTestSetup(t)
	r := httptest.NewRequest("GET", "https://example.invalid/admin/auth/session", nil)
	r.Header.Set("Origin", h2.agent.origin)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: owner.Token})
	w = httptest.NewRecorder()
	h2.routes().ServeHTTP(w, r)
	if w.Code != 200 || strings.Contains(w.Body.String(), "sso") || strings.Contains(w.Body.String(), "sign_out_url") {
		t.Fatalf("password session exposes SSO sign-out: %d %s", w.Code, w.Body.String())
	}
	if out := sessionJSON(owner.Session); out["sso"] != nil || out["sign_out_url"] != nil {
		t.Fatal("password session JSON has SSO fields")
	}
}

func ssoTokensWithAuthTime(r *http.Request, authTime int64) {
	claims := map[string]any{"sub": ssoTestUser}
	if authTime != 0 {
		claims["auth_time"] = authTime
	}
	r.Header.Set("X-Secdns-SSO-Id-Token", "Bearer "+ssoTestJWT(claims))
}

func TestTrustedSSOPublicPathNeverOffersBreakGlass(t *testing.T) {
	h, _ := ssoTestServer(t, true)
	for _, path := range []string{"/auth/login/password", "/auth/login/totp", "/auth/setup/begin", "/auth/recovery/local",
		"/auth/recovery/code", "/auth/agent-session", "/auth/totp/begin", "/auth/totp/confirm", "/auth/reauth/password-totp",
		"/auth/password", "/auth/recovery-codes/regenerate", "/auth/passkeys/login/begin"} {
		w := serve(h, ssoRequest(h, "POST", path, `{}`))
		if w.Code != 403 || !strings.Contains(w.Body.String(), "break_glass_only") {
			t.Fatalf("%s on the SSO path: %d %s", path, w.Code, w.Body.String())
		}
	}
	// The same password step without SSO headers (private socket, break-glass) still works.
	r := ssoRequest(h, "POST", "/auth/login/password", `{"username":"owner","password":"A synthetic long password phrase 8472!"}`)
	for _, k := range []string{"X-Secdns-SSO-Secret", "X-Secdns-SSO-User", "X-Secdns-SSO-Username", "X-Secdns-SSO-Roles", "X-Secdns-SSO-Id-Token", "X-Secdns-SSO-Access-Token"} {
		r.Header.Del(k)
	}
	if w := serve(h, r); w.Code != 200 || !strings.Contains(w.Body.String(), "challenge") {
		t.Fatalf("break-glass password step: %d %s", w.Code, w.Body.String())
	}
	// Read-only and exchange routes stay available on the SSO path.
	if w := serve(h, ssoRequest(h, "GET", "/auth/state", "")); w.Code != 200 {
		t.Fatalf("state on the SSO path: %d", w.Code)
	}
}

func TestTrustedSSOStepUpIsAFreshIdentityProviderSignIn(t *testing.T) {
	now := time.Now()
	for _, c := range []struct {
		name     string
		authTime int64
		recent   bool
	}{
		{"fresh", now.Add(-time.Minute).Unix(), true},
		{"just-now", now.Unix(), true},
		{"old-sso-reuse", now.Add(-10 * time.Minute).Unix(), false},
		{"at-window", now.Add(-adminauth.RecentAuthenticationWindow - time.Second).Unix(), false},
		{"future", now.Add(10 * time.Minute).Unix(), false},
		{"absent", 0, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			h, _ := ssoTestServer(t, true)
			r := ssoRequest(h, "POST", "/auth/login/sso", `{}`)
			ssoTokensWithAuthTime(r, c.authTime)
			w := serve(h, r)
			var out map[string]any
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil {
				t.Fatalf("exchange: %d %s", w.Code, w.Body.String())
			}
			r = ssoRequest(h, "POST", "/auth/sessions/revoke-others", `{}`)
			ssoTokensWithAuthTime(r, c.authTime)
			r.AddCookie(w.Result().Cookies()[0])
			r.Header.Set("X-SecDNS-CSRF", out["csrf"].(string))
			got := serve(h, r)
			if c.recent && got.Code != 200 {
				t.Fatalf("fresh WithMy ID sign-in not accepted as step-up: %d %s", got.Code, got.Body.String())
			}
			if !c.recent && (got.Code != 403 || !strings.Contains(got.Body.String(), "recent_authentication_required")) {
				t.Fatalf("stale/absent auth_time treated as recent: %d %s", got.Code, got.Body.String())
			}
		})
	}
}

func TestTrustedSSOPageCarriesNoPasswordField(t *testing.T) {
	h, _ := ssoTestServer(t, true)
	h.UI = true
	r := ssoRequest(h, "GET", "/ui/", "")
	r.Header.Del("Content-Type")
	w := serve(h, r)
	if w.Code != 200 || strings.Contains(w.Body.String(), `type="password"`) || !strings.Contains(w.Body.String(), `<section id="login" class="card" hidden>`) {
		t.Fatalf("SSO page: %d password-field=%v", w.Code, strings.Contains(w.Body.String(), `type="password"`))
	}
	// Break-glass (no SSO headers) keeps today's page.
	r = httptest.NewRequest("GET", "https://example.invalid/admin/ui/", nil)
	r.RemoteAddr = "127.0.0.1:40000"
	w = serve(h, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `type="password"`) {
		t.Fatalf("break-glass page: %d", w.Code)
	}
}

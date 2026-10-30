package server

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/zhouchenh/secDNS/internal/adminauth"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func gatewayOTP(t *testing.T, secret string, now time.Time) string {
	t.Helper()
	key, e := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if e != nil {
		t.Fatal(e)
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(now.Unix()/30))
	h := hmac.New(sha1.New, key)
	h.Write(counter[:])
	sum := h.Sum(nil)
	offset := sum[len(sum)-1] & 15
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[offset:offset+4])&0x7fffffff)%1000000)
}
func TestRecordGatewayHumanSessionRemoteCAS(t *testing.T) {
	upstream := &HTTPAdminServer{Token: strings.Repeat("u", 32)}
	bindRRsetTest(t, upstream)
	var calls atomic.Int32
	var drop atomic.Bool
	drop.Store(true)
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer "+upstream.Token || r.Header.Get("Cookie") != "" || r.Header.Get("Origin") != "" || r.Header.Get("X-SecDNS-CSRF") != "" {
			t.Error("browser identity leaked or authority token missing")
		}
		recorder := httptest.NewRecorder()
		upstream.routes().ServeHTTP(recorder, r)
		if r.Method == "POST" && recorder.Code == 200 && drop.CompareAndSwap(true, false) {
			conn, buf, e := w.(http.Hijacker).Hijack()
			if e != nil {
				t.Error(e)
				return
			}
			buf.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{")
			buf.Flush()
			conn.Close()
			return
		}
		for k, v := range recorder.Header() {
			w.Header()[k] = v
		}
		w.Header().Set("Set-Cookie", "should-not-forward=1")
		w.WriteHeader(recorder.Code)
		w.Write(recorder.Body.Bytes())
	}))
	defer remote.Close()
	h, grant := humanTestServer(t)
	h.RecordAuthorityURL = remote.URL + "/admin"
	h.RecordAuthorityToken = upstream.Token
	h.UI = true
	if e := h.prepareRecordBinding(); e != nil {
		t.Fatal(e)
	}
	if h.store != nil || h.versioned != nil {
		t.Fatal("gateway opened local records")
	}
	now := time.Now()
	password := "Synthetic gateway password 39!"
	en, e := h.agent.human.BeginEnrollment(grant, "owner", "Synthetic owner", password, "192.0.2.1", false, now)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = h.agent.human.Confirm(en.Challenge, gatewayOTP(t, en.Secret, now), "192.0.2.1", now); e != nil {
		t.Fatal(e)
	}
	now = now.Add(31 * time.Second)
	h.agent.now = func() time.Time { return now }
	mux := h.routes()
	request := func(method, path, body string, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "https://example.invalid/admin"+path, strings.NewReader(body))
		r.Header.Set("Origin", h.agent.origin)
		r.Header.Set("Sec-Fetch-Site", "same-origin")
		r.Header.Set("Content-Type", "application/json")
		if cookie != nil {
			r.AddCookie(cookie)
		}
		if csrf != "" {
			r.Header.Set("X-SecDNS-CSRF", csrf)
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	login := request("POST", "/auth/login/password", `{"username":"owner","password":"`+password+`"}`, nil, "")
	if login.Code != 200 {
		t.Fatal("password login", login.Code)
	}
	var challenge map[string]string
	json.Unmarshal(login.Body.Bytes(), &challenge)
	confirm := request("POST", "/auth/login/totp", `{"challenge":"`+challenge["challenge"]+`","code":"`+gatewayOTP(t, en.Secret, now)+`"}`, nil, "")
	if confirm.Code != 200 {
		t.Fatal("MFA login", confirm.Code, confirm.Body.String())
	}
	cookies := confirm.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatal("session cookie missing")
	}
	cookie := cookies[0]
	var session map[string]any
	json.Unmarshal(confirm.Body.Bytes(), &session)
	csrf, _ := session["csrf"].(string)
	if csrf == "" {
		t.Fatal("csrf missing")
	}
	snapshot := request("GET", "/snapshot", "", cookie, "")
	if snapshot.Code != 200 || snapshot.Header().Get("SecDNS-RRset-Mutations") != "v1" || snapshot.Header().Get("Set-Cookie") != "" {
		t.Fatal("remote snapshot", snapshot.Code)
	}
	conditional := httptest.NewRequest("GET", "https://example.invalid/admin/snapshot", nil)
	conditional.AddCookie(cookie)
	conditional.Header.Set("Sec-Fetch-Site", "same-origin")
	conditional.Header.Set("If-None-Match", snapshot.Header().Get("ETag"))
	cw := httptest.NewRecorder()
	mux.ServeHTTP(cw, conditional)
	if cw.Code != 304 || cw.Header().Get("ETag") != snapshot.Header().Get("ETag") || cw.Header().Get("SecDNS-RRset-Mutations") != "v1" {
		t.Fatal("remote conditional capability lost")
	}
	before := calls.Load()
	for _, kind := range []string{"absent", "invalid", "mixed", "origin"} {
		r := httptest.NewRequest("POST", "https://example.invalid/admin/snapshot/rrset", nil)
		r.Body = noRead{t}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", h.agent.origin)
		r.Header.Set("Sec-Fetch-Site", "same-origin")
		r.Header.Set("X-SecDNS-CSRF", csrf)
		if kind != "absent" {
			if kind == "invalid" {
				r.AddCookie(&http.Cookie{Name: sessionCookie, Value: "expired-or-revoked-session"})
			} else {
				r.AddCookie(cookie)
			}
		}
		if kind == "mixed" {
			r.Header.Set("Authorization", "Bearer "+h.Token)
		}
		if kind == "origin" {
			r.Header.Set("Origin", "https://other.invalid")
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		h.agent.now = func() time.Time { return now }
		if w.Code < 400 {
			t.Fatal("invalid session admitted", kind)
		}
	}
	if calls.Load() != before {
		t.Fatal("invalid session reached upstream")
	}
	before = calls.Load()
	for _, bad := range []string{"", "bad"} {
		w := request("POST", "/snapshot/rrset", rrsetBody, cookie, bad)
		if w.Code < 400 {
			t.Fatal("CSRF bypass")
		}
	}
	if calls.Load() != before {
		t.Fatal("unauthorized upstream request")
	}
	before = calls.Load()
	first := request("POST", "/snapshot/rrset", rrsetBody, cookie, csrf)
	if calls.Load() != before+1 {
		t.Fatal("gateway automatically retried uncertain write")
	}
	if first.Code != 502 {
		t.Fatal("lost acknowledgement must stay uncertain", first.Code)
	}
	replay := request("POST", "/snapshot/rrset", rrsetBody, cookie, csrf)
	if replay.Code != 200 {
		t.Fatal("replay", replay.Code, replay.Body.String())
	}
	again := request("POST", "/snapshot/rrset", rrsetBody, cookie, csrf)
	if !bytes.Equal(replay.Body.Bytes(), again.Body.Bytes()) {
		t.Fatal("receipt not preserved")
	}
	stale := request("POST", "/snapshot/rrset", strings.Replace(rrsetBody, `"op"`, `"new-op"`, 1), cookie, csrf)
	if stale.Code != 409 {
		t.Fatal("CAS not preserved", stale.Code)
	}
	view, _ := upstream.versioned.Acquire()
	if view.Metadata().Revision != 2 || len(view.Records()) != 1 {
		t.Fatal("mutation replay duplicated")
	}
	for _, path := range []string{"/records", "/snapshot/events", "/snapshot?url=http://example.invalid"} {
		if w := request("GET", path, "", cookie, ""); w.Code < 400 {
			t.Fatal("route admitted", path)
		}
	}
	ui := request("GET", "/ui/", "", nil, "")
	if !strings.Contains(ui.Body.String(), "Remote DNS server") || !strings.Contains(ui.Body.String(), "state.js") {
		t.Fatal("gateway editor mode")
	}
	before = calls.Load()
	h.agent.now = func() time.Time { return now.Add(48 * time.Hour) }
	r := httptest.NewRequest("POST", "https://example.invalid/admin/snapshot/rrset", nil)
	r.Body = noRead{t}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", h.agent.origin)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.Header.Set("X-SecDNS-CSRF", csrf)
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 401 || calls.Load() != before {
		t.Fatal("expired session reached authority")
	}
}
func TestRecordGatewayRejectBeforeBodyAndRedirect(t *testing.T) {
	h, token := agentTestServer(t, []adminauth.Scope{adminauth.RecordsRead})
	h.RecordAuthorityURL = "http://127.0.0.1:12345/admin"
	h.RecordAuthorityToken = strings.Repeat("x", 32)
	if e := h.prepareRecordBinding(); e != nil {
		t.Fatal(e)
	}
	for _, auth := range []string{"", "Bearer " + h.Token, "Bearer " + token} {
		r := httptest.NewRequest("POST", "/admin/snapshot", nil)
		r.Header.Set("Authorization", auth)
		r.Body = noRead{t}
		w := httptest.NewRecorder()
		h.routes().ServeHTTP(w, r)
		if w.Code < 400 {
			t.Fatal("unauthorized admitted")
		}
	}
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "http://example.invalid/secret")
		w.Header().Set("Set-Cookie", "no=1")
		w.WriteHeader(302)
	}))
	defer remote.Close()
	h.RecordAuthorityURL = remote.URL + "/admin"
	r := httptest.NewRequest("GET", "/admin/snapshot", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.routes().ServeHTTP(w, r)
	if w.Code != 502 || w.Header().Get("Location") != "" || w.Header().Get("Set-Cookie") != "" {
		t.Fatal("redirect escaped")
	}
}
func TestRecordGatewayConfiguration(t *testing.T) {
	for _, target := range []string{"http://example.invalid:80/admin", "https://127.0.0.1:80/admin", "http://127.0.0.1/admin", "http://user@127.0.0.1:80/admin", "http://127.0.0.1:80/a/../b", "http://127.0.0.1:80/admin?q=x", "http://127.0.0.1:80/%61dmin", "http://127.0.0.1:80/"} {
		h := &HTTPAdminServer{RecordAuthorityURL: target, RecordAuthorityToken: strings.Repeat("x", 32), AgentAuthConfigured: true}
		if h.ValidateRecordGateway() == nil {
			t.Fatal("invalid URL accepted", target)
		}
	}
	h := &HTTPAdminServer{RecordAuthorityURL: "http://127.0.0.1:18055/owned-static", RecordAuthorityToken: strings.Repeat("x", 32), AgentAuthConfigured: true}
	if e := h.ValidateRecordGateway(); e != nil {
		t.Fatal(e)
	}
	h.Store = "local"
	if h.ValidateRecordGateway() == nil {
		t.Fatal("mixed stores")
	}
}

func TestRecordGatewayPrivateTokenFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "existing-token")
	h := &HTTPAdminServer{RecordAuthorityURL: "http://127.0.0.1:18055/admin", RecordAuthorityTokenFile: path, AgentAuthConfigured: true}
	if h.ValidateRecordGateway() != nil {
		t.Fatal("validation must be read-free")
	}
	if h.prepareRecordGateway() == nil {
		t.Fatal("missing credential accepted")
	}
	if _, e := os.Stat(path); !os.IsNotExist(e) {
		t.Fatal("missing credential created")
	}
	token := strings.Repeat("k", 32)
	if e := os.WriteFile(path, []byte(token+"\r\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := h.prepareRecordGateway(); e != nil {
		t.Fatal(e)
	}
	if h.recordAuthorityCredential != token || h.RecordAuthorityToken != "" {
		t.Fatal("credential load")
	}
	os.WriteFile(path, []byte("invalid"), 0600)
	if h.recordAuthorityCredential != token {
		t.Fatal("credential unexpectedly reloaded")
	}
	if h.prepareRecordGateway() == nil {
		t.Fatal("invalid credential accepted")
	}
	h.RecordAuthorityToken = token
	if h.ValidateRecordGateway() == nil {
		t.Fatal("ambiguous credential configuration")
	}
}

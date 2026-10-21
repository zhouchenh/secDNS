package server

import (
	"context"
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
	"testing"
	"time"
)

func nodeTestOTP(secret string, now time.Time) string {
	key, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(now.Unix()/30))
	m := hmac.New(sha1.New, key)
	m.Write(b)
	hash := m.Sum(nil)
	offset := hash[len(hash)-1] & 15
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(hash[offset:offset+4])&0x7fffffff)%1000000)
}
func nodeTestSetup(t *testing.T) (*HTTPAdminServer, adminauth.HumanResult) {
	h, grant := humanTestServer(t)
	now := time.Now()
	en, e := h.agent.human.BeginEnrollment(grant, "owner", "Test owner", "A synthetic long password phrase 8472!", "127.0.0.1", false, now)
	if e != nil {
		t.Fatal(e)
	}
	result, e := h.agent.human.Confirm(en.Challenge, nodeTestOTP(en.Secret, now), "127.0.0.1", now)
	if e != nil {
		t.Fatal(e)
	}
	h.NodeAdapterExecutable = filepath.Join(t.TempDir(), "python.exe")
	h.NodeAdapterScript = filepath.Join(t.TempDir(), "adapter.py")
	h.NodeAuditDirectory = t.TempDir()
	return h, result
}
func nodeTestRequest(h *HTTPAdminServer, s adminauth.HumanResult, method, path, body, csrf string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Origin", h.agent.origin)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-SecDNS-CSRF", csrf)
	if s.Token != "" {
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: s.Token})
	}
	w := httptest.NewRecorder()
	h.routes().ServeHTTP(w, r)
	return w
}
func TestNodeAuthorizationReplayAndReadback(t *testing.T) {
	h, s := nodeTestSetup(t)
	calls := 0
	withdraw := false
	h.nodeRunner = func(ctx context.Context, action, node, id string) (nodeSnapshot, error) {
		calls++
		out := nodeSnapshot{Schema: 1, Node: node, ObservedAt: time.Now().UTC(), Reachable: true}
		out.Daemon.Active = true
		out.Maintenance.Withdraw = withdraw
		if action != "status" {
			withdraw = action == "drain"
			out.Maintenance.Withdraw = withdraw
			raw := fmt.Sprintf(`{"request_id":%q,"action":%q,"confirmed":true,"status":"confirmed"}`, id, action)
			json.Unmarshal([]byte(raw), &out.Operation)
		}
		return out, nil
	}
	path := "/admin/nodes/amd103/maintenance"
	body := `{"action":"drain","request_id":"11111111-1111-4111-8111-111111111111","expected_withdraw":"false","confirm_node":"amd103"}`
	for _, csrf := range []string{"", "wrong"} {
		w := nodeTestRequest(h, s, "POST", path, body, csrf)
		if w.Code != 403 {
			t.Fatal(w.Code, w.Body)
		}
	}
	if calls != 0 {
		t.Fatal("unauthorized adapter invocation")
	}
	w := nodeTestRequest(h, s, "POST", path, body, s.Session.CSRF)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"confirmed":true`) {
		t.Fatal(w.Code, w.Body)
	}
	w = nodeTestRequest(h, s, "POST", path, strings.Replace(body, `"false"`, `"true"`, 1), s.Session.CSRF)
	if w.Code != 409 {
		t.Fatal("replayed", w.Code)
	}
	logs, e := os.ReadDir(h.NodeAuditDirectory)
	if e != nil || len(logs) != 1 {
		t.Fatal(e, logs)
	}
	data, _ := os.ReadFile(filepath.Join(h.NodeAuditDirectory, logs[0].Name()))
	if !strings.Contains(string(data), `"stage":"intent"`) || !strings.Contains(string(data), `"stage":"confirmed"`) {
		t.Fatal("missing durable audit")
	}
	for _, p := range []string{"../../host", "router", "amd103;whoami"} {
		w = nodeTestRequest(h, s, "GET", "/admin/nodes/"+p, "", "")
		if w.Code == 200 {
			t.Fatal("unknown node accepted")
		}
	}
}
func TestNodesDenyLegacyAndAgents(t *testing.T) {
	h, _ := nodeTestSetup(t)
	h.nodeRunner = func(context.Context, string, string, string) (nodeSnapshot, error) {
		t.Fatal("unauthorized invocation")
		return nodeSnapshot{}, nil
	}
	r := httptest.NewRequest("GET", "/admin/nodes/amd103", nil)
	r.Header.Set("Authorization", "Bearer "+h.Token)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	h.routes().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal(w.Code)
	}
	a, token := agentTestServer(t, []adminauth.Scope{adminauth.UIView, adminauth.RecordsRead, adminauth.RecordsWrite})
	a.NodeAdapterExecutable = h.NodeAdapterExecutable
	a.NodeAdapterScript = h.NodeAdapterScript
	a.NodeAuditDirectory = h.NodeAuditDirectory
	r = httptest.NewRequest("GET", "/admin/nodes/amd103", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	w = httptest.NewRecorder()
	a.routes().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal(w.Code)
	}
}
func TestNodeStrictMutationAndUnavailable(t *testing.T) {
	h, s := nodeTestSetup(t)
	h.nodeRunner = func(context.Context, string, string, string) (nodeSnapshot, error) {
		return nodeSnapshot{Node: "amd103", Stale: true}, nil
	}
	for _, body := range []string{`{"action":"shell"}`, `{"action":"drain","request_id":"../escape","expected_withdraw":"false","confirm_node":"amd103"}`, `{"action":"drain","request_id":"11111111-1111-4111-8111-111111111111","expected_withdraw":"false","confirm_node":"intel108"}`} {
		w := nodeTestRequest(h, s, "POST", "/admin/nodes/amd103/maintenance", body, s.Session.CSRF)
		if w.Code != 400 {
			t.Fatal(w.Code)
		}
	}
	body := `{"action":"drain","request_id":"11111111-1111-4111-8111-111111111111","expected_withdraw":"false","confirm_node":"amd103"}`
	w := nodeTestRequest(h, s, "POST", "/admin/nodes/amd103/maintenance", body, s.Session.CSRF)
	if w.Code != 409 {
		t.Fatal(w.Code)
	}
	entries, _ := os.ReadDir(h.NodeAuditDirectory)
	if len(entries) != 0 {
		t.Fatal("stale node mutated")
	}
}
func TestNodeAgentCookieAndUncertainReceipt(t *testing.T) {
	a, bearer := agentTestServer(t, []adminauth.Scope{adminauth.UIView, adminauth.RecordsRead, adminauth.RecordsWrite})
	a.NodeAdapterExecutable = filepath.Join(t.TempDir(), "python.exe")
	a.NodeAdapterScript = filepath.Join(t.TempDir(), "adapter.py")
	a.NodeAuditDirectory = t.TempDir()
	token, csrf, _, e := a.agent.sessions.Exchange(bearer, "realm", "node", time.Now())
	if e != nil {
		t.Fatal(e)
	}
	r := httptest.NewRequest("POST", "/admin/nodes/amd103/maintenance", strings.NewReader(`{}`))
	r.Header.Set("Origin", a.agent.origin)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-SecDNS-CSRF", csrf)
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("agent cookie admitted", w.Code)
	}
	h, s := nodeTestSetup(t)
	mutations := 0
	h.nodeRunner = func(ctx context.Context, action, node, id string) (nodeSnapshot, error) {
		if action != "status" {
			mutations++
			return nodeSnapshot{}, fmt.Errorf("synthetic uncertainty")
		}
		return nodeSnapshot{Schema: 1, Node: node, ObservedAt: time.Now(), Reachable: true}, nil
	}
	body := `{"action":"drain","request_id":"22222222-2222-4222-8222-222222222222","expected_withdraw":"true","confirm_node":"amd103"}`
	w = nodeTestRequest(h, s, "POST", "/admin/nodes/amd103/maintenance", body, s.Session.CSRF)
	if w.Code != 409 || mutations != 0 {
		t.Fatal("state conflict mutated", w.Code)
	}
	body = strings.Replace(body, `"true"`, `"false"`, 1)
	w = nodeTestRequest(h, s, "POST", "/admin/nodes/amd103/maintenance", body, s.Session.CSRF)
	if w.Code != 502 || mutations != 1 {
		t.Fatal(w.Code, mutations)
	}
	w = nodeTestRequest(h, s, "POST", "/admin/nodes/amd103/maintenance", body, s.Session.CSRF)
	if w.Code != 409 || mutations != 1 {
		t.Fatal("uncertain replay", w.Code, mutations)
	}
	entries, _ := os.ReadDir(h.NodeAuditDirectory)
	data, _ := os.ReadFile(filepath.Join(h.NodeAuditDirectory, entries[0].Name()))
	if !strings.Contains(string(data), `"stage":"uncertain"`) {
		t.Fatal("uncertain receipt absent")
	}
}
func TestNodeManagementExcludedFromFollowerOnly(t *testing.T) {
	h, _ := nodeTestSetup(t)
	h.FollowerStatusOnly = true
	if h.nodesEnabled() {
		t.Fatal("follower listener exposes node management")
	}
	r := httptest.NewRequest("POST", "/admin/nodes/amd103/maintenance", nil)
	w := httptest.NewRecorder()
	h.routes().ServeHTTP(w, r)
	if w.Code != 404 {
		t.Fatal(w.Code)
	}
}

func TestNodeReceiptSafeNamesAndLegacyReplay(t *testing.T) {
	dir := t.TempDir()
	for _, id := range []string{"../escape", `..\escape`, "/absolute", "C:/absolute", "11111111-1111-4111-8111-111111111111/../../x", ""} {
		if file, err := reserveNodeReceipt(dir, id); err == nil {
			file.Close()
			t.Fatalf("unsafe identifier accepted: %q", id)
		}
	}
	const oldID = "33333333-3333-4333-8333-333333333333"
	if err := os.WriteFile(filepath.Join(dir, oldID+".jsonl"), []byte("legacy intent"), 0600); err != nil {
		t.Fatal(err)
	}
	if file, err := reserveNodeReceipt(dir, oldID); !os.IsExist(err) {
		if file != nil {
			file.Close()
		}
		t.Fatalf("legacy receipt replay not blocked: %v", err)
	}
	const newID = "44444444-4444-4444-8444-444444444444"
	file, err := reserveNodeReceipt(dir, newID)
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Base(file.Name())
	file.Close()
	if strings.Contains(name, newID) || len(name) != len("operation-")+64+len(".jsonl") || !strings.HasPrefix(name, "operation-") {
		t.Fatal("unexpected receipt basename", name)
	}
	if file, err = reserveNodeReceipt(dir, newID); !os.IsExist(err) {
		if file != nil {
			file.Close()
		}
		t.Fatalf("new receipt replay not blocked: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 2 {
		t.Fatal("unexpected receipt creation", err, len(entries))
	}
}

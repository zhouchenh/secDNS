package server

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/zhouchenh/secDNS/internal/adminauth"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestExternalPeerActualHandlerCRUDAndAuthority(t *testing.T) {
	h, s := nodeTestSetup(t)
	config := nodeBGPFixture("amd103")
	revision := strings.Repeat("a", 64)
	calls := 0
	policy := &nodeExternalPolicy{Schema: 1, Node: "amd103", Peers: []nodeExternalEnrollment{{ID: "fixture", AllowedAFIs: []int{4, 6}, AllowedExports: []string{"203.0.113.53/32"}}}}
	h.nodeBGPRunner = func(_ context.Context, action, node, id string, raw []byte) (nodeBGPResult, error) {
		out := nodeBGPResult{Schema: 1, Node: node, Revision: revision, Config: config, ExternalPolicy: policy}
		var body nodeBGPRequest
		_ = json.Unmarshal(raw, &body)
		if action == "bgp-validate" {
			out.Valid = true
			out.Config = body.Config
		}
		if action == "bgp-apply" {
			calls++
			config = body.Config
			revision = fmt.Sprintf("%x", sha256.Sum256(raw))
			out.BGP = &nodeBGPView{revision, config}
			out.Operation = &nodeBGPOperation{RequestID: id, Action: action, Confirmed: true, Status: "confirmed"}
		}
		return out, nil
	}
	no := false
	peer := nodeExternalPeer{ID: "fixture", Name: "Switch.fixture@IPv6", Enabled: &no, AFIs: []int{4, 6}, Keepalive: 1, Hold: 5, Exports: []string{}}
	proposed := nodeBGPFixture("amd103")
	proposed.ExternalPeers = []nodeExternalPeer{peer}
	request := func(mode string, c nodeBGPConfig, rev, id string) int {
		raw, _ := json.Marshal(nodeBGPRequest{ExpectedRevision: rev, Config: c, RequestID: id})
		w := nodeTestRequest(h, s, "POST", "/admin/nodes/amd103/bgp/"+mode, string(raw), s.Session.CSRF)
		return w.Code
	}
	if status := request("preview", proposed, revision, ""); status != 200 {
		t.Fatal("preview", status)
	}
	old := revision
	if status := request("apply", proposed, revision, "11111111-1111-4111-8111-111111111111"); status != 200 {
		t.Fatal("add", status)
	}
	proposed.ExternalPeers[0].Hold = 6
	if status := request("apply", proposed, old, "22222222-2222-4222-8222-222222222222"); status != 409 {
		t.Fatal("stale", status)
	}
	if status := request("apply", proposed, revision, "11111111-1111-4111-8111-111111111111"); status != 409 {
		t.Fatal("reused ID", status)
	}
	if status := request("apply", proposed, revision, "22222222-2222-4222-8222-222222222222"); status != 200 {
		t.Fatal("edit", status)
	}
	proposed.ExternalPeers[0].ID = "not-enrolled"
	if status := request("preview", proposed, revision, ""); status != 400 {
		t.Fatal("unknown target", status)
	}
	proposed.ExternalPeers = nil
	if status := request("apply", proposed, revision, "33333333-3333-4333-8333-333333333333"); status != 200 {
		t.Fatal("remove", status)
	}
	if calls != 3 || len(config.ExternalPeers) != 0 {
		t.Fatal("unexpected mutation", calls)
	}
}

func TestExternalPeerRoutesRejectAgentAndBearer(t *testing.T) {
	h, bearer := agentTestServer(t, []adminauth.Scope{adminauth.UIView, adminauth.RecordsRead, adminauth.RecordsWrite})
	h.NodeAdapterExecutable = filepath.Join(t.TempDir(), "python.exe")
	h.NodeAdapterScript = filepath.Join(t.TempDir(), "adapter.py")
	h.NodeAuditDirectory = t.TempDir()
	token, csrf, _, err := h.agent.sessions.Exchange(bearer, "realm", "node", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	h.nodeBGPRunner = func(context.Context, string, string, string, []byte) (nodeBGPResult, error) {
		calls++
		return nodeBGPResult{}, nil
	}
	for _, mode := range []string{"preview", "apply"} {
		for _, cookie := range []bool{false, true} {
			r := httptest.NewRequest("POST", "/admin/nodes/amd103/bgp/"+mode, strings.NewReader(`{}`))
			r.Header.Set("Origin", h.agent.origin)
			r.Header.Set("Sec-Fetch-Site", "same-origin")
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("X-SecDNS-CSRF", csrf)
			if cookie {
				r.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
			} else {
				r.Header.Set("Authorization", "Bearer "+bearer)
			}
			w := httptest.NewRecorder()
			h.routes().ServeHTTP(w, r)
			if w.Code != 403 {
				t.Fatal(mode, cookie, w.Code)
			}
		}
	}
	if calls != 0 {
		t.Fatal("agent reached node runner")
	}
}

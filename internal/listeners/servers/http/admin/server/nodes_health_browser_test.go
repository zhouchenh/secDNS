package server

import (
	"context"
	"encoding/json"
	"github.com/zhouchenh/secDNS/internal/adminauth"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Browser exercises actual human authorization, validation, CAS, audit and routes;
// only candidate process execution is a disposable in-memory fixture.
func TestNodeHealthBrowser(t *testing.T) {
	if os.Getenv("ADMINAUTH_BROWSER") != "1" {
		t.Skip("opt-in local Chromium")
	}
	h, session := nodeTestSetup(t)
	h.UI = true
	h.nodeRunner = func(_ context.Context, _, node, _ string) (nodeSnapshot, error) {
		raw := map[string]any{"schema": 1, "node": node, "observed_at": time.Now().UTC(), "reachable": true, "stale": false, "daemon": map[string]any{"active": true, "pid": 123}, "maintenance": map[string]bool{"withdraw": false}, "profiles": []any{}, "peers": []any{}}
		data, _ := json.Marshal(raw)
		var out nodeSnapshot
		_ = json.Unmarshal(data, &out)
		return out, nil
	}
	var mu sync.Mutex
	configs := map[string]map[string]int{}
	revisions := map[string]string{}
	h.nodeHealthRunner = func(_ context.Context, action, node, id string, payload []byte) (nodeHealthResult, error) {
		mu.Lock()
		defer mu.Unlock()
		if configs[node] == nil {
			configs[node] = map[string]int{"interval_seconds": 15, "probe_timeout_ms": 2500, "failure_threshold": 2, "recovery_threshold": 2}
			revisions[node] = strings.Repeat("a", 64)
		}
		var body struct {
			Config map[string]int `json:"config"`
		}
		if len(payload) > 0 {
			if err := json.Unmarshal(payload, &body); err != nil {
				return nodeHealthResult{}, err
			}
		}
		view := func(config map[string]int, revision string) map[string]any {
			return map[string]any{"schema": 1, "node": node, "revision": revision, "config": config, "derived": map[string]int{"stale_seconds": 2*config["interval_seconds"] + (2*config["probe_timeout_ms"]+999)/1000 + 1}}
		}
		raw := view(configs[node], revisions[node])
		if action == "health-validate" {
			raw = view(body.Config, revisions[node])
			raw["valid"] = true
		}
		if action == "health-apply" && body.Config["recovery_threshold"] == 3 {
			raw["health_settings"] = view(configs[node], revisions[node])
			raw["operation"] = map[string]any{"request_id": id, "action": "health-apply", "confirmed": false, "status": "rolled_back"}
		} else if action == "health-apply" {
			configs[node] = body.Config
			revisions[node] = strings.Repeat("b", 64)
			raw = view(configs[node], revisions[node])
			raw["health_settings"] = view(configs[node], revisions[node])
			raw["operation"] = map[string]any{"request_id": id, "action": "health-apply", "confirmed": true, "status": "confirmed"}
		}
		data, _ := json.Marshal(raw)
		var out nodeHealthResult
		err := json.Unmarshal(data, &out)
		return out, err
	}
	ts := httptest.NewUnstartedServer(h.routes())
	h.agent.origin = "https://" + ts.Listener.Addr().String()
	ts.StartTLS()
	defer ts.Close()
	script, _ := filepath.Abs("../../../../../../scripts/test-node-health-browser.cjs")
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "node", script)
	command.Env = append(os.Environ(), "NODE_HEALTH_QA_URL="+ts.URL, "NODE_HEALTH_QA_COOKIE="+session.Token)
	output, err := command.CombinedOutput()
	t.Log(string(output))
	if err != nil {
		t.Fatal(err)
	}
}

func TestNodeHealthAgentCookieRejected(t *testing.T) {
	a, bearer := agentTestServer(t, []adminauth.Scope{adminauth.UIView, adminauth.RecordsRead, adminauth.RecordsWrite})
	a.NodeAdapterExecutable = filepath.Join(t.TempDir(), "python.exe")
	a.NodeAdapterScript = filepath.Join(t.TempDir(), "adapter.py")
	a.NodeAuditDirectory = t.TempDir()
	token, csrf, _, err := a.agent.sessions.Exchange(bearer, "realm", "node", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	a.nodeHealthRunner = func(context.Context, string, string, string, []byte) (nodeHealthResult, error) {
		calls++
		return nodeHealthResult{}, nil
	}
	for _, endpoint := range []string{"", "/preview", "/apply"} {
		method := "POST"
		if endpoint == "" {
			method = "GET"
		}
		r := httptest.NewRequest(method, "/admin/nodes/amd103/health-settings"+endpoint, strings.NewReader(`{}`))
		r.Header.Set("Origin", a.agent.origin)
		r.Header.Set("Sec-Fetch-Site", "same-origin")
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-SecDNS-CSRF", csrf)
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
		w := httptest.NewRecorder()
		a.routes().ServeHTTP(w, r)
		if w.Code != 403 || calls != 0 {
			t.Fatalf("agent admitted on %s: status=%d calls=%d", endpoint, w.Code, calls)
		}
	}
}

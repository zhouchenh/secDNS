package server

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestNodeConsoleBrowser(t *testing.T) {
	if os.Getenv("ADMINAUTH_BROWSER") != "1" {
		t.Skip("opt-in local Chromium")
	}
	h, s := nodeTestSetup(t)
	h.UI = true
	var mu sync.Mutex
	withdraw := map[string]bool{}
	h.nodeRunner = func(ctx context.Context, action, node, id string) (nodeSnapshot, error) {
		mu.Lock()
		defer mu.Unlock()
		state := withdraw[node]
		if action != "status" {
			state = action == "drain"
			withdraw[node] = state
		}
		raw := map[string]any{"schema": 1, "node": node, "observed_at": time.Now().UTC(), "reachable": true, "stale": false, "daemon": map[string]any{"active": true, "pid": 123}, "maintenance": map[string]bool{"withdraw": state}, "profiles": []any{map[string]any{"role": "normal", "family": 4, "healthy": true, "advertised": !state, "prefix": "192.0.2.53/32"}, map[string]any{"role": "dns64", "family": 6, "healthy": true, "advertised": !state, "prefix": "2001:db8::64/128"}}, "peers": []any{map[string]any{"address": "192.0.2.1", "family": 4, "state": "Established", "prefixes": []string{"192.0.2.53/32"}}}}
		if action != "status" {
			raw["operation"] = map[string]any{"request_id": id, "action": action, "confirmed": true, "status": "confirmed"}
		}
		b, _ := json.Marshal(raw)
		var out nodeSnapshot
		json.Unmarshal(b, &out)
		return out, nil
	}
	if executable := os.Getenv("NODE_QA_REAL_EXECUTABLE"); executable != "" {
		h.NodeAdapterExecutable = executable
		h.NodeAdapterScript = os.Getenv("NODE_QA_REAL_SCRIPT")
		h.nodeRunner = nil
	}
	ts := httptest.NewUnstartedServer(h.routes())
	h.agent.origin = "https://" + ts.Listener.Addr().String()
	ts.StartTLS()
	defer ts.Close()
	script, _ := filepath.Abs("../../../../../../scripts/test-node-console-browser.cjs")
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "node", script)
	cmd.Env = append(os.Environ(), "NODE_QA_URL="+ts.URL, "NODE_QA_COOKIE="+s.Token)
	out, e := cmd.CombinedOutput()
	t.Log(string(out))
	if e != nil {
		t.Fatal(e)
	}
}

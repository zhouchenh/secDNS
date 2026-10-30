package server

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// The drain API refuses to withdraw the last healthy provider of a prefix the node announces,
// before any receipt or adapter mutation (review R2 / item 3).
func TestNodeDrainRefusesLastHealthyProvider(t *testing.T) {
	type view struct {
		prefixes            []string
		healthy, stale, off bool
		withdrawn, down     bool
	}
	for _, c := range []struct {
		name   string
		others map[string]view
		want   int
	}{
		{"another healthy provider for every prefix", map[string]view{"intel108": {prefixes: []string{"192.0.2.53/32", "192.0.2.64/32"}, healthy: true}, "cix106": {down: true}}, 200},
		{"one prefix only on this node", map[string]view{"intel108": {prefixes: []string{"192.0.2.53/32"}, healthy: true}, "cix106": {prefixes: []string{"192.0.2.53/32"}, healthy: true}}, 409},
		{"other provider failing its check", map[string]view{"intel108": {prefixes: []string{"192.0.2.53/32", "192.0.2.64/32"}}, "cix106": {down: true}}, 409},
		{"other provider stale", map[string]view{"intel108": {prefixes: []string{"192.0.2.53/32", "192.0.2.64/32"}, healthy: true, stale: true}, "cix106": {down: true}}, 409},
		{"other provider drained", map[string]view{"intel108": {prefixes: []string{"192.0.2.53/32", "192.0.2.64/32"}, healthy: true, withdrawn: true}, "cix106": {down: true}}, 409},
		{"other provider DNS stopped", map[string]view{"intel108": {prefixes: []string{"192.0.2.53/32", "192.0.2.64/32"}, healthy: true, off: true}, "cix106": {down: true}}, 409},
		{"providers split across two nodes", map[string]view{"intel108": {prefixes: []string{"192.0.2.53/32"}, healthy: true}, "cix106": {prefixes: []string{"192.0.2.64/32"}, healthy: true}}, 200},
	} {
		t.Run(c.name, func(t *testing.T) {
			h, s := nodeTestSetup(t)
			var mu sync.Mutex
			mutations := 0
			h.nodeRunner = func(_ context.Context, action, node, id string) (nodeSnapshot, error) {
				mu.Lock()
				defer mu.Unlock()
				v := view{prefixes: []string{"192.0.2.53/32", "192.0.2.64/32"}, healthy: true}
				if node != "amd103" {
					v = c.others[node]
				}
				if v.down {
					return nodeSnapshot{}, fmt.Errorf("unreachable")
				}
				var profiles []map[string]any
				for _, p := range v.prefixes {
					profiles = append(profiles, map[string]any{"role": "normal", "family": 4, "enabled": true, "healthy": v.healthy, "advertised": !v.withdrawn, "prefix": p})
				}
				raw := map[string]any{"schema": 1, "node": node, "observed_at": time.Now().UTC(), "reachable": true, "stale": v.stale,
					"daemon": map[string]any{"active": !v.off}, "maintenance": map[string]bool{"withdraw": v.withdrawn}, "profiles": profiles}
				if action != "status" {
					mutations++
					raw["operation"] = map[string]any{"request_id": id, "action": action, "confirmed": true, "status": "confirmed"}
				}
				b, _ := json.Marshal(raw)
				var out nodeSnapshot
				return out, json.Unmarshal(b, &out)
			}
			body := `{"action":"drain","request_id":"33333333-3333-4333-8333-333333333333","expected_withdraw":"false","confirm_node":"amd103"}`
			w := nodeTestRequest(h, s, "POST", "/admin/nodes/amd103/maintenance", body, s.Session.CSRF)
			if w.Code != c.want {
				t.Fatalf("want %d, got %d %s", c.want, w.Code, w.Body.String())
			}
			entries, _ := os.ReadDir(h.NodeAuditDirectory)
			if c.want == 409 {
				if !strings.Contains(w.Body.String(), "last_healthy_provider") || mutations != 0 || len(entries) != 0 {
					t.Fatalf("refused drain mutated: %s mutations=%d receipts=%d", w.Body.String(), mutations, len(entries))
				}
			} else if mutations != 1 {
				t.Fatalf("allowed drain: %d mutations", mutations)
			}
		})
	}
}

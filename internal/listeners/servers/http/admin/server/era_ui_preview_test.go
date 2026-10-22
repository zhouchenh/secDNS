package server

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/zhouchenh/secDNS/internal/recordset"
	"github.com/zhouchenh/secDNS/internal/recordstore"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// Opt-in disposable backend preview; never binds outside loopback or invokes an adapter.
func TestEraUIManualPreview(t *testing.T) {
	if os.Getenv("SECDNS_ERA_PREVIEW") != "1" {
		t.Skip("local manual preview")
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
		profiles := []any{}
		for _, role := range []string{"normal", "dns64"} {
			for _, family := range []int{4, 6} {
				prefix := "192.0.2.53/32"
				if role == "dns64" {
					prefix = "192.0.2.64/32"
				}
				if family == 6 {
					prefix = "2001:db8::53/128"
					if role == "dns64" {
						prefix = "2001:db8::64/128"
					}
				}
				profiles = append(profiles, map[string]any{"role": role, "family": family, "enabled": true, "healthy": true, "local_healthy": true, "upstream_healthy": true, "upstream_age_seconds": 3, "reason": "ready", "advertised": !state, "prefix": prefix})
			}
		}
		raw["profiles"] = profiles
		raw["peers"] = []any{
			map[string]any{"address": "192.0.2.101", "family": 4, "state": "Established", "prefixes": []string{"192.0.2.53/32", "192.0.2.64/32"}},
			map[string]any{"address": "192.0.2.102", "family": 4, "state": "Established", "prefixes": []string{"192.0.2.53/32", "192.0.2.64/32"}},
			map[string]any{"address": "2001:db8:1234:5678:abcd:ef01:2345:6789", "family": 6, "state": "Established", "prefixes": []string{"2001:db8:1234:5678::53/128", "2001:db8:1234:5678::64/128"}},
			map[string]any{"address": "2001:db8:9876:5432:ffff:eeee:dddd:cccc", "family": 6, "state": "Established", "prefixes": []string{"2001:db8:1234:5678::53/128", "2001:db8:1234:5678::64/128"}},
		}
		if node == os.Getenv("SECDNS_ERA_STALE_NODE") {
			raw["stale"] = true
			raw["observed_at"] = time.Now().Add(-time.Minute).UTC()
		}

		if action != "status" {
			raw["operation"] = map[string]any{"request_id": id, "action": action, "confirmed": true, "status": "confirmed"}
		}
		b, _ := json.Marshal(raw)
		var out nodeSnapshot
		json.Unmarshal(b, &out)
		return out, nil
	}
	configs := map[string]nodeBGPConfig{}
	revisions := map[string]string{}
	h.nodeBGPRunner = func(ctx context.Context, action, node, id string, payload []byte) (nodeBGPResult, error) {
		mu.Lock()
		defer mu.Unlock()
		if _, ok := configs[node]; !ok {
			configs[node] = nodeBGPFixture(node)
			revisions[node] = strings.Repeat("a", 64)
		}
		out := nodeBGPResult{Schema: 1, Node: node, Revision: revisions[node], Config: configs[node]}
		if os.Getenv("SECDNS_EXTERNAL_PREVIEW") == "1" {
			out.ExternalPolicy = &nodeExternalPolicy{Schema: 1, Node: node, Peers: []nodeExternalEnrollment{}}
			if node != "intel108" {
				out.ExternalPolicy.Peers = append(out.ExternalPolicy.Peers, nodeExternalEnrollment{ID: "fixture-switch", Address: "2001:db8:85:1::1", TransportFamily: 6, LocalSource: "2001:db8:85:1::", LocalASN: 8505, RemoteASN: 8501, Port: 179, AllowedAFIs: []int{4, 6}, AllowedExports: []string{"203.0.113.53/32", "203.0.113.64/32", "2001:db8:53::53/128", "2001:db8:53::64/128"}})
			}
			for _, p := range configs[node].ExternalPeers {
				for _, f := range p.AFIs {
					out.ExternalStatus = append(out.ExternalStatus, nodeExternalObservation{ID: p.ID, Family: f, State: "Idle", Observed: true, Prefixes: []string{}})
				}
			}
		}

		var body nodeBGPRequest
		if len(payload) > 0 {
			json.Unmarshal(payload, &body)
		}
		if action == "bgp-validate" {
			out.Config = body.Config
			out.Valid = true
		}
		if action == "bgp-apply" {
			configs[node] = body.Config
			revisions[node] = fmt.Sprintf("%x", sha256.Sum256(payload))
			out.BGP = &nodeBGPView{revisions[node], configs[node]}
			out.Operation = &nodeBGPOperation{RequestID: id, Action: action, Confirmed: true, Status: "confirmed"}
		}
		return out, nil
	}
	healthConfigs := map[string]map[string]int{}
	healthRevisions := map[string]string{}
	h.nodeHealthRunner = func(_ context.Context, action, node, id string, payload []byte) (nodeHealthResult, error) {
		mu.Lock()
		defer mu.Unlock()
		if healthConfigs[node] == nil {
			healthConfigs[node] = map[string]int{"interval_seconds": 15, "probe_timeout_ms": 2500, "failure_threshold": 2, "recovery_threshold": 2}
			healthRevisions[node] = strings.Repeat("a", 64)
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
		raw := view(healthConfigs[node], healthRevisions[node])
		if action == "health-validate" {
			raw = view(body.Config, healthRevisions[node])
			raw["valid"] = true
		}
		if action == "health-apply" && body.Config["recovery_threshold"] == 3 {
			raw["health_settings"] = view(healthConfigs[node], healthRevisions[node])
			raw["operation"] = map[string]any{"request_id": id, "action": "health-apply", "confirmed": false, "status": "rolled_back"}
		} else if action == "health-apply" {
			healthConfigs[node] = body.Config
			healthRevisions[node] = strings.Repeat("b", 64)
			raw = view(healthConfigs[node], healthRevisions[node])
			raw["health_settings"] = view(healthConfigs[node], healthRevisions[node])
			raw["operation"] = map[string]any{"request_id": id, "action": "health-apply", "confirmed": true, "status": "confirmed"}
		}
		data, _ := json.Marshal(raw)
		var out nodeHealthResult
		err := json.Unmarshal(data, &out)
		return out, err
	}

	store, err := recordstore.NewVersionedMemory(recordstore.Enrollment{RulesetID: "design-preview", LineageID: "disposable"})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	h.versioned = store
	records := []recordset.Record{{Name: "gateway.office.invalid.", Type: "A", Values: []string{"192.0.2.1"}, TTLSeconds: 300}, {Name: "files.office.invalid.", Type: "AAAA", Values: []string{"2001:db8::20"}, TTLSeconds: 300}, {Name: "docs.office.invalid.", Type: "CNAME", Values: []string{"files.office.invalid."}, TTLSeconds: 300}, {Name: "printer.office.invalid.", Type: "A", Values: []string{"192.0.2.20"}, TTLSeconds: 60}}
	if _, err = store.Replace(recordstore.Expected{RulesetID: "design-preview", LineageID: "disposable", Revision: 1}, "preview-seed", records); err != nil {
		t.Fatal(err)
	}
	previewAddress := "127.0.0.1:5194"
	if os.Getenv("SECDNS_EXTERNAL_PREVIEW") == "1" {
		previewAddress = "127.0.0.1:5196"
	}
	listener, err := net.Listen("tcp", previewAddress)
	if err != nil {
		t.Fatal(err)
	}
	h.agent.origin = "http://" + previewAddress
	routes := h.routes()
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: s.Token})
		routes.ServeHTTP(w, r)
	})}
	go server.Serve(listener)
	defer server.Close()
	t.Log("Disposable backend preview http://" + previewAddress + "/admin/ui/")
	time.Sleep(90 * time.Minute)
}

// A separate unauthenticated fixture presents the real sign-in UI without
// touching the enrolled preview session or any real account.
func TestEraUISignInPreview(t *testing.T) {
	if os.Getenv("SECDNS_ERA_SIGNIN") != "1" {
		t.Skip("local sign-in preview")
	}
	h, _ := nodeTestSetup(t)
	h.UI = true
	h.NodeAdapterExecutable = ""
	h.NodeAdapterScript = ""
	listener, err := net.Listen("tcp", "127.0.0.1:5195")
	if err != nil {
		t.Fatal(err)
	}
	h.agent.origin = "http://127.0.0.1:5195"
	routes := h.routes()
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "Visual fixture: submissions disabled", http.StatusMethodNotAllowed)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/auth/human.js") {
			capture := httptest.NewRecorder()
			routes.ServeHTTP(capture, r)
			for key, values := range capture.Header() {
				for _, value := range values {
					w.Header().Add(key, value)
				}
			}
			w.Header().Del("Content-Length")
			script := capture.Body.String()
			marker := strings.LastIndex(script, "})();")
			if capture.Code != http.StatusOK || marker < 0 {
				t.Error("missing real auth renderer")
				http.Error(w, "fixture unavailable", 500)
				return
			}
			script = script[:marker] + eraAuthVisualStates + script[marker:]
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(script))
			return
		}
		routes.ServeHTTP(w, r)
	})}
	go server.Serve(listener)
	defer server.Close()
	t.Log("Disposable sign-in preview http://127.0.0.1:5195/admin/ui/")
	time.Sleep(90 * time.Minute)
}

// Test-only visual inputs drive the existing renderer, without authentication requests.
// This constant is compiled only into the opt-in loopback test binary, never secDNS.
const eraAuthVisualStates = `
 const visual=new URLSearchParams(location.search).get('auth_visual');
 if(['mfa','setup','recovery','expired','error','loading'].includes(visual)){
  const fixtureLabel=document.createElement('p');fixtureLabel.textContent='Disposable visual fixture — submissions disabled';card.prepend(fixtureLabel);
  document.addEventListener('submit',event=>{event.preventDefault();event.stopImmediatePropagation();},true);
  const showVisual=()=>{step='start';replacement=false;setupRequired=false;mode.value='login';busy=false;
   if(visual==='mfa')step='otp';
   if(visual==='setup'){setupRequired=true;mode.value='setup';}
   if(visual==='recovery')mode.value='code';
   if(visual==='expired')note.textContent='Sign-in timed out. Enter your username and password to start again.';
   if(visual==='error')note.textContent='Sign-in could not be completed. Check your details or wait before trying again.';
   if(visual==='loading'){busy=true;note.textContent='Checking sign-in…';}
   render();
  };
  window.addEventListener('authstate',()=>queueMicrotask(showVisual));if(window.secDNSAgent.state)queueMicrotask(showVisual);
 }
`

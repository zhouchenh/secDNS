package server

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNodeHealthCASReceiptAndCSRF(t *testing.T) {
	h, s := nodeTestSetup(t)
	revision := strings.Repeat("a", 64)
	config := nodeHealthConfig{15, 2500, 2, 2}
	applies := 0
	h.nodeHealthRunner = func(_ context.Context, action, node, id string, raw []byte) (nodeHealthResult, error) {
		out := nodeHealthResult{Schema: 1, Node: node, Revision: revision, Config: config, Derived: healthDerived(config)}
		if action == "health-validate" {
			var b nodeHealthRequest
			json.Unmarshal(raw, &b)
			out.Config = b.Config
			out.Derived = healthDerived(b.Config)
			out.Valid = true
		}
		if action == "health-apply" {
			applies++
			var b nodeHealthRequest
			json.Unmarshal(raw, &b)
			config = b.Config
			revision = strings.Repeat("b", 64)
			out.HealthSettings = &nodeHealthView{1, node, revision, config, healthDerived(config)}
			out.Operation = &nodeBGPOperation{RequestID: id, Action: action, Status: "confirmed", Confirmed: true}
		}
		return out, nil
	}
	body := nodeHealthRequest{ExpectedRevision: revision, Config: nodeHealthConfig{3, 1000, 2, 2}}
	raw, _ := json.Marshal(body)
	path := "/admin/nodes/amd103/health-settings/"
	if w := nodeTestRequest(h, s, "POST", path+"preview", string(raw), ""); w.Code != 403 {
		t.Fatal(w.Code)
	}
	if w := nodeTestRequest(h, s, "POST", path+"preview", string(raw), s.Session.CSRF); w.Code != 200 || applies != 0 {
		t.Fatal(w.Code, w.Body)
	}
	body.RequestID = "71111111-1111-4111-8111-111111111111"
	body.ConfirmNode = "amd103"
	raw, _ = json.Marshal(body)
	if w := nodeTestRequest(h, s, "POST", path+"apply", string(raw), s.Session.CSRF); w.Code != 200 || applies != 1 {
		t.Fatal(w.Code, w.Body)
	}
	if w := nodeTestRequest(h, s, "POST", path+"apply", string(raw), s.Session.CSRF); w.Code != 409 || applies != 1 {
		t.Fatal("CAS", w.Code)
	}
	body.ExpectedRevision = revision
	raw, _ = json.Marshal(body)
	if w := nodeTestRequest(h, s, "POST", path+"apply", string(raw), s.Session.CSRF); w.Code != 409 || applies != 1 {
		t.Fatal("receipt", w.Code)
	}
}
func TestNodeHealthRejectMalformedHelper(t *testing.T) {
	for _, bad := range []string{"missing", "mismatch", "derived", "rollback"} {
		t.Run(bad, func(t *testing.T) {
			h, s := nodeTestSetup(t)
			old := nodeHealthConfig{15, 2500, 2, 2}
			wanted := nodeHealthConfig{3, 1000, 2, 2}
			rev := strings.Repeat("a", 64)
			h.nodeHealthRunner = func(_ context.Context, action, node, id string, _ []byte) (nodeHealthResult, error) {
				out := nodeHealthResult{Schema: 1, Node: node, Revision: rev, Config: old, Derived: healthDerived(old)}
				if action == "health-apply" {
					out.Operation = &nodeBGPOperation{RequestID: id, Action: action, Confirmed: true, Status: "confirmed"}
					out.HealthSettings = &nodeHealthView{1, node, strings.Repeat("b", 64), wanted, healthDerived(wanted)}
					switch bad {
					case "missing":
						out.HealthSettings = nil
					case "mismatch":
						out.HealthSettings.Config = old
					case "derived":
						out.HealthSettings.Derived.StaleSeconds = 1
					case "rollback":
						out.Operation.Confirmed = false
						out.Operation.Status = "rolled_back"
					}
				}
				return out, nil
			}
			raw, _ := json.Marshal(nodeHealthRequest{ExpectedRevision: rev, Config: wanted, RequestID: "72222222-2222-4222-8222-222222222222", ConfirmNode: "amd103"})
			if w := nodeTestRequest(h, s, "POST", "/admin/nodes/amd103/health-settings/apply", string(raw), s.Session.CSRF); w.Code != 502 {
				t.Fatal(w.Code, w.Body)
			}
		})
	}
}
func TestNodeHealthStrictInput(t *testing.T) {
	for _, cfg := range []nodeHealthConfig{{3, 1500, 2, 2}, {3, 1000, 1, 2}, {15, 2500, 2, 6}} {
		if validateNodeHealth("amd103", cfg) == nil {
			t.Fatal("invalid settings")
		}
	}
	raw := `{"expected_revision":"` + strings.Repeat("a", 64) + `","config":{"interval_seconds":3,"probe_timeout_ms":1000,"failure_threshold":2,"recovery_threshold":2}}`
	for _, bad := range []string{strings.Replace(raw, `"interval_seconds":3`, `"interval_seconds":3,"interval_seconds":3`, 1), strings.Replace(raw, `"interval_seconds":3`, `"interval_seconds":true`, 1), strings.Replace(raw, `"interval_seconds":3`, `"interval_seconds":3,"host":"8.8.8.8"`, 1)} {
		if _, e := readNodeHealthRequest(httptest.NewRecorder(), httptest.NewRequest("POST", "/", strings.NewReader(bad)), "amd103", false); e == nil {
			t.Fatal("bad input accepted")
		}
	}
}

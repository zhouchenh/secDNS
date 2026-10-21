package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
)

func nodeBGPFixture(node string) nodeBGPConfig {
	own := nodeBGPIdentities[node]
	c := nodeBGPConfig{LocalASN: own.ASN, RouterID: own.IPv4}
	yes := true
	for _, id := range nodeIDs {
		if id == node {
			continue
		}
		peer := nodeBGPIdentities[id]
		for _, family := range []int{4, 6} {
			address := peer.IPv4
			if family == 6 {
				address = peer.IPv6
			}
			c.Peers = append(c.Peers, nodeBGPPeer{address, family, peer.ASN, &yes, 3, 9})
		}
	}
	for _, role := range []string{"normal", "dns64"} {
		for _, family := range []int{4, 6} {
			c.Announcements = append(c.Announcements, nodeAnnouncement{role, family, &yes})
		}
	}
	return c
}
func TestNodeBGPStrictInventory(t *testing.T) {
	for _, node := range nodeIDs {
		c := nodeBGPFixture(node)
		if e := validateNodeBGP(node, c); e != nil {
			t.Fatal(e)
		}
		c.Peers[0].Address = "8.8.8.8"
		if validateNodeBGP(node, c) == nil {
			t.Fatal("externalpeer")
		}
		c = nodeBGPFixture(node)
		c.Peers[0].RemoteASN = 65000
		if validateNodeBGP(node, c) == nil {
			t.Fatal("wrongASN")
		}
		c = nodeBGPFixture(node)
		c.Peers[0].Keepalive = 4
		if validateNodeBGP(node, c) == nil {
			t.Fatal("holdratio")
		}
		c = nodeBGPFixture(node)
		no := false
		for i := range c.Peers {
			if c.Peers[i].Family == 6 {
				c.Peers[i].Enabled = &no
			}
		}
		if validateNodeBGP(node, c) == nil {
			t.Fatal("noIPv6peer")
		}
		c = nodeBGPFixture(node)
		c.Announcements[0].Enabled = nil
		if validateNodeBGP(node, c) == nil {
			t.Fatal("missingexplicitflag")
		}
	}
}
func TestNodeBGPPreviewApplyCASAudit(t *testing.T) {
	h, s := nodeTestSetup(t)
	revision := strings.Repeat("a", 64)
	config := nodeBGPFixture("amd103")
	applies := 0
	h.nodeBGPRunner = func(ctx context.Context, action, node, id string, raw []byte) (nodeBGPResult, error) {
		out := nodeBGPResult{Schema: 1, Node: node, Revision: revision, Config: config}
		if action == "bgp-validate" {
			out.Valid = true
		}
		if action == "bgp-apply" {
			applies++
			var body nodeBGPRequest
			json.Unmarshal(raw, &body)
			config = body.Config
			revision = strings.Repeat("b", 64)
			out.BGP = &nodeBGPView{revision, config}
			out.Operation = &nodeBGPOperation{RequestID: id, Action: action, Confirmed: true, Status: "confirmed"}
		}
		return out, nil
	}
	config.Peers[0].Hold = 12
	body := nodeBGPRequest{ExpectedRevision: revision, Config: config}
	raw, _ := json.Marshal(body)
	path := "/admin/nodes/amd103/bgp/"
	w := nodeTestRequest(h, s, "POST", path+"preview", string(raw), "")
	if w.Code != 403 {
		t.Fatal(w.Code)
	}
	w = nodeTestRequest(h, s, "POST", path+"preview", string(raw), s.Session.CSRF)
	if w.Code != 200 || applies != 0 {
		t.Fatal(w.Code, applies)
	}
	body.RequestID = "55555555-5555-4555-8555-555555555555"
	raw, _ = json.Marshal(body)
	w = nodeTestRequest(h, s, "POST", path+"apply", string(raw), s.Session.CSRF)
	if w.Code != 200 || applies != 1 {
		t.Fatal(w.Code, w.Body)
	}
	w = nodeTestRequest(h, s, "POST", path+"apply", string(raw), s.Session.CSRF)
	if w.Code != 409 || applies != 1 {
		t.Fatal("CAS did not protect", w.Code)
	}
	body.ExpectedRevision = revision
	raw, _ = json.Marshal(body)
	w = nodeTestRequest(h, s, "POST", path+"apply", string(raw), s.Session.CSRF)
	if w.Code != 409 || applies != 1 {
		t.Fatal("receipt did not protect", w.Code)
	}
}
func TestNodeBGPRejectDuplicateAndUnknownFields(t *testing.T) {
	base := nodeBGPRequest{ExpectedRevision: strings.Repeat("a", 64), Config: nodeBGPFixture("amd103")}
	raw, _ := json.Marshal(base)
	for _, text := range []string{strings.Replace(string(raw), `"local_asn":65101`, `"local_asn":65101,"local_asn":65101`, 1), strings.Replace(string(raw), `"local_asn"`, `"LOCAL_ASN"`, 1), strings.Replace(string(raw), `"local_asn":65101`, `"local_asn":65101,"command":"evil"`, 1), fmt.Sprintf("%s{}", raw)} {
		r := httptest.NewRequest("POST", "/", strings.NewReader(text))
		if _, e := readNodeBGPRequest(httptest.NewRecorder(), r, "amd103", false); e == nil {
			t.Fatal("noncanonical request accepted")
		}
	}
}

func TestNodeBGPRefusesUnverifiedHelperResults(t *testing.T) {
	for _, scenario := range []string{"preview_wrong_config", "preview_wrong_revision", "apply_missing_bgp", "apply_wrong_config", "apply_false_rollback"} {
		t.Run(scenario, func(t *testing.T) {
			h, s := nodeTestSetup(t)
			baseline := nodeBGPFixture("amd103")
			proposed := nodeBGPFixture("amd103")
			proposed.Peers[0].Hold = 18
			revision := strings.Repeat("a", 64)
			h.nodeBGPRunner = func(ctx context.Context, action, node, id string, payload []byte) (nodeBGPResult, error) {
				out := nodeBGPResult{Schema: 1, Node: node, Revision: revision, Config: baseline}
				if action == "bgp-validate" {
					out.Valid = true
					out.Config = proposed
					if scenario == "preview_wrong_config" {
						out.Config = baseline
					}
					if scenario == "preview_wrong_revision" {
						out.Revision = strings.Repeat("b", 64)
					}
				}
				if action == "bgp-apply" {
					out.Operation = &nodeBGPOperation{RequestID: id, Action: action, Confirmed: true, Status: "confirmed"}
					if scenario != "apply_missing_bgp" {
						out.BGP = &nodeBGPView{revision, baseline}
					}
					if scenario == "apply_false_rollback" {
						out.Operation.Confirmed = false
						out.Operation.Status = "rolled_back"
						out.BGP.Config = proposed
					}
				}
				return out, nil
			}
			body := nodeBGPRequest{ExpectedRevision: revision, Config: proposed}
			mode := "preview"
			expected := 409
			if strings.HasPrefix(scenario, "apply") {
				mode = "apply"
				expected = 502
				body.RequestID = "66666666-6666-4666-8666-666666666666"
			}
			raw, _ := json.Marshal(body)
			w := nodeTestRequest(h, s, "POST", "/admin/nodes/amd103/bgp/"+mode, string(raw), s.Session.CSRF)
			if w.Code != expected {
				t.Fatal("unverified outcome admitted", w.Code, w.Body)
			}
		})
	}
}

func TestNodeBGPVerifiedRollback(t *testing.T) {
	h, s := nodeTestSetup(t)
	baseline := nodeBGPFixture("amd103")
	proposed := nodeBGPFixture("amd103")
	proposed.Peers[0].Hold = 12
	revision := strings.Repeat("a", 64)
	h.nodeBGPRunner = func(ctx context.Context, action, node, id string, payload []byte) (nodeBGPResult, error) {
		out := nodeBGPResult{Schema: 1, Node: node, Revision: revision, Config: baseline}
		if action == "bgp-apply" {
			out.Operation = &nodeBGPOperation{RequestID: id, Action: action, Confirmed: false, Status: "rolled_back", Rollback: "restored"}
			out.BGP = &nodeBGPView{revision, baseline}
		}
		return out, nil
	}
	raw, _ := json.Marshal(nodeBGPRequest{ExpectedRevision: revision, Config: proposed, RequestID: "77777777-7777-4777-8777-777777777777"})
	w := nodeTestRequest(h, s, "POST", "/admin/nodes/amd103/bgp/apply", string(raw), s.Session.CSRF)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"status":"rolled_back"`) {
		t.Fatal(w.Code, w.Body)
	}
}

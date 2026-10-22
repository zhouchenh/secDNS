package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"
)

type nodeBGPPeer struct {
	Address   string `json:"address"`
	Family    int    `json:"family"`
	RemoteASN int    `json:"remote_asn"`
	Enabled   *bool  `json:"enabled"`
	Keepalive int    `json:"keepalive_seconds"`
	Hold      int    `json:"hold_seconds"`
}
type nodeAnnouncement struct {
	Role    string `json:"role"`
	Family  int    `json:"family"`
	Enabled *bool  `json:"enabled"`
}
type nodeBGPConfig struct {
	ExternalPeers []nodeExternalPeer `json:"external_peers,omitempty"`
	LocalASN      int                `json:"local_asn"`
	RouterID      string             `json:"router_id"`
	Peers         []nodeBGPPeer      `json:"peers"`
	Announcements []nodeAnnouncement `json:"announcements"`
}
type nodeBGPView struct {
	Revision string        `json:"revision"`
	Config   nodeBGPConfig `json:"config"`
}
type nodeBGPResult struct {
	ExternalPolicy *nodeExternalPolicy       `json:"external_policy,omitempty"`
	ExternalStatus []nodeExternalObservation `json:"external_status,omitempty"`
	Schema         int                       `json:"schema"`
	Node           string                    `json:"node"`
	Revision       string                    `json:"revision,omitempty"`
	Config         nodeBGPConfig             `json:"config"`
	Valid          bool                      `json:"valid,omitempty"`
	BGP            *nodeBGPView              `json:"bgp,omitempty"`
	Operation      *nodeBGPOperation         `json:"operation,omitempty"`
}
type nodeBGPOperation struct {
	RequestID string `json:"request_id"`
	Action    string `json:"action"`
	Confirmed bool   `json:"confirmed"`
	Status    string `json:"status"`
	Rollback  string `json:"rollback,omitempty"`
}
type nodeBGPRequest struct {
	ExpectedRevision string        `json:"expected_revision"`
	Config           nodeBGPConfig `json:"config"`
	RequestID        string        `json:"request_id,omitempty"`
}

var nodeRevision = regexp.MustCompile(`^[a-f0-9]{64}$`)
var nodeBGPIdentities = map[string]struct {
	ASN        int
	IPv4, IPv6 string
}{
	"amd103":   {65101, "100.91.1.82", "2001:470:f9d1:9001:be24:11ff:fe53:e209"},
	"cix106":   {65102, "100.91.1.83", "2001:470:f9d1:9001:45:52ff:fe41:106"},
	"intel108": {65103, "100.91.1.84", "2001:470:f9d1:9001:45:52ff:fe41:108"},
}

func validateNodeBGP(node string, c nodeBGPConfig) error {
	own, ok := nodeBGPIdentities[node]
	if !ok || c.LocalASN != own.ASN || c.RouterID != own.IPv4 || len(c.Peers) != 4 || len(c.Announcements) != 4 {
		return errors.New("candidate_identity_mismatch")
	}
	seen := map[string]bool{}
	enabled := map[int]int{}
	for _, p := range c.Peers {
		valid := false
		for id, peer := range nodeBGPIdentities {
			if id == node {
				continue
			}
			if p.RemoteASN == peer.ASN && ((p.Family == 4 && p.Address == peer.IPv4) || (p.Family == 6 && p.Address == peer.IPv6)) {
				valid = true
			}
		}
		if !valid || seen[p.Address] || p.Enabled == nil {
			return errors.New("candidate_peer_mismatch")
		}
		seen[p.Address] = true
		if p.Keepalive < 3 || p.Keepalive > 30 || p.Hold < 9 || p.Hold > 90 || p.Hold < 3*p.Keepalive {
			return errors.New("invalid_bgp_timers")
		}
		if *p.Enabled {
			enabled[p.Family]++
		}
	}
	if enabled[4] == 0 || enabled[6] == 0 {
		return errors.New("one_peer_per_family_required")
	}
	profiles := map[string]bool{}
	for _, p := range c.Announcements {
		key := p.Role + string(rune(p.Family))
		if (p.Role != "normal" && p.Role != "dns64") || (p.Family != 4 && p.Family != 6) || p.Enabled == nil || profiles[key] {
			return errors.New("invalid_announcement_inventory")
		}
		profiles[key] = true
	}
	return validateExternalPeers(c.ExternalPeers)
}
func (h *HTTPAdminServer) runNodeBGP(ctx context.Context, action, node, id string, body []byte) (nodeBGPResult, error) {
	var out nodeBGPResult
	if !h.nodesEnabled() || !knownNode(node) {
		return out, errors.New("node management unavailable")
	}
	if h.nodeBGPRunner != nil {
		return h.nodeBGPRunner(ctx, action, node, id, body)
	}
	args := []string{h.NodeAdapterScript, action, node}
	if id != "" {
		args = append(args, id)
	}
	cmd := exec.CommandContext(ctx, h.NodeAdapterExecutable, args...)
	cmd.WaitDelay = 2 * time.Second
	cmd.Stdin = bytes.NewReader(body)
	var output limitedNodeOutput
	cmd.Stdout = &output
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return out, errors.New("bgp_operation_unconfirmed")
	}
	if json.Unmarshal(output.Bytes(), &out) != nil || out.Schema != 1 || out.Node != node {
		return out, errors.New("invalid_bgp_observation")
	}
	return out, nil
}
func readNodeBGPRequest(w http.ResponseWriter, r *http.Request, node string, apply bool) (nodeBGPRequest, error) {
	var body nodeBGPRequest
	r.Body = http.MaxBytesReader(w, r.Body, 16384)
	defer r.Body.Close()
	raw, readErr := io.ReadAll(r.Body)
	if readErr != nil || strictNodeJSON(json.NewDecoder(bytes.NewReader(raw)), 0) != nil {
		return body, errors.New("invalid_bgp_request")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&body) != nil || d.Decode(new(any)) != io.EOF {
		return body, errors.New("invalid_bgp_request")
	}
	if !nodeRevision.MatchString(body.ExpectedRevision) || (apply && !nodeRequestID.MatchString(body.RequestID)) || (!apply && body.RequestID != "") {
		return body, errors.New("invalid_bgp_revision_or_request")
	}
	return body, validateNodeBGP(node, body.Config)
}
func (h *HTTPAdminServer) nodeBGPRoutes(mux *http.ServeMux, base string) {
	if !h.nodesEnabled() {
		return
	}
	mux.HandleFunc("GET "+base+"/nodes/{node}/bgp", h.withNodeHuman(false, func(w http.ResponseWriter, r *http.Request, _ string) {
		node := r.PathValue("node")
		if !knownNode(node) {
			agentError(w, 404, "unknown_node")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		out, err := h.runNodeBGP(ctx, "bgp-get", node, "", nil)
		if err != nil || validateNodeBGP(node, out.Config) != nil || !nodeRevision.MatchString(out.Revision) {
			agentError(w, 503, "bgp_configuration_unavailable")
			return
		}
		writeJSON(w, 200, out)
	}))
	for _, mode := range []string{"preview", "apply"} {
		mux.HandleFunc("POST "+base+"/nodes/{node}/bgp/"+mode, h.withNodeHuman(true, func(w http.ResponseWriter, r *http.Request, actor string) {
			node := r.PathValue("node")
			if !knownNode(node) {
				agentError(w, 404, "unknown_node")
				return
			}
			apply := mode == "apply"
			body, err := readNodeBGPRequest(w, r, node, apply)
			if err != nil {
				agentError(w, 400, err.Error())
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
			if apply {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), 150*time.Second)
			}
			defer cancel()
			if apply {
				if !nodeOperationLock.TryLock() {
					agentError(w, 409, "node_operation_in_progress")
					return
				}
				defer nodeOperationLock.Unlock()
			}
			current, err := h.runNodeBGP(ctx, "bgp-get", node, "", nil)
			if err != nil {
				agentError(w, 503, "bgp_configuration_unavailable")
				return
			}
			if validateNodeBGP(node, current.Config) != nil || !nodeRevision.MatchString(current.Revision) {
				agentError(w, 503, "bgp_configuration_unavailable")
				return
			}
			if current.Revision != body.ExpectedRevision {
				agentError(w, 409, "bgp_revision_changed_refresh")
				return
			}
			if err := authorizeExternalPeers(body.Config.ExternalPeers, current.ExternalPolicy); err != nil {
				agentError(w, 400, "external_peer_not_enrolled")
				return
			}
			payload, _ := json.Marshal(struct {
				ExpectedRevision string        `json:"expected_revision"`
				Config           nodeBGPConfig `json:"config"`
			}{body.ExpectedRevision, body.Config})
			if !apply {
				out, err := h.runNodeBGP(ctx, "bgp-validate", node, "", payload)
				if err != nil || !out.Valid || out.Revision != body.ExpectedRevision || !sameNodeBGP(out.Config, body.Config) {
					agentError(w, 409, "bgp_validation_failed")
					return
				}
				writeJSON(w, 200, out)
				return
			}
			if os.MkdirAll(h.NodeAuditDirectory, 0700) != nil {
				agentError(w, 503, "node_audit_unavailable")
				return
			}
			receipt, err := reserveNodeReceipt(h.NodeAuditDirectory, body.RequestID)
			if err != nil {
				agentError(w, 409, "operation_id_used_or_audit_unavailable")
				return
			}
			defer receipt.Close()
			record := func(stage string) error {
				if err := json.NewEncoder(receipt).Encode(map[string]any{"time": time.Now().UTC(), "actor": actor, "node": node, "action": "bgp-apply", "request_id": body.RequestID, "expected_revision": body.ExpectedRevision, "stage": stage}); err != nil {
					return err
				}
				return receipt.Sync()
			}
			if record("intent") != nil {
				agentError(w, 503, "node_audit_unavailable")
				return
			}
			out, err := h.runNodeBGP(ctx, "bgp-apply", node, body.RequestID, payload)
			if err != nil || out.Operation == nil || out.Operation.RequestID != body.RequestID || out.Operation.Action != "bgp-apply" {
				_ = record("uncertain")
				agentError(w, 502, "operation_uncertain_refresh_do_not_retry")
				return
			}
			confirmed := out.Operation.Confirmed && out.Operation.Status == "confirmed" && out.BGP != nil && nodeRevision.MatchString(out.BGP.Revision) && validateNodeBGP(node, out.BGP.Config) == nil && sameNodeBGP(out.BGP.Config, body.Config) && out.Operation.Rollback == ""
			rolledBack := !out.Operation.Confirmed && out.Operation.Status == "rolled_back" && out.BGP != nil && out.BGP.Revision == current.Revision && sameNodeBGP(out.BGP.Config, current.Config)
			if !confirmed && !rolledBack {
				_ = record("uncertain")
				agentError(w, 502, "operation_uncertain_refresh_do_not_retry")
				return
			}
			if record(out.Operation.Status) != nil {
				agentError(w, 502, "operation_audit_incomplete_refresh_do_not_retry")
				return
			}
			writeJSON(w, 200, out)
		}))
	}
}

func strictNodeJSON(d *json.Decoder, depth int) error {
	if depth > 8 {
		return errors.New("JSON nesting limit")
	}
	t, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			s, ok := key.(string)
			if err != nil || !ok || s != strings.ToLower(s) || seen[s] {
				return errors.New("duplicate or noncanonical JSON field")
			}
			seen[s] = true
			if err = strictNodeJSON(d, depth+1); err != nil {
				return err
			}
		}
		_, err = d.Token()
		return err
	case '[':
		for d.More() {
			if err = strictNodeJSON(d, depth+1); err != nil {
				return err
			}
		}
		_, err = d.Token()
		return err
	default:
		return errors.New("invalid JSON delimiter")
	}
}

func sameNodeBGP(a, b nodeBGPConfig) bool {
	a.Peers = append([]nodeBGPPeer(nil), a.Peers...)
	b.Peers = append([]nodeBGPPeer(nil), b.Peers...)
	a.Announcements = append([]nodeAnnouncement(nil), a.Announcements...)
	b.Announcements = append([]nodeAnnouncement(nil), b.Announcements...)
	a.ExternalPeers = append([]nodeExternalPeer(nil), a.ExternalPeers...)
	b.ExternalPeers = append([]nodeExternalPeer(nil), b.ExternalPeers...)
	for _, c := range []*nodeBGPConfig{&a, &b} {
		sort.Slice(c.ExternalPeers, func(i, j int) bool { return c.ExternalPeers[i].ID < c.ExternalPeers[j].ID })
		sort.Slice(c.Peers, func(i, j int) bool { return c.Peers[i].Address < c.Peers[j].Address })
		sort.Slice(c.Announcements, func(i, j int) bool {
			if c.Announcements[i].Role == c.Announcements[j].Role {
				return c.Announcements[i].Family < c.Announcements[j].Family
			}
			return c.Announcements[i].Role < c.Announcements[j].Role
		})
	}
	return reflect.DeepEqual(a, b)
}

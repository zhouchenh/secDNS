package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

// Node management is opt-in, local inventory only, and deliberately human-only.
// The operator configures executable paths; HTTP requests never select hosts or commands.
type nodeSnapshot struct {
	Schema     int       `json:"schema"`
	Node       string    `json:"node"`
	ObservedAt time.Time `json:"observed_at"`
	Reachable  bool      `json:"reachable"`
	Stale      bool      `json:"stale"`
	Errors     []string  `json:"errors,omitempty"`
	Daemon     struct {
		Active bool `json:"active"`
		PID    int  `json:"pid"`
	} `json:"daemon"`
	Maintenance struct {
		Withdraw bool `json:"withdraw"`
	} `json:"maintenance"`
	Profiles []struct {
		Role               string   `json:"role"`
		Family             int      `json:"family"`
		Healthy            *bool    `json:"healthy"`
		LocalHealthy       *bool    `json:"local_healthy"`
		UpstreamHealthy    *bool    `json:"upstream_healthy"`
		UpstreamAgeSeconds *float64 `json:"upstream_age_seconds"`
		Reason             string   `json:"reason"`
		Enabled            *bool    `json:"enabled"`
		Advertised         bool     `json:"advertised"`
		Prefix             string   `json:"prefix"`
	} `json:"profiles"`
	Peers []struct {
		Address  string   `json:"address"`
		Family   int      `json:"family"`
		State    string   `json:"state"`
		Prefixes []string `json:"prefixes,omitempty"`
	} `json:"peers"`
	HeartbeatAgeSeconds *float64 `json:"heartbeat_age_seconds,omitempty"`
	Operation           *struct {
		RequestID string `json:"request_id"`
		Action    string `json:"action"`
		Confirmed bool   `json:"confirmed"`
		Status    string `json:"status"`
	} `json:"operation,omitempty"`
}

var nodeIDs = []string{"amd103", "intel108", "cix106"}
var nodeRequestID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var nodeOperationLock sync.Mutex

func knownNode(id string) bool {
	for _, n := range nodeIDs {
		if n == id {
			return true
		}
	}
	return false
}
func (h *HTTPAdminServer) nodesEnabled() bool {
	return !h.FollowerStatusOnly && h.AgentAuthConfigured && filepath.IsAbs(h.NodeAdapterExecutable) && filepath.IsAbs(h.NodeAdapterScript) && filepath.IsAbs(h.NodeAuditDirectory)
}

type limitedNodeOutput struct{ bytes.Buffer }

func (b *limitedNodeOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 65536 {
		return 0, errors.New("adapter output limit")
	}
	return b.Buffer.Write(p)
}
func (h *HTTPAdminServer) runNode(ctx context.Context, action, node, id string) (nodeSnapshot, error) {
	var result nodeSnapshot
	if !h.nodesEnabled() || !knownNode(node) {
		return result, errors.New("node management unavailable")
	}
	args := []string{h.NodeAdapterScript, action, node}
	if action != "status" {
		args = append(args, id)
	}
	if h.nodeRunner != nil {
		return h.nodeRunner(ctx, action, node, id)
	}
	cmd := exec.CommandContext(ctx, h.NodeAdapterExecutable, args...)
	cmd.WaitDelay = 2 * time.Second
	var output limitedNodeOutput
	cmd.Stdout = &output
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return result, errors.New("node adapter unavailable")
	}
	if json.Unmarshal(output.Bytes(), &result) != nil || result.Schema != 1 || result.Node != node || result.ObservedAt.IsZero() {
		return nodeSnapshot{}, errors.New("invalid node observation")
	}
	if time.Since(result.ObservedAt) > 45*time.Second || time.Until(result.ObservedAt) > 5*time.Second {
		result.Stale = true
	}
	return result, nil
}
func (h *HTTPAdminServer) nodeRoutes(mux *http.ServeMux, base string) {
	h.nodeBGPRoutes(mux, base)
	h.nodeHealthRoutes(mux, base)
	if !h.nodesEnabled() {
		return
	}
	mux.HandleFunc("GET "+base+"/nodes/{node}", h.withNodeHuman(false, func(w http.ResponseWriter, r *http.Request, _ string) {
		node := r.PathValue("node")
		if !knownNode(node) {
			agentError(w, 404, "unknown_node")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		result, err := h.runNode(ctx, "status", node, "")
		if err != nil {
			agentError(w, 503, "node_observation_unavailable")
			return
		}
		writeJSON(w, 200, result)
	}))
	mux.HandleFunc("POST "+base+"/nodes/{node}/maintenance", h.withNodeHuman(true, func(w http.ResponseWriter, r *http.Request, actor string) {
		node := r.PathValue("node")
		if !knownNode(node) {
			agentError(w, 404, "unknown_node")
			return
		}
		body, err := humanBody(w, r, "action", "request_id", "expected_withdraw", "confirm_node")
		if err != nil || (body["action"] != "drain" && body["action"] != "resume") || !nodeRequestID.MatchString(body["request_id"]) || body["confirm_node"] != node || (body["expected_withdraw"] != "true" && body["expected_withdraw"] != "false") {
			agentError(w, 400, "invalid_node_operation")
			return
		}
		if !nodeOperationLock.TryLock() {
			agentError(w, 409, "node_operation_in_progress")
			return
		}
		defer nodeOperationLock.Unlock()
		// Finish bounded reconciliation even if the browser disconnects. Never retry a mutation.
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		before, err := h.runNode(ctx, "status", node, "")
		if err != nil || !before.Reachable || before.Stale {
			agentError(w, 409, "fresh_node_observation_required")
			return
		}
		expected := body["expected_withdraw"] == "true"
		if before.Maintenance.Withdraw != expected {
			agentError(w, 409, "node_state_changed_refresh")
			return
		}
		// Never drain the last healthy provider of a prefix this node announces: every such
		// prefix needs another fresh, reachable, announcing node whose check for it passes.
		// Checked here, before any receipt or adapter mutation; the console dialog shows the same.
		if body["action"] == "drain" && len(h.lastProviderPrefixes(ctx, node, before)) > 0 {
			agentError(w, 409, "last_healthy_provider")
			return
		}
		if err = os.MkdirAll(h.NodeAuditDirectory, 0700); err != nil {
			agentError(w, 503, "node_audit_unavailable")
			return
		}
		// O_EXCL is a durable replay barrier, including after server restart.
		file, err := reserveNodeReceipt(h.NodeAuditDirectory, body["request_id"])
		if err != nil {
			agentError(w, 409, "operation_id_used_or_audit_unavailable")
			return
		}
		defer file.Close()
		record := func(stage string) error {
			if e := json.NewEncoder(file).Encode(map[string]any{"time": time.Now().UTC(), "actor": actor, "node": node, "action": body["action"], "request_id": body["request_id"], "stage": stage}); e != nil {
				return e
			}
			return file.Sync()
		}
		if record("intent") != nil {
			agentError(w, 503, "node_audit_unavailable")
			return
		}
		result, err := h.runNode(ctx, body["action"], node, body["request_id"])
		if err != nil {
			_ = record("uncertain")
			agentError(w, 502, "operation_uncertain_refresh_do_not_retry")
			return
		}
		valid := result.Operation != nil && result.Operation.RequestID == body["request_id"] && result.Operation.Action == body["action"]
		if !valid {
			_ = record("uncertain")
			agentError(w, 502, "operation_uncertain_refresh_do_not_retry")
			return
		}
		if record(result.Operation.Status) != nil {
			agentError(w, 502, "operation_audit_incomplete_refresh_do_not_retry")
			return
		}
		writeJSON(w, 200, result)
	}))
}

// lastProviderPrefixes lists the prefixes node currently announces that no other node serves:
// another node counts only with a fresh reachable observation, an active DNS process, no
// maintenance withdrawal, and an enabled, healthy, advertised profile for the same prefix. An
// unavailable or stale observation counts as not serving (fail closed).
func (h *HTTPAdminServer) lastProviderPrefixes(ctx context.Context, node string, target nodeSnapshot) []string {
	var prefixes []string
	seen := map[string]bool{}
	for _, p := range target.Profiles {
		if p.Advertised && (p.Enabled == nil || *p.Enabled) && p.Prefix != "" && !seen[p.Prefix] {
			seen[p.Prefix] = true
			prefixes = append(prefixes, p.Prefix)
		}
	}
	if len(prefixes) == 0 {
		return nil
	}
	others := make([]nodeSnapshot, len(nodeIDs))
	ok := make([]bool, len(nodeIDs))
	var wg sync.WaitGroup
	for i, other := range nodeIDs {
		if other == node {
			continue
		}
		wg.Add(1)
		go func(i int, other string) {
			defer wg.Done()
			s, err := h.runNode(ctx, "status", other, "")
			others[i], ok[i] = s, err == nil
		}(i, other)
	}
	wg.Wait()
	var last []string
	for _, prefix := range prefixes {
		served := false
		for i, s := range others {
			if !ok[i] || !s.Reachable || s.Stale || !s.Daemon.Active || s.Maintenance.Withdraw {
				continue
			}
			for _, p := range s.Profiles {
				if p.Prefix == prefix && (p.Enabled == nil || *p.Enabled) && p.Healthy != nil && *p.Healthy && p.Advertised {
					served = true
				}
			}
		}
		if !served {
			last = append(last, prefix)
		}
	}
	return last
}

// Receipt paths are derived from a fixed-length digest, never from a request
// string. Match legacy UUID receipt names without turning them into file paths:
// their existence still blocks replay after upgrading from the original format.
func reserveNodeReceipt(directory, requestID string) (*os.File, error) {
	if !nodeRequestID.MatchString(requestID) {
		return nil, errors.New("invalid operation identifier")
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if entry.Name() == requestID+".jsonl" {
			return nil, os.ErrExist
		}
	}
	digest := sha256.Sum256([]byte(requestID))
	basename := "operation-" + hex.EncodeToString(digest[:]) + ".jsonl"
	return os.OpenFile(filepath.Join(directory, basename), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
}

func (h *HTTPAdminServer) withNodeHuman(mutation bool, next func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.agent == nil || !h.browserRequest(r, mutation) || len(r.Header.Values("Authorization")) != 0 {
			agentError(w, 403, "human_authentication_required")
			return
		}
		token, _ := cookieValue(r)
		session, err := h.agent.sessions.Authenticate(token, r.Header.Get("X-SecDNS-CSRF"), mutation, mutation, h.agent.now())
		if err != nil || session.Actor.Kind() != "human" {
			agentError(w, 403, "human_authentication_required")
			return
		}
		_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(160 * time.Second))
		next(w, r, session.Actor.ID())
	}
}

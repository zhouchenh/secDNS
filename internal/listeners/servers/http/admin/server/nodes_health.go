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
	"time"
)

type nodeHealthConfig struct {
	IntervalSeconds   int `json:"interval_seconds"`
	ProbeTimeoutMS    int `json:"probe_timeout_ms"`
	FailureThreshold  int `json:"failure_threshold"`
	RecoveryThreshold int `json:"recovery_threshold"`
}
type nodeHealthDerived struct {
	StaleSeconds int `json:"stale_seconds"`
}
type nodeHealthView struct {
	Schema   int               `json:"schema"`
	Node     string            `json:"node"`
	Revision string            `json:"revision"`
	Config   nodeHealthConfig  `json:"config"`
	Derived  nodeHealthDerived `json:"derived"`
}
type nodeHealthResult struct {
	Schema         int               `json:"schema"`
	Node           string            `json:"node"`
	Revision       string            `json:"revision,omitempty"`
	Config         nodeHealthConfig  `json:"config"`
	Derived        nodeHealthDerived `json:"derived"`
	Valid          bool              `json:"valid,omitempty"`
	HealthSettings *nodeHealthView   `json:"health_settings,omitempty"`
	Operation      *nodeBGPOperation `json:"operation,omitempty"`
}
type nodeHealthRequest struct {
	ExpectedRevision string           `json:"expected_revision"`
	Config           nodeHealthConfig `json:"config"`
	RequestID        string           `json:"request_id,omitempty"`
	ConfirmNode      string           `json:"confirm_node,omitempty"`
}

func validateNodeHealth(_ string, c nodeHealthConfig) error {
	if c.IntervalSeconds < 3 || c.IntervalSeconds > 15 || c.ProbeTimeoutMS < 500 || c.ProbeTimeoutMS > 2500 || c.FailureThreshold < 2 || c.FailureThreshold > 3 || c.RecoveryThreshold < 2 || c.RecoveryThreshold > 5 || 2*c.ProbeTimeoutMS+500 > 1000*c.IntervalSeconds {
		return errors.New("invalid_health_config")
	}
	return nil
}
func healthDerived(c nodeHealthConfig) nodeHealthDerived {
	return nodeHealthDerived{2*c.IntervalSeconds + (2*c.ProbeTimeoutMS+999)/1000 + 1}
}
func sameNodeHealth(a, b nodeHealthConfig) bool { return a == b }
func (h *HTTPAdminServer) runNodeHealth(ctx context.Context, action, node, id string, body []byte) (nodeHealthResult, error) {
	var out nodeHealthResult
	if !h.nodesEnabled() || !knownNode(node) {
		return out, errors.New("node management unavailable")
	}
	if h.nodeHealthRunner != nil {
		return h.nodeHealthRunner(ctx, action, node, id, body)
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
		return out, errors.New("health_operation_unconfirmed")
	}
	if json.Unmarshal(output.Bytes(), &out) != nil || out.Schema != 1 || out.Node != node {
		return out, errors.New("invalid_health_observation")
	}
	return out, nil
}
func readNodeHealthRequest(w http.ResponseWriter, r *http.Request, node string, apply bool) (nodeHealthRequest, error) {
	var body nodeHealthRequest
	r.Body = http.MaxBytesReader(w, r.Body, 16384)
	defer r.Body.Close()
	raw, readErr := io.ReadAll(r.Body)
	if readErr != nil || strictNodeJSON(json.NewDecoder(bytes.NewReader(raw)), 0) != nil {
		return body, errors.New("invalid_health_request")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&body) != nil || d.Decode(new(any)) != io.EOF {
		return body, errors.New("invalid_health_request")
	}
	if !nodeRevision.MatchString(body.ExpectedRevision) || (apply && !nodeRequestID.MatchString(body.RequestID)) || (!apply && body.RequestID != "") {
		return body, errors.New("invalid_health_revision_or_request")
	}
	if (apply && body.ConfirmNode != node) || (!apply && body.ConfirmNode != "") {
		return body, errors.New("invalid_health_confirmation")
	}
	return body, validateNodeHealth(node, body.Config)
}
func (h *HTTPAdminServer) nodeHealthRoutes(mux *http.ServeMux, base string) {
	if !h.nodesEnabled() {
		return
	}
	mux.HandleFunc("GET "+base+"/nodes/{node}/health-settings", h.withNodeHuman(false, func(w http.ResponseWriter, r *http.Request, _ string) {
		node := r.PathValue("node")
		if !knownNode(node) {
			agentError(w, 404, "unknown_node")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		out, err := h.runNodeHealth(ctx, "health-get", node, "", nil)
		if err != nil || validateNodeHealth(node, out.Config) != nil || !nodeRevision.MatchString(out.Revision) || out.Derived != healthDerived(out.Config) {
			agentError(w, 503, "health_configuration_unavailable")
			return
		}
		writeJSON(w, 200, out)
	}))
	for _, mode := range []string{"preview", "apply"} {
		mux.HandleFunc("POST "+base+"/nodes/{node}/health-settings/"+mode, h.withNodeHuman(true, func(w http.ResponseWriter, r *http.Request, actor string) {
			node := r.PathValue("node")
			if !knownNode(node) {
				agentError(w, 404, "unknown_node")
				return
			}
			apply := mode == "apply"
			body, err := readNodeHealthRequest(w, r, node, apply)
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
			current, err := h.runNodeHealth(ctx, "health-get", node, "", nil)
			if err != nil {
				agentError(w, 503, "health_configuration_unavailable")
				return
			}
			if validateNodeHealth(node, current.Config) != nil || !nodeRevision.MatchString(current.Revision) || current.Derived != healthDerived(current.Config) {
				agentError(w, 503, "health_configuration_unavailable")
				return
			}
			if current.Revision != body.ExpectedRevision {
				agentError(w, 409, "health_revision_changed_refresh")
				return
			}
			payload, _ := json.Marshal(struct {
				ExpectedRevision string           `json:"expected_revision"`
				Config           nodeHealthConfig `json:"config"`
			}{body.ExpectedRevision, body.Config})
			if !apply {
				out, err := h.runNodeHealth(ctx, "health-validate", node, "", payload)
				if err != nil || !out.Valid || out.Revision != body.ExpectedRevision || !sameNodeHealth(out.Config, body.Config) || out.Derived != healthDerived(body.Config) {
					agentError(w, 409, "health_validation_failed")
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
				if err := json.NewEncoder(receipt).Encode(map[string]any{"time": time.Now().UTC(), "actor": actor, "node": node, "action": "health-apply", "request_id": body.RequestID, "expected_revision": body.ExpectedRevision, "stage": stage}); err != nil {
					return err
				}
				return receipt.Sync()
			}
			if record("intent") != nil {
				agentError(w, 503, "node_audit_unavailable")
				return
			}
			out, err := h.runNodeHealth(ctx, "health-apply", node, body.RequestID, payload)
			if err != nil || out.Operation == nil || out.Operation.RequestID != body.RequestID || out.Operation.Action != "health-apply" {
				_ = record("uncertain")
				agentError(w, 502, "operation_uncertain_refresh_do_not_retry")
				return
			}
			confirmed := out.Operation.Confirmed && out.Operation.Status == "confirmed" && out.HealthSettings != nil && nodeRevision.MatchString(out.HealthSettings.Revision) && validateNodeHealth(node, out.HealthSettings.Config) == nil && sameNodeHealth(out.HealthSettings.Config, body.Config) && out.HealthSettings.Derived == healthDerived(body.Config) && out.HealthSettings.Schema == 1 && out.HealthSettings.Node == node && out.Operation.Rollback == ""
			rolledBack := !out.Operation.Confirmed && out.Operation.Status == "rolled_back" && out.HealthSettings != nil && out.HealthSettings.Revision == current.Revision && sameNodeHealth(out.HealthSettings.Config, current.Config) && out.HealthSettings.Derived == healthDerived(current.Config) && out.HealthSettings.Schema == 1 && out.HealthSettings.Node == node
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

package server

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"time"

	"github.com/zhouchenh/secDNS/internal/sourcepolicy"
)

const (
	maxSourcePolicyExplainBodyBytes = 4 << 10
	sourcePolicyExplainSchema       = "secdns.source-policy-explain.v1"
)

const (
	explainInvalidRequest = "source_policy_explain_invalid_request"
	explainTooLarge       = "source_policy_explain_too_large"
	explainUnknownRole    = "source_policy_explain_unknown_role"
	explainUnavailable    = "source_policy_explain_unavailable"
)

type sourcePolicyExplainRequest struct {
	ListenerRole string `json:"listener_role"`
	ClientIP     string `json:"client_ip"`
	At           string `json:"at"`
}

// UnmarshalJSON keeps this new endpoint strict without changing the legacy
// records API's compatibility behavior. Field names are exact, duplicates and
// unknown fields are rejected, and the handler separately rejects trailing JSON.
func (request *sourcePolicyExplainRequest) UnmarshalJSON(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return errors.New("source-policy explain request must be an object")
	}
	seen := make(map[string]struct{}, 3)
	for decoder.More() {
		token, err = decoder.Token()
		if err != nil {
			return err
		}
		name, ok := token.(string)
		if !ok {
			return errors.New("invalid source-policy explain field")
		}
		if _, exists := seen[name]; exists {
			return errors.New("duplicate source-policy explain field")
		}
		seen[name] = struct{}{}
		var target *string
		switch name {
		case "listener_role":
			target = &request.ListenerRole
		case "client_ip":
			target = &request.ClientIP
		case "at":
			target = &request.At
		default:
			return errors.New("unknown source-policy explain field")
		}
		if err := decoder.Decode(target); err != nil {
			return err
		}
	}
	if _, err := decoder.Token(); err != nil {
		return err
	}
	return nil
}

type sourcePolicyExplainResponse struct {
	Schema            string `json:"schema"`
	Evaluation        string `json:"evaluation"`
	PolicyFingerprint string `json:"policy_fingerprint"`
	ListenerRole      string `json:"listener_role"`
	ClientIP          string `json:"client_ip"`
	EvaluatedAt       string `json:"evaluated_at"`
	Resolver          string `json:"resolver"`
	SourceSet         string `json:"source_set,omitempty"`
	RuleIndex         int    `json:"rule_index"`
	Reason            string `json:"reason"`
}

// SourcePolicyExplainEnabled and BindSourcePolicySelector form a narrow,
// optional configuration seam. The admin listener receives only the immutable
// selector, never resolver instances, caches, or transport state.
func (h *HTTPAdminServer) SourcePolicyExplainEnabled() bool {
	return h != nil && h.SourcePolicyExplain
}

func (h *HTTPAdminServer) BindSourcePolicySelector(selector sourcepolicy.Explainer) bool {
	if h == nil || !h.SourcePolicyExplain || selector == nil || h.sourcePolicySelector != nil {
		return false
	}
	h.sourcePolicySelector = selector
	return true
}

func (h *HTTPAdminServer) sourcePolicyExplainRoutes(mux *http.ServeMux, base string) {
	mux.HandleFunc("POST "+base+"/source-policy/explain", h.auth(h.handleSourcePolicyExplain))
}

func (h *HTTPAdminServer) handleSourcePolicyExplain(w http.ResponseWriter, r *http.Request) {
	selector := h.sourcePolicySelector
	if selector == nil {
		writeExplainError(w, http.StatusServiceUnavailable, explainUnavailable)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxSourcePolicyExplainBodyBytes)
	decoder := json.NewDecoder(r.Body)
	var request sourcePolicyExplainRequest
	if err := decoder.Decode(&request); err != nil {
		writeExplainDecodeError(w, err)
		return
	}
	if err := decoder.Decode(new(interface{})); err != io.EOF {
		writeExplainDecodeError(w, err)
		return
	}
	peer, err := netip.ParseAddr(request.ClientIP)
	if err != nil || !peer.IsValid() || peer.Zone() != "" {
		writeExplainError(w, http.StatusBadRequest, explainInvalidRequest)
		return
	}
	peer = peer.Unmap()
	at, ok := parseExplainTime(request.At)
	if request.ListenerRole == "" || !ok {
		writeExplainError(w, http.StatusBadRequest, explainInvalidRequest)
		return
	}
	decision, err := selector.Select(request.ListenerRole, peer, at)
	if err != nil {
		if errors.Is(err, sourcepolicy.ErrUnknownRole) {
			writeExplainError(w, http.StatusBadRequest, explainUnknownRole)
		} else {
			writeExplainError(w, http.StatusServiceUnavailable, explainUnavailable)
		}
		return
	}
	reason := "matched_rule"
	if decision.UsedDefault {
		reason = "explicit_default"
	}
	writeJSON(w, http.StatusOK, sourcePolicyExplainResponse{
		Schema:            sourcePolicyExplainSchema,
		Evaluation:        "diagnostic_preview",
		PolicyFingerprint: hex.EncodeToString(decision.CachePartition.PolicyFingerprint[:]),
		ListenerRole:      request.ListenerRole,
		ClientIP:          peer.String(),
		EvaluatedAt:       at.Format(time.RFC3339Nano),
		Resolver:          decision.ResolverPolicyID,
		SourceSet:         decision.SourceSetID,
		RuleIndex:         decision.RuleIndex,
		Reason:            reason,
	})
}

func parseExplainTime(value string) (time.Time, bool) {
	if value == "" {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, false
	}
	parsed = parsed.UTC().Round(0)
	if parsed.IsZero() || parsed.Year() < 1 || parsed.Year() > 9999 {
		return time.Time{}, false
	}
	return parsed, true
}

func writeExplainDecodeError(w http.ResponseWriter, err error) {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		writeExplainError(w, http.StatusRequestEntityTooLarge, explainTooLarge)
		return
	}
	writeExplainError(w, http.StatusBadRequest, explainInvalidRequest)
}

func writeExplainError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}

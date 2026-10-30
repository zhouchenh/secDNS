package server

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/zhouchenh/secDNS/internal/recordset"
	"github.com/zhouchenh/secDNS/internal/recordstore"
	"io"
	"net/http"
	"net/textproto"
	"strconv"
	"strings"
	"time"
)

const operatorProvenanceProfileHeader = "SecDNS-Operator-Provenance-Profile"
const operatorProvenanceSourceHeader = "SecDNS-Operator-Provenance-Source-SHA256"
const operatorProvenanceContentHeader = "SecDNS-Operator-Provenance-Content-SHA256"

func setOperatorSuppliedProvenanceHeaders(w http.ResponseWriter, provenance recordset.OperatorSuppliedProvenance, ok bool) {
	if !ok {
		return
	}
	w.Header().Set(operatorProvenanceProfileHeader, provenance.Profile())
	w.Header().Set(operatorProvenanceSourceHeader, provenance.SourceSHA256())
	w.Header().Set(operatorProvenanceContentHeader, provenance.ContentSHA256())
}

func snapshotError(w http.ResponseWriter, err error) {
	status := http.StatusServiceUnavailable
	code := "snapshot_unavailable"
	switch {
	case errors.Is(err, recordstore.ErrVersionedInput), errors.Is(err, recordset.ErrInvalid), errors.Is(err, recordset.ErrLimit):
		status = http.StatusBadRequest
		code = "invalid_snapshot_request"
	case errors.Is(err, recordstore.ErrIdentity):
		status = http.StatusConflict
		code = "identity_conflict"
	case errors.Is(err, recordstore.ErrRRsetSchemaRequired):
		status = http.StatusConflict
		code = "rrset_schema_required"
	case errors.Is(err, recordstore.ErrRevisionConflict):
		status = http.StatusConflict
		code = "revision_conflict"
	case errors.Is(err, recordstore.ErrOperationConflict):
		status = http.StatusConflict
		code = "operation_conflict"
	case errors.Is(err, recordstore.ErrReceiptCapacity):
		status = http.StatusConflict
		code = "receipt_capacity"
	case errors.Is(err, recordstore.ErrRevisionOverflow):
		status = http.StatusConflict
		code = "revision_exhausted"
	case errors.Is(err, recordstore.ErrOperatorProvenanceUnavailable):
		status = http.StatusConflict
		code = "operator_provenance_unavailable"
	}
	writeJSON(w, status, map[string]string{"error": code})
}

func snapshotResponseETag(view recordstore.View, provenance recordset.OperatorSuppliedProvenance, hasProvenance bool) (string, error) {
	envelope, err := view.MarshalJSON()
	if err != nil {
		return "", err
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte("secdns.snapshot-http-representation.v1\x00"))
	_, _ = digest.Write(envelope)
	_, _ = digest.Write([]byte{'\n'}) // writeJSON adds exactly one trailing newline.
	if hasProvenance {
		for _, value := range []string{provenance.Profile(), provenance.SourceSHA256(), provenance.ContentSHA256()} {
			_, _ = digest.Write([]byte{0})
			_, _ = digest.Write([]byte(value))
		}
	} else {
		_, _ = digest.Write([]byte("\x00no-operator-provenance"))
	}
	return `"secdns-exact-snapshot-v1-` + hex.EncodeToString(digest.Sum(nil)) + `"`, nil
}

// snapshotNotModified applies If-None-Match's weak comparison semantics to the
// strong tag emitted by this endpoint. Invalid field syntax is ignored as a
// failed precondition rather than partially matched.
func snapshotNotModified(values []string, current string) bool {
	if len(values) == 0 {
		return false
	}
	value := textproto.TrimString(strings.Join(values, ","))
	if value == "*" {
		return true
	}
	matched := false
	for value != "" {
		candidate, remain := scanSnapshotETag(value)
		if candidate == "" {
			return false
		}
		if strings.TrimPrefix(candidate, "W/") == strings.TrimPrefix(current, "W/") {
			matched = true
		}
		remain = textproto.TrimString(remain)
		if remain == "" {
			return matched
		}
		if remain[0] != ',' {
			return false
		}
		value = textproto.TrimString(remain[1:])
		if value == "" {
			return false
		}
	}
	return false
}

func scanSnapshotETag(value string) (tag, remain string) {
	value = textproto.TrimString(value)
	start := 0
	if strings.HasPrefix(value, "W/") {
		start = 2
	}
	if len(value[start:]) < 2 || value[start] != '"' {
		return "", ""
	}
	for index := start + 1; index < len(value); index++ {
		character := value[index]
		switch {
		case character == 0x21 || character >= 0x23 && character <= 0x7e || character >= 0x80:
		case character == '"':
			return value[:index+1], value[index+1:]
		default:
			return "", ""
		}
	}
	return "", ""
}

func (h *HTTPAdminServer) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	view, e := h.versioned.Acquire()
	if e != nil {
		snapshotError(w, e)
		return
	}
	provenance, hasProvenance := view.OperatorSuppliedProvenance()
	etag, e := snapshotResponseETag(view, provenance, hasProvenance)
	if e != nil {
		snapshotError(w, recordstore.ErrVersionedStorage)
		return
	}
	setOperatorSuppliedProvenanceHeaders(w, provenance, hasProvenance)
	w.Header().Set("ETag", etag)
	if h.versioned.SupportsRRsetMutations() {
		w.Header().Set("SecDNS-RRset-Mutations", "v1")
	}
	if snapshotNotModified(r.Header.Values("If-None-Match"), etag) {
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusNotModified)
		return
	}
	writeJSON(w, http.StatusOK, view)
}
func (h *HTTPAdminServer) handleReplace(w http.ResponseWriter, r *http.Request) {
	raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, recordset.MaxBytes))
	if e != nil {
		var size *http.MaxBytesError
		if errors.As(e, &size) {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "snapshot_too_large"})
		} else {
			snapshotError(w, recordstore.ErrVersionedInput)
		}
		return
	}
	request, e := recordset.ParseReplacement(raw)
	if e != nil {
		snapshotError(w, recordstore.ErrVersionedInput)
		return
	}
	expected := recordstore.Expected{RulesetID: request.RulesetID, LineageID: request.LineageID, Revision: request.Revision}
	provenance, hasProvenance := request.OperatorSuppliedProvenance()
	confirmed, stated := request.ConfirmRemovals()
	// set by a record gateway that moved the body field into a header for older authorities
	confirmed, stated, ok := confirmRemovalsValue(r, confirmed, stated)
	if !ok {
		snapshotError(w, recordstore.ErrVersionedInput)
		return
	}
	if code := h.removalConfirmationError(request, hasProvenance, confirmed, stated); code != "" {
		writeRemovalConfirmationError(w, code)
		return
	}
	var receipt recordstore.Receipt
	if hasProvenance {
		receipt, e = h.versioned.ReplaceWithOperatorSuppliedProvenance(expected, request.OperationID, request.Records, provenance)
	} else {
		receipt, e = h.versioned.Replace(expected, request.OperationID, request.Records)
	}
	if e != nil {
		snapshotError(w, e)
		return
	}
	provenance, hasProvenance = receipt.OperatorSuppliedProvenance()
	setOperatorSuppliedProvenanceHeaders(w, provenance, hasProvenance)
	writeJSON(w, http.StatusOK, map[string]string{"operation_id": receipt.OperationID, "revision": strconv.FormatUint(receipt.Revision, 10), "content_sha256": receipt.ContentSHA256, "committed_at": receipt.CommittedAt.UTC().Format(time.RFC3339Nano)})
}

// removalConfirmationError guards destructive replacements. An exact import (a replacement
// carrying operator-supplied provenance) that removes records from its expected base must
// state confirm_removals equal to the server's own count; any replacement that states
// confirm_removals must match it. The count is computed only while the current generation
// is the expected one: otherwise the store itself decides (revision conflict, or the
// idempotent replay of an already committed operation), so retries stay safe.
func (h *HTTPAdminServer) removalConfirmationError(request recordset.Replacement, exactImport bool, confirmed int, stated bool) string {
	if !exactImport && !stated {
		return ""
	}
	view, e := h.versioned.Acquire()
	if e != nil {
		// fail closed: a destructive request is never admitted without its check
		return "snapshot_unavailable"
	}
	return removalConfirmationCode(view.Metadata(), view.Records(), request, exactImport, confirmed, stated)
}

// writeRemovalConfirmationError maps a removal-confirmation refusal to its response: the
// confirmation codes are conflicts the operator resolves by reviewing again; an unavailable
// base (local store or the record authority behind the gateway) refuses before any change.
func writeRemovalConfirmationError(w http.ResponseWriter, code string) {
	status := http.StatusConflict
	switch code {
	case "snapshot_unavailable", "removal_check_unavailable":
		status = http.StatusServiceUnavailable
	case "invalid_snapshot_request":
		status = http.StatusBadRequest
	}
	writeJSON(w, status, map[string]string{"error": code})
}

// confirmRemovalsValue reads confirm_removals from the body, or else from the one
// SecDNS-Confirm-Removals header a record gateway sets for older authorities.
func confirmRemovalsValue(r *http.Request, confirmed int, stated bool) (int, bool, bool) {
	values := r.Header.Values(confirmRemovalsHeader)
	if stated || len(values) == 0 {
		return confirmed, stated, true
	}
	if len(values) != 1 {
		return 0, false, false
	}
	n, e := recordset.ParseConfirmRemovals(values[0])
	if e != nil {
		return 0, false, false
	}
	return n, true, true
}

// rrsetRemovalCode is the removal rule for one RRset deletion against a base generation: it
// removes one record when the key exists there. A stated count must match; requireCount (the
// record gateway) also refuses an unstated deletion of an existing record. A base other than
// the expected generation is left to the store's own check (revision conflict or replay).
func rrsetRemovalCode(base recordset.Metadata, baseRecords []recordset.Record, request recordset.RRsetMutation, requireCount bool) string {
	confirmed, stated := request.ConfirmRemovals()
	if request.Action != "delete" || request.Key == nil || !stated && !requireCount {
		return ""
	}
	if base.RulesetID != request.RulesetID || base.LineageID != request.LineageID || base.Revision != request.Revision {
		return ""
	}
	removed := 0
	for _, r := range baseRecords {
		if strings.TrimSuffix(strings.ToLower(r.Name), ".") == strings.TrimSuffix(strings.ToLower(request.Key.Name), ".") && strings.EqualFold(r.Type, request.Key.Type) {
			removed = 1
			break
		}
	}
	switch {
	case !stated && removed > 0:
		return "removal_confirmation_required"
	case stated && confirmed != removed:
		return "removal_confirmation_mismatch"
	}
	return ""
}

// confirmRemovalsHeader carries confirm_removals from the record gateway to the authority.
const confirmRemovalsHeader = "SecDNS-Confirm-Removals"

// removalConfirmationCode is the shared rule for a base generation (local store or the
// record authority behind the gateway): "" when the request may proceed.
func removalConfirmationCode(base recordset.Metadata, baseRecords []recordset.Record, request recordset.Replacement, exactImport bool, confirmed int, stated bool) string {
	if !exactImport && !stated {
		return ""
	}
	if base.RulesetID != request.RulesetID || base.LineageID != request.LineageID || base.Revision != request.Revision {
		return ""
	}
	removed := countRemovedRecords(baseRecords, request.Records)
	switch {
	case !stated && removed > 0:
		return "removal_confirmation_required"
	case stated && confirmed != removed:
		return "removal_confirmation_mismatch"
	}
	return ""
}

func countRemovedRecords(before, after []recordset.Record) int {
	key := func(r recordset.Record) string {
		return strings.TrimSuffix(strings.ToLower(r.Name), ".") + "/" + strings.ToUpper(r.Type)
	}
	kept := make(map[string]struct{}, len(after))
	for _, r := range after {
		kept[key(r)] = struct{}{}
	}
	removed := 0
	seen := make(map[string]struct{}, len(before))
	for _, r := range before {
		k := key(r)
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		if _, ok := kept[k]; !ok {
			removed++
		}
	}
	return removed
}

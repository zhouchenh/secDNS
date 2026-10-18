package server

import (
	"errors"
	"github.com/zhouchenh/secDNS/internal/recordset"
	"github.com/zhouchenh/secDNS/internal/recordstore"
	"io"
	"net/http"
	"strconv"
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
func (h *HTTPAdminServer) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	view, e := h.versioned.Acquire()
	if e != nil {
		snapshotError(w, e)
		return
	}
	provenance, hasProvenance := view.OperatorSuppliedProvenance()
	setOperatorSuppliedProvenanceHeaders(w, provenance, hasProvenance)
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

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
	}
	writeJSON(w, status, map[string]string{"error": code})
}
func (h *HTTPAdminServer) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	view, e := h.versioned.Acquire()
	if e != nil {
		snapshotError(w, e)
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
	receipt, e := h.versioned.Replace(recordstore.Expected{RulesetID: request.RulesetID, LineageID: request.LineageID, Revision: request.Revision}, request.OperationID, request.Records)
	if e != nil {
		snapshotError(w, e)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"operation_id": receipt.OperationID, "revision": strconv.FormatUint(receipt.Revision, 10), "content_sha256": receipt.ContentSHA256, "committed_at": receipt.CommittedAt.UTC().Format(time.RFC3339Nano)})
}

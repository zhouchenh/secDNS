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

func (h *HTTPAdminServer) handleRRsetMutation(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, recordset.MaxBytes))
	if err != nil {
		var size *http.MaxBytesError
		if errors.As(err, &size) {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "snapshot_too_large"})
		} else {
			snapshotError(w, recordstore.ErrVersionedInput)
		}
		return
	}
	request, err := recordset.ParseRRsetMutation(raw)
	if err != nil {
		snapshotError(w, recordstore.ErrVersionedInput)
		return
	}
	receipt, err := h.versioned.MutateRRset(request)
	if err != nil {
		snapshotError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"operation_id": receipt.OperationID, "revision": strconv.FormatUint(receipt.Revision, 10), "content_sha256": receipt.ContentSHA256, "committed_at": receipt.CommittedAt.UTC().Format(time.RFC3339Nano)})
}

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
	// A deletion may state the number of records it removes (0 or 1), in the body or in the
	// header a record gateway sets; a stated count must match this store's expected base.
	if confirmed, stated := request.ConfirmRemovals(); !stated && len(r.Header.Values(confirmRemovalsHeader)) > 0 {
		if request.Action != "delete" {
			snapshotError(w, recordstore.ErrVersionedInput)
			return
		}
		n, s, ok := confirmRemovalsValue(r, confirmed, stated)
		if !ok || n > 1 {
			snapshotError(w, recordstore.ErrVersionedInput)
			return
		}
		request = request.WithConfirmRemovals(n, s)
	}
	if _, stated := request.ConfirmRemovals(); stated {
		view, e := h.versioned.Acquire()
		if e != nil {
			writeRemovalConfirmationError(w, "snapshot_unavailable")
			return
		}
		if code := rrsetRemovalCode(view.Metadata(), view.Records(), request, false); code != "" {
			writeRemovalConfirmationError(w, code)
			return
		}
	}
	receipt, err := h.versioned.MutateRRset(request)
	if err != nil {
		snapshotError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"operation_id": receipt.OperationID, "revision": strconv.FormatUint(receipt.Revision, 10), "content_sha256": receipt.ContentSHA256, "committed_at": receipt.CommittedAt.UTC().Format(time.RFC3339Nano)})
}

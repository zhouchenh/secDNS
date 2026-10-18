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

package snapshotfollower

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/zhouchenh/secDNS/internal/recordset"
	"github.com/zhouchenh/secDNS/internal/recordstore"
)

const (
	errorAuth      = "authentication"
	errorCanceled  = "canceled"
	errorProtocol  = "protocol"
	errorSnapshot  = "snapshot"
	errorStorage   = "storage"
	errorTransport = "transport"
)

func strongETag(value string) bool {
	if len(value) < 2 || len(value) > 256 || value[0] != '"' || value[len(value)-1] != '"' || strings.HasPrefix(value, "W/") {
		return false
	}
	for _, character := range []byte(value[1 : len(value)-1]) {
		if character < 0x21 || character == 0x22 || character == 0x5c || character == 0x7f {
			return false
		}
	}
	return true
}

func (w *Worker) request(ctx context.Context, endpoint string) (*http.Request, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+w.config.Token)
	request.Header.Set("Accept-Encoding", "identity")
	return request, nil
}

// fetch returns a new strong validator only after a 200 representation has
// completed durable acceptance. A fresh worker never treats 304 as readiness.
func (w *Worker) fetch(parent context.Context, etag string, initialized bool) (string, bool, string) {
	ctx, cancel := context.WithTimeout(parent, w.fetchTimeout)
	defer cancel()
	request, err := w.request(ctx, w.endpoint("/snapshot"))
	if err != nil {
		return etag, initialized, errorProtocol
	}
	if initialized && etag != "" {
		request.Header.Set("If-None-Match", etag)
	}
	response, err := w.client.Do(request)
	if err != nil {
		if parent.Err() != nil {
			return etag, initialized, errorCanceled
		}
		return etag, initialized, errorTransport
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusNotModified:
		if !initialized || etag == "" {
			return etag, initialized, errorProtocol
		}
		w.update(func(status *Status) {
			status.ConnectionState = "current"
			status.ErrorCategory = ""
		})
		return etag, initialized, ""
	case http.StatusOK:
		etagValues := response.Header.Values("ETag")
		if len(etagValues) != 1 || !strongETag(etagValues[0]) {
			return etag, initialized, errorProtocol
		}
		candidateETag := etagValues[0]
		body, err := io.ReadAll(io.LimitReader(response.Body, recordset.MaxBytes+1))
		if err != nil {
			return etag, initialized, errorTransport
		}
		if len(body) > recordset.MaxBytes {
			return etag, initialized, errorSnapshot
		}
		acceptance, err := w.store.Accept(w.config.Enrollment, body)
		if err != nil {
			category := errorSnapshot
			switch {
			case errors.Is(err, recordstore.ErrFollowerStorage), errors.Is(err, recordstore.ErrFollowerFaulted), errors.Is(err, recordstore.ErrClosed):
				category = errorStorage
			}
			return etag, initialized, category
		}
		meta := acceptance.State.Snapshot
		w.update(func(status *Status) {
			status.Ready = true
			status.Revision = meta.Revision
			status.ContentSHA256 = meta.ContentSHA256
			status.LastSuccess = w.now().UTC()
			status.ConnectionState = "current"
			status.ErrorCategory = ""
		})
		return candidateETag, true, ""
	case http.StatusUnauthorized, http.StatusForbidden:
		return etag, initialized, errorAuth
	default:
		return etag, initialized, errorProtocol
	}
}

func (w *Worker) setFailure(category string) {
	w.update(func(status *Status) {
		status.ConnectionState = "backoff"
		status.ErrorCategory = category
	})
}

func (w *Worker) currentCursor() (string, bool) {
	view, err := w.store.Acquire()
	if err != nil {
		return "", false
	}
	meta := view.State().Snapshot
	return w.config.Enrollment.LineageID + ":" + strconv.FormatUint(meta.Revision, 10), true
}

// Run synchronizes until ctx is canceled. It is safe to call once per Worker.
// Events are hints only; every accepted state arrives through a full snapshot GET.
func (w *Worker) Run(ctx context.Context) {
	if !w.running.CompareAndSwap(false, true) {
		return
	}
	defer w.running.Store(false)

	etag := ""
	initialized := false
	backoff := minBackoff
	for ctx.Err() == nil {
		w.update(func(status *Status) { status.ConnectionState = "fetching" })
		var category string
		etag, initialized, category = w.fetch(ctx, etag, initialized)
		trigger := false
		if category == "" {
			backoff = minBackoff
			trigger, category = w.stream(ctx)
		}
		if ctx.Err() != nil {
			break
		}
		if trigger {
			continue
		}
		if category == "" {
			category = errorTransport
		}
		w.setFailure(category)
		if !w.sleep(ctx, w.jitter(backoff)) {
			break
		}
		if backoff < maxBackoff {
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
	w.update(func(status *Status) {
		status.ConnectionState = "stopped"
		if status.ErrorCategory == "" {
			status.ErrorCategory = errorCanceled
		}
	})
}

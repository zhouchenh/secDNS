package server

import (
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/zhouchenh/secDNS/internal/recordstore"
)

const snapshotEventStreamLifetime = 30 * time.Second

type snapshotEventCursor struct {
	lineage  string
	revision uint64
	present  bool
}

type snapshotEventData struct {
	Status    string `json:"status"`
	RulesetID string `json:"ruleset_id"`
	LineageID string `json:"lineage_id"`
	Revision  string `json:"revision"`
}

func validSnapshotEventIdentity(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '-' || character == '_' || character == '.') {
			return false
		}
	}
	return true
}

func parseSnapshotEventCursor(values []string) (snapshotEventCursor, error) {
	if len(values) == 0 || len(values) == 1 && values[0] == "" {
		return snapshotEventCursor{}, nil
	}
	if len(values) != 1 {
		return snapshotEventCursor{}, errors.New("invalid snapshot event ID")
	}
	value := values[0]
	separator := strings.LastIndexByte(value, ':')
	if separator < 1 || separator == len(value)-1 {
		return snapshotEventCursor{}, errors.New("invalid snapshot event ID")
	}
	lineage, revisionText := value[:separator], value[separator+1:]
	revision, err := strconv.ParseUint(revisionText, 10, 64)
	if err != nil || revision == 0 || strconv.FormatUint(revision, 10) != revisionText || !validSnapshotEventIdentity(lineage) {
		return snapshotEventCursor{}, errors.New("invalid snapshot event ID")
	}
	return snapshotEventCursor{lineage: lineage, revision: revision, present: true}, nil
}

func snapshotEventStatus(notification recordstore.RevisionNotification, previous snapshotEventCursor) string {
	if notification.Resync || !previous.present || notification.LineageID != previous.lineage || previous.revision == math.MaxUint64 || notification.Revision != previous.revision+1 {
		return "resync"
	}
	return "advanced"
}

func writeSnapshotEvent(w io.Writer, notification recordstore.RevisionNotification, status string) error {
	payload, err := json.Marshal(snapshotEventData{
		Status:    status,
		RulesetID: notification.RulesetID,
		LineageID: notification.LineageID,
		Revision:  strconv.FormatUint(notification.Revision, 10),
	})
	if err != nil {
		return err
	}
	_, err = io.WriteString(w, "id: "+notification.LineageID+":"+strconv.FormatUint(notification.Revision, 10)+"\n"+
		"event: snapshot-revision\n"+
		"data: "+string(payload)+"\n\n")
	return err
}

func (h *HTTPAdminServer) handleSnapshotEvents(w http.ResponseWriter, r *http.Request) {
	h.streamSnapshotEvents(w, r, snapshotEventStreamLifetime)
}

func (h *HTTPAdminServer) streamSnapshotEvents(w http.ResponseWriter, r *http.Request, lifetime time.Duration) {
	streamEnd := time.Now().Add(lifetime)
	resume, err := parseSnapshotEventCursor(r.Header.Values("Last-Event-ID"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_snapshot_event_id"})
		return
	}
	_, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "snapshot_events_unavailable"})
		return
	}
	controller := http.NewResponseController(w)
	if err = controller.SetWriteDeadline(streamEnd); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "snapshot_events_unavailable"})
		return
	}
	subscription, err := h.versioned.SubscribeRevisions()
	if err != nil {
		if errors.Is(err, recordstore.ErrRevisionSubscriptionCapacity) {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "snapshot_event_capacity"})
			return
		}
		snapshotError(w, err)
		return
	}
	defer subscription.Close()
	timer := time.NewTimer(time.Until(streamEnd))
	defer timer.Stop()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	if err = controller.Flush(); err != nil {
		return
	}
	previous := resume
	first := true
	for {
		select {
		case <-r.Context().Done():
			return
		case <-timer.C:
			return
		case notification, open := <-subscription.Events():
			if !open {
				return
			}
			if first && resume.present && resume.lineage == notification.LineageID && resume.revision == notification.Revision {
				first = false
				previous = resume
				continue
			}
			status := snapshotEventStatus(notification, previous)
			if err = writeSnapshotEvent(w, notification, status); err != nil {
				return
			}
			if err = controller.Flush(); err != nil {
				return
			}
			first = false
			previous = snapshotEventCursor{lineage: notification.LineageID, revision: notification.Revision, present: true}
		}
	}
}

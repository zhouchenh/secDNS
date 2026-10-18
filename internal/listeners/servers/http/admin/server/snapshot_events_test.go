package server

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zhouchenh/secDNS/internal/recordset"
	"github.com/zhouchenh/secDNS/internal/recordstore"
)

type receivedSnapshotEvent struct {
	id      string
	event   string
	payload map[string]string
}

type deadlineRecorder struct {
	*httptest.ResponseRecorder
	deadline time.Time
}

func (w *deadlineRecorder) SetWriteDeadline(deadline time.Time) error {
	w.deadline = deadline
	return nil
}

type blockedDeadlineWriter struct {
	header       http.Header
	deadline     time.Time
	flushStarted chan struct{}
}

func (w *blockedDeadlineWriter) Header() http.Header {
	return w.header
}

func (w *blockedDeadlineWriter) Write(payload []byte) (int, error) {
	return len(payload), nil
}

func (w *blockedDeadlineWriter) WriteHeader(int) {}

func (w *blockedDeadlineWriter) SetWriteDeadline(deadline time.Time) error {
	w.deadline = deadline
	return nil
}

func (w *blockedDeadlineWriter) Flush() {}

func (w *blockedDeadlineWriter) FlushError() error {
	close(w.flushStarted)
	timer := time.NewTimer(time.Until(w.deadline))
	defer timer.Stop()
	<-timer.C
	return fmt.Errorf("synthetic blocked write reached deadline")
}

func openSnapshotEventStream(t *testing.T, server *httptest.Server, lastEventID string) (*http.Response, *bufio.Reader) {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, server.URL+"/admin/snapshot/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+testToken)
	if lastEventID != "" {
		request.Header.Set("Last-Event-ID", lastEventID)
	}
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		t.Fatalf("event stream status %d: %s", response.StatusCode, body)
	}
	return response, bufio.NewReader(response.Body)
}

func readSnapshotEvent(reader *bufio.Reader) (receivedSnapshotEvent, error) {
	result := receivedSnapshotEvent{}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return receivedSnapshotEvent{}, err
		}
		line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
		if line == "" {
			return result, nil
		}
		switch {
		case strings.HasPrefix(line, "id: "):
			result.id = strings.TrimPrefix(line, "id: ")
		case strings.HasPrefix(line, "event: "):
			result.event = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: "):
			if err = json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &result.payload); err != nil {
				return receivedSnapshotEvent{}, err
			}
		default:
			return receivedSnapshotEvent{}, fmt.Errorf("unexpected SSE line %q", line)
		}
	}
}

func receiveSnapshotEvent(t *testing.T, reader *bufio.Reader) receivedSnapshotEvent {
	t.Helper()
	type result struct {
		event receivedSnapshotEvent
		err   error
	}
	done := make(chan result, 1)
	go func() {
		event, err := readSnapshotEvent(reader)
		done <- result{event: event, err: err}
	}()
	select {
	case got := <-done:
		if got.err != nil {
			t.Fatal(got.err)
		}
		return got.event
	case <-time.After(2 * time.Second):
		t.Fatal("snapshot event timed out")
		return receivedSnapshotEvent{}
	}
}

func assertSnapshotEvent(t *testing.T, event receivedSnapshotEvent, id, status, revision string) {
	t.Helper()
	if event.id != id || event.event != "snapshot-revision" || len(event.payload) != 4 || event.payload["status"] != status || event.payload["ruleset_id"] != "r" || event.payload["lineage_id"] != "l" || event.payload["revision"] != revision {
		t.Fatalf("unexpected snapshot event: %+v", event)
	}
}

func postSnapshot(t *testing.T, server *httptest.Server, revision, operation, address string) {
	t.Helper()
	body := fmt.Sprintf(`{"expected":{"ruleset_id":"r","lineage_id":"l","revision":"%s"},"operation_id":"%s","records":[{"name":"x.invalid.","type":"A","values":["%s"],"ttl_seconds":60}]}`, revision, operation, address)
	request, err := http.NewRequest(http.MethodPost, server.URL+"/admin/snapshot", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+testToken)
	request.Header.Set("Content-Type", "application/json")
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	responseBody, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("snapshot POST status %d: %s", response.StatusCode, responseBody)
	}
}

func TestSnapshotEventCursorParsing(t *testing.T) {
	for _, test := range []struct {
		values   []string
		lineage  string
		revision uint64
		present  bool
		valid    bool
	}{
		{values: nil, valid: true},
		{values: []string{""}, valid: true},
		{values: []string{"lineage_1:18446744073709551615"}, lineage: "lineage_1", revision: ^uint64(0), present: true, valid: true},
		{values: []string{"lineage:0"}},
		{values: []string{"lineage:01"}},
		{values: []string{"lineage:-1"}},
		{values: []string{"lineage:1 "}},
		{values: []string{"bad:lineage:1"}},
		{values: []string{"lineage:1", "lineage:2"}},
	} {
		cursor, err := parseSnapshotEventCursor(test.values)
		if (err == nil) != test.valid {
			t.Fatalf("values %q validity: %v", test.values, err)
		}
		if err == nil && (cursor.lineage != test.lineage || cursor.revision != test.revision || cursor.present != test.present) {
			t.Fatalf("values %q cursor: %+v", test.values, cursor)
		}
	}
}

func TestSnapshotEventsAuthenticateBeforeCursorAndBoundCapacity(t *testing.T) {
	store, err := recordstore.NewVersionedMemory(recordstore.Enrollment{RulesetID: "r", LineageID: "l"})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	handler := &HTTPAdminServer{Token: testToken, versioned: store}
	for _, test := range []struct {
		token  string
		status int
		code   string
	}{
		{status: http.StatusUnauthorized, code: "missing or malformed Authorization: Bearer header"},
		{token: "wrong", status: http.StatusForbidden, code: "invalid bearer token"},
		{token: testToken, status: http.StatusBadRequest, code: "invalid_snapshot_event_id"},
	} {
		request := httptest.NewRequest(http.MethodGet, "/admin/snapshot/events", nil)
		request.Header.Set("Last-Event-ID", "not-canonical")
		if test.token != "" {
			request.Header.Set("Authorization", "Bearer "+test.token)
		}
		response := httptest.NewRecorder()
		handler.routes().ServeHTTP(response, request)
		var body map[string]string
		if json.Unmarshal(response.Body.Bytes(), &body) != nil || response.Code != test.status || body["error"] != test.code {
			t.Fatalf("authentication order: status=%d body=%s", response.Code, response.Body.String())
		}
	}

	var subscriptions []*recordstore.RevisionSubscription
	for range recordstore.MaxRevisionSubscriptions {
		subscription, subscribeErr := store.SubscribeRevisions()
		if subscribeErr != nil {
			t.Fatal(subscribeErr)
		}
		subscriptions = append(subscriptions, subscription)
	}
	defer func() {
		for _, subscription := range subscriptions {
			subscription.Close()
		}
	}()
	request := httptest.NewRequest(http.MethodGet, "/admin/snapshot/events", nil)
	request.Header.Set("Authorization", "Bearer "+testToken)
	response := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	handler.routes().ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || response.Body.String() != "{\"error\":\"snapshot_event_capacity\"}\n" {
		t.Fatal(response.Code, response.Body.String())
	}

	legacy := &HTTPAdminServer{Token: testToken}
	if legacyResponse := do(legacy, http.MethodGet, "/admin/snapshot/events", testToken, ""); legacyResponse.Code != http.StatusNotFound {
		t.Fatal("legacy store exposed snapshot events", legacyResponse.Code)
	}
}

func TestSnapshotEventStreamRequiresAndEnforcesWriteDeadline(t *testing.T) {
	store, err := recordstore.NewVersionedMemory(recordstore.Enrollment{RulesetID: "r", LineageID: "l"})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	handler := &HTTPAdminServer{Token: testToken, versioned: store}

	unsupported := httptest.NewRecorder()
	handler.streamSnapshotEvents(unsupported, httptest.NewRequest(http.MethodGet, "/admin/snapshot/events", nil), time.Second)
	if unsupported.Code != http.StatusServiceUnavailable || unsupported.Body.String() != "{\"error\":\"snapshot_events_unavailable\"}\n" {
		t.Fatal("unsupported deadline did not fail closed", unsupported.Code, unsupported.Body.String())
	}

	lifetime := 40 * time.Millisecond
	blocked := &blockedDeadlineWriter{header: make(http.Header), flushStarted: make(chan struct{})}
	started := time.Now()
	done := make(chan struct{})
	go func() {
		handler.streamSnapshotEvents(blocked, httptest.NewRequest(http.MethodGet, "/admin/snapshot/events", nil), lifetime)
		close(done)
	}()
	select {
	case <-blocked.flushStarted:
	case <-time.After(time.Second):
		t.Fatal("stream did not reach blocked initial flush")
	}
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("blocked writer outlived its write deadline")
	}
	if elapsed := time.Since(started); elapsed > 250*time.Millisecond {
		t.Fatal("stream lifetime included write grace", elapsed)
	}
	if delay := blocked.deadline.Sub(started); delay < lifetime/2 || delay > 2*lifetime {
		t.Fatal("write deadline did not use the single stream end", delay)
	}

	var subscriptions []*recordstore.RevisionSubscription
	for range recordstore.MaxRevisionSubscriptions {
		subscription, subscribeErr := store.SubscribeRevisions()
		if subscribeErr != nil {
			t.Fatal("stream leaked a subscription", subscribeErr)
		}
		subscriptions = append(subscriptions, subscription)
	}
	for _, subscription := range subscriptions {
		subscription.Close()
	}
}

func TestSnapshotEventsResumeAdvanceAndFullFetch(t *testing.T) {
	store, err := recordstore.NewVersionedMemory(recordstore.Enrollment{RulesetID: "r", LineageID: "l"})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	handler := &HTTPAdminServer{Token: testToken, versioned: store}
	server := httptest.NewServer(handler.routes())
	defer server.Close()

	initialResponse, initialReader := openSnapshotEventStream(t, server, "")
	if initialResponse.Header.Get("Content-Type") != "text/event-stream" || initialResponse.Header.Get("Cache-Control") != "no-store" || initialResponse.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("event stream headers", initialResponse.Header)
	}
	assertSnapshotEvent(t, receiveSnapshotEvent(t, initialReader), "l:1", "resync", "1")
	initialResponse.Body.Close()

	response, reader := openSnapshotEventStream(t, server, "l:1")
	defer response.Body.Close()
	eventResult := make(chan struct {
		event receivedSnapshotEvent
		err   error
	}, 1)
	go func() {
		event, readErr := readSnapshotEvent(reader)
		eventResult <- struct {
			event receivedSnapshotEvent
			err   error
		}{event, readErr}
	}()
	select {
	case unexpected := <-eventResult:
		t.Fatal("exact resume emitted current state", unexpected)
	case <-time.After(30 * time.Millisecond):
	}
	postSnapshot(t, server, "1", "event-two", "192.0.2.1")
	select {
	case got := <-eventResult:
		if got.err != nil {
			t.Fatal(got.err)
		}
		assertSnapshotEvent(t, got.event, "l:2", "advanced", "2")
	case <-time.After(2 * time.Second):
		t.Fatal("published revision event timed out")
	}

	request, _ := http.NewRequest(http.MethodGet, server.URL+"/admin/snapshot", nil)
	request.Header.Set("Authorization", "Bearer "+testToken)
	snapshotResponse, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	wire, _ := io.ReadAll(snapshotResponse.Body)
	snapshotResponse.Body.Close()
	snapshot, err := recordset.Parse(wire)
	if snapshotResponse.StatusCode != http.StatusOK || err != nil || snapshot.Metadata().Revision != 2 || len(snapshot.Records()) != 1 {
		t.Fatal("full snapshot handoff", snapshotResponse.StatusCode, err, string(wire))
	}

	postSnapshot(t, server, "1", "event-two", "192.0.2.1")
	postSnapshot(t, server, "2", "event-three", "192.0.2.1")
	assertSnapshotEvent(t, receiveSnapshotEvent(t, reader), "l:3", "advanced", "3")
}

func TestSnapshotEventsStaleFutureAndUnknownLineageResync(t *testing.T) {
	store, err := recordstore.NewVersionedMemory(recordstore.Enrollment{RulesetID: "r", LineageID: "l"})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	base, _ := store.Acquire()
	if _, err = store.Replace(recordstore.Expected{RulesetID: "r", LineageID: "l", Revision: base.Metadata().Revision}, "make-two", nil); err != nil {
		t.Fatal(err)
	}
	handler := &HTTPAdminServer{Token: testToken, versioned: store}
	server := httptest.NewServer(handler.routes())
	defer server.Close()

	for _, lastEventID := range []string{"l:1", "other:2", "l:3", "l:18446744073709551615"} {
		response, reader := openSnapshotEventStream(t, server, lastEventID)
		assertSnapshotEvent(t, receiveSnapshotEvent(t, reader), "l:2", "resync", "2")
		response.Body.Close()
	}
}

func TestSnapshotEventStreamHasFixedLifetimeAndStoreCloseTermination(t *testing.T) {
	store, err := recordstore.NewVersionedMemory(recordstore.Enrollment{RulesetID: "r", LineageID: "l"})
	if err != nil {
		t.Fatal(err)
	}
	handler := &HTTPAdminServer{Token: testToken, versioned: store}
	short := httptest.NewServer(http.HandlerFunc(handler.auth(func(w http.ResponseWriter, r *http.Request) {
		handler.streamSnapshotEvents(w, r, 25*time.Millisecond)
	})))
	response, _ := openSnapshotEventStream(t, short, "l:1")
	done := make(chan error, 1)
	go func() {
		_, readErr := io.ReadAll(response.Body)
		done <- readErr
	}()
	select {
	case readErr := <-done:
		if readErr != nil && !errors.Is(readErr, io.ErrUnexpectedEOF) {
			t.Fatal(readErr)
		}
	case <-time.After(time.Second):
		t.Fatal("bounded stream did not end")
	}
	response.Body.Close()
	short.Close()

	server := httptest.NewServer(handler.routes())
	response, _ = openSnapshotEventStream(t, server, "l:1")
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	done = make(chan error, 1)
	go func() {
		_, readErr := io.ReadAll(response.Body)
		done <- readErr
	}()
	select {
	case readErr := <-done:
		if readErr != nil {
			t.Fatal(readErr)
		}
	case <-time.After(time.Second):
		t.Fatal("store close did not terminate stream")
	}
	response.Body.Close()
	server.Close()
}

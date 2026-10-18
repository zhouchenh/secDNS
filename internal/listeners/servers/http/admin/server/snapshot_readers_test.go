package server

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zhouchenh/secDNS/internal/recordstore"
)

const readerToken = "reader-token-0123456789abcdef-0001"

func TestSnapshotReaderIsReadOnlyAndServerDerived(t *testing.T) {
	versioned, err := recordstore.NewVersionedMemory(recordstore.Enrollment{RulesetID: "r", LineageID: "l"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = versioned.Close() })
	handler := &HTTPAdminServer{Token: testToken, versioned: versioned, SnapshotReaders: []SnapshotReader{{NodeID: "node-one", Token: readerToken}}}
	if err := handler.ValidateSnapshotReaders(); err != nil {
		t.Fatal(err)
	}
	if response := do(handler, http.MethodGet, "/admin/snapshot", readerToken, ""); response.Code != http.StatusOK {
		t.Fatal("reader could not fetch snapshot", response.Code, response.Body.String())
	}
	replacement := `{"expected":{"ruleset_id":"r","lineage_id":"l","revision":"1"},"operation_id":"op","records":[]}`
	if response := do(handler, http.MethodPost, "/admin/snapshot", readerToken, replacement); response.Code != http.StatusForbidden {
		t.Fatal("reader reached mutation route", response.Code)
	}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Authorization", "Bearer "+readerToken)
	request.Header.Set("X-Node-ID", "claimed-other")
	response := httptest.NewRecorder()
	handler.readAuth(func(w http.ResponseWriter, r *http.Request) {
		nodeID, ok := SnapshotReaderNodeID(r.Context())
		if !ok || nodeID != "node-one" {
			t.Error("reader identity was not server-derived", nodeID, ok)
		}
		w.WriteHeader(http.StatusNoContent)
	})(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatal(response.Code)
	}
	if response := do(handler, http.MethodGet, "/admin/snapshot", testToken, ""); response.Code != http.StatusOK {
		t.Fatal("legacy admin read changed", response.Code)
	}
}

func TestSnapshotReaderNegativeRouteMatrix(t *testing.T) {
	versioned, err := recordstore.NewVersionedMemory(recordstore.Enrollment{RulesetID: "r", LineageID: "l"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = versioned.Close() })
	handler := &HTTPAdminServer{Token: testToken, versioned: versioned, UI: true, SourcePolicyExplain: true, SnapshotReaders: []SnapshotReader{{NodeID: "node-one", Token: readerToken}}}
	for _, test := range []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodPost, "/admin/snapshot", `{}`},
		{http.MethodGet, "/admin/records", ""},
		{http.MethodPost, "/admin/records", `{}`},
		{http.MethodDelete, "/admin/records/name.invalid./A", ""},
		{http.MethodPost, "/admin/import/routeros/preview", "source"},
		{http.MethodPost, "/admin/source-policy/explain", `{}`},
	} {
		response := do(handler, test.method, test.path, readerToken, test.body)
		if response.Code != http.StatusForbidden {
			t.Fatalf("reader reached %s %s: %d %s", test.method, test.path, response.Code, response.Body.String())
		}
	}
	if response := do(handler, http.MethodGet, "/admin/snapshot", readerToken, ""); response.Code != http.StatusOK {
		t.Fatal("allowed snapshot route refused", response.Code)
	}
	// A recorder cannot provide a write deadline, but reaching the event handler
	// (503) proves the read credential passed auth; 403 would mean it did not.
	if response := do(handler, http.MethodGet, "/admin/snapshot/events", readerToken, ""); response.Code != http.StatusServiceUnavailable {
		t.Fatal("allowed event route did not pass auth", response.Code, response.Body.String())
	}
}

func TestSnapshotReaderValidation(t *testing.T) {
	valid := SnapshotReader{NodeID: "node", Token: readerToken}
	for _, readers := range [][]SnapshotReader{
		{{NodeID: "bad space", Token: readerToken}},
		{{NodeID: "node", Token: "short"}},
		{{NodeID: "node", Token: " " + readerToken}},
		{{NodeID: "node", Token: strings.Repeat("x", 31) + "é"}},
		{valid, valid},
		{{NodeID: "one", Token: readerToken}, {NodeID: "two", Token: readerToken}},
	} {
		handler := &HTTPAdminServer{Token: testToken, SnapshotReaders: readers}
		if !errors.Is(handler.ValidateSnapshotReaders(), ErrSnapshotReaders) {
			t.Fatal("invalid reader set accepted", readers)
		}
	}
	tooMany := make([]SnapshotReader, 65)
	for index := range tooMany {
		tooMany[index] = SnapshotReader{NodeID: "node-" + strings.Repeat("x", index%10) + string(rune('A'+index%26)), Token: readerToken + strings.Repeat("x", index+1)}
	}
	if !errors.Is((&HTTPAdminServer{Token: testToken, SnapshotReaders: tooMany}).ValidateSnapshotReaders(), ErrSnapshotReaders) {
		t.Fatal("reader capacity ignored")
	}
	equal := &HTTPAdminServer{Token: readerToken, SnapshotReaders: []SnapshotReader{valid}}
	if !errors.Is(equal.ValidateSnapshotReaders(), ErrSnapshotReaders) {
		t.Fatal("admin/read token equality accepted")
	}
}

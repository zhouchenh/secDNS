package server

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zhouchenh/secDNS/internal/recordset"
	"github.com/zhouchenh/secDNS/internal/recordstore"
)

func getSnapshot(h *HTTPAdminServer, token string, validators ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/admin/snapshot", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for _, validator := range validators {
		req.Header.Add("If-None-Match", validator)
	}
	recorder := httptest.NewRecorder()
	h.routes().ServeHTTP(recorder, req)
	return recorder
}

func TestSnapshotConditionalGETAndFollowerOrdering(t *testing.T) {
	authority, err := recordstore.NewVersionedMemory(recordstore.Enrollment{RulesetID: "rules", LineageID: "lineage-a"})
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	handler := &HTTPAdminServer{Token: testToken, versioned: authority}

	enrollment := recordstore.FollowerEnrollment{
		ClusterID: "cluster", Kind: recordstore.FollowerExactRecords,
		RulesetID: "rules", LineageID: "lineage-a", AuthorityEpoch: "epoch-a",
	}
	databasePath := filepath.Join(t.TempDir(), "follower.db")
	follower, err := recordstore.CreateFollowerSQLite(databasePath, enrollment)
	if err != nil {
		t.Fatal(err)
	}

	initial := getSnapshot(handler, testToken)
	if initial.Code != http.StatusOK || initial.Header().Get("ETag") == "" {
		t.Fatal(initial.Code, initial.Header())
	}
	initialBody := append([]byte(nil), initial.Body.Bytes()...)
	authorityView, err := authority.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := authorityView.MarshalJSON()
	if err != nil || string(initialBody) != string(canonical)+"\n" {
		t.Fatal("ordinary snapshot representation changed", err)
	}
	accepted, err := follower.Accept(enrollment, initialBody)
	if err != nil || accepted.Outcome != "initial" || accepted.State.Snapshot.Revision != 1 {
		t.Fatal(accepted, err)
	}
	initialTag := initial.Header().Get("ETag")

	notModified := getSnapshot(handler, testToken, initialTag)
	if notModified.Code != http.StatusNotModified || notModified.Body.Len() != 0 || notModified.Header().Get("ETag") != initialTag || notModified.Header().Get("Cache-Control") != "no-store" {
		t.Fatal(notModified.Code, notModified.Header(), notModified.Body.String())
	}
	unauthorized := getSnapshot(handler, "", initialTag)
	if unauthorized.Code != http.StatusUnauthorized || unauthorized.Header().Get("ETag") != "" {
		t.Fatal("conditional read bypassed authentication", unauthorized.Code, unauthorized.Header())
	}

	replacement := `{"expected":{"ruleset_id":"rules","lineage_id":"lineage-a","revision":"1"},"operation_id":"replace-one","records":[{"name":"x.invalid.","type":"A","values":["192.0.2.1"],"ttl_seconds":60}]}`
	if response := do(handler, http.MethodPost, "/admin/snapshot", testToken, replacement); response.Code != http.StatusOK {
		t.Fatal(response.Code, response.Body.String())
	}
	advanced := getSnapshot(handler, testToken, initialTag)
	if advanced.Code != http.StatusOK || advanced.Header().Get("ETag") == initialTag {
		t.Fatal(advanced.Code, advanced.Header())
	}
	revisionTwo, err := recordset.Parse(advanced.Body.Bytes())
	if err != nil || revisionTwo.Metadata().Revision != 2 {
		t.Fatal(err)
	}
	accepted, err = follower.Accept(enrollment, advanced.Body.Bytes())
	if err != nil || accepted.Outcome != "advanced" || accepted.State.Snapshot.Revision != 2 {
		t.Fatal(accepted, err)
	}

	currentTag := advanced.Header().Get("ETag")
	weakList := getSnapshot(handler, testToken, `"unrelated"`, "W/"+currentTag)
	if weakList.Code != http.StatusNotModified || weakList.Body.Len() != 0 {
		t.Fatal(weakList.Code, weakList.Body.String())
	}
	if wildcard := getSnapshot(handler, testToken, "*"); wildcard.Code != http.StatusNotModified || wildcard.Body.Len() != 0 {
		t.Fatal(wildcard.Code, wildcard.Body.String())
	}

	// A new authority revision remains observable even when its content digest is
	// unchanged, preserving the follower's high-water revision.
	replacement = strings.ReplaceAll(strings.ReplaceAll(replacement, `"revision":"1"`, `"revision":"2"`), `"operation_id":"replace-one"`, `"operation_id":"replace-two"`)
	if response := do(handler, http.MethodPost, "/admin/snapshot", testToken, replacement); response.Code != http.StatusOK {
		t.Fatal(response.Code, response.Body.String())
	}
	revisionThreeResponse := getSnapshot(handler, testToken, currentTag)
	if revisionThreeResponse.Code != http.StatusOK || revisionThreeResponse.Header().Get("ETag") == currentTag {
		t.Fatal(revisionThreeResponse.Code, revisionThreeResponse.Header())
	}
	revisionThree, err := recordset.Parse(revisionThreeResponse.Body.Bytes())
	if err != nil || revisionThree.Metadata().Revision != 3 || revisionThree.Metadata().ContentSHA256 != revisionTwo.Metadata().ContentSHA256 {
		t.Fatal("revision/content binding", err)
	}
	accepted, err = follower.Accept(enrollment, revisionThreeResponse.Body.Bytes())
	if err != nil || accepted.Outcome != "advanced" || accepted.State.Snapshot.Revision != 3 {
		t.Fatal(accepted, err)
	}

	if err = follower.Close(); err != nil {
		t.Fatal(err)
	}
	follower, err = recordstore.OpenFollowerSQLite(databasePath, enrollment)
	if err != nil {
		t.Fatal(err)
	}
	defer follower.Close()
	view, err := follower.Acquire()
	if err != nil || view.State().Snapshot.Revision != 3 {
		t.Fatal("durable follower watermark", err)
	}
	if _, err = follower.Accept(enrollment, initialBody); !errors.Is(err, recordstore.ErrFollowerRollback) {
		t.Fatal("old full response did not remain a rollback after restart", err)
	}

	// The validator binds the lineage even when rules, revision and record content
	// are otherwise equal.
	other, err := recordstore.NewVersionedMemory(recordstore.Enrollment{RulesetID: "rules", LineageID: "lineage-b"})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	otherResponse := getSnapshot(&HTTPAdminServer{Token: testToken, versioned: other}, testToken)
	if otherResponse.Code != http.StatusOK || otherResponse.Header().Get("ETag") == initialTag {
		t.Fatal("lineage not bound", otherResponse.Code, otherResponse.Header())
	}

	if err = authority.Close(); err != nil {
		t.Fatal(err)
	}
	if unavailable := getSnapshot(handler, testToken, "*"); unavailable.Code != http.StatusServiceUnavailable || unavailable.Header().Get("ETag") != "" {
		t.Fatal("validator masked unavailable authority", unavailable.Code, unavailable.Header())
	}
}

func TestSnapshotIfNoneMatchParsing(t *testing.T) {
	current := `"secdns-exact-snapshot-v1-0123456789abcdef"`
	for _, test := range []struct {
		name   string
		values []string
		match  bool
	}{
		{"absent", nil, false},
		{"exact", []string{current}, true},
		{"weak", []string{"W/" + current}, true},
		{"list", []string{`"other"`, current}, true},
		{"quoted comma", []string{`"other,tag", ` + current}, true},
		{"wildcard", []string{" * "}, true},
		{"other", []string{`"other"`}, false},
		{"malformed prefix", []string{"invalid, " + current}, false},
		{"malformed suffix", []string{current + ","}, false},
		{"unterminated", []string{`"unterminated`}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := snapshotNotModified(test.values, current); got != test.match {
				t.Fatalf("match=%v, want %v", got, test.match)
			}
		})
	}
}

func TestSnapshotResponseETagBindsProvenance(t *testing.T) {
	store, err := recordstore.NewVersionedMemory(recordstore.Enrollment{RulesetID: "rules", LineageID: "lineage"})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	view, err := store.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	without, err := snapshotResponseETag(view, recordset.OperatorSuppliedProvenance{}, false)
	if err != nil {
		t.Fatal(err)
	}
	first, err := recordset.NewOperatorSuppliedProvenance(recordset.RouterOSExactExplicitProfile, strings.Repeat("a", 64), view.Metadata().ContentSHA256)
	if err != nil {
		t.Fatal(err)
	}
	second, err := recordset.NewOperatorSuppliedProvenance(recordset.RouterOSExactExplicitProfile, strings.Repeat("b", 64), view.Metadata().ContentSHA256)
	if err != nil {
		t.Fatal(err)
	}
	withFirst, err := snapshotResponseETag(view, first, true)
	if err != nil {
		t.Fatal(err)
	}
	withSecond, err := snapshotResponseETag(view, second, true)
	if err != nil {
		t.Fatal(err)
	}
	if without == withFirst || withFirst == withSecond || without == withSecond {
		t.Fatal("operator-supplied provenance is not bound into the representation validator")
	}
}

package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zhouchenh/secDNS/internal/recordset"
	"github.com/zhouchenh/secDNS/internal/recordstore"
)

// C20: an exact import (replacement with operator-supplied provenance) that removes
// records must state confirm_removals equal to the server's own count.
func TestSnapshotExactImportRequiresRemovalConfirmation(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			enrollment := recordstore.Enrollment{RulesetID: "r", LineageID: "l"}
			var store *recordstore.VersionedStore
			var err error
			if backend == "memory" {
				store, err = recordstore.NewVersionedMemory(enrollment)
			} else {
				store, err = recordstore.OpenVersionedSQLite(filepath.Join(t.TempDir(), "db"), enrollment)
			}
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			h := &HTTPAdminServer{Token: testToken, versioned: store}
			var seed []recordset.Record
			for i := 1; i <= 7; i++ {
				seed = append(seed, recordset.Record{Name: fmt.Sprintf("h%d.example.invalid.", i), Type: "A", Values: []string{fmt.Sprintf("192.0.2.%d", i)}, TTLSeconds: 60})
			}
			if _, err = store.Replace(recordstore.Expected{RulesetID: "r", LineageID: "l", Revision: 1}, "seed", seed); err != nil {
				t.Fatal(err)
			}
			// the import keeps h1 (changed), H2 (case-insensitive key), and adds n1: 5 removed
			imported := `[{"name":"h1.example.invalid.","type":"A","values":["198.51.100.1"],"ttl_seconds":60},{"name":"H2.EXAMPLE.INVALID","type":"A","values":["192.0.2.2"],"ttl_seconds":60},{"name":"n1.example.invalid.","type":"A","values":["198.51.100.9"],"ttl_seconds":60}]`
			var records []recordset.Record
			if err = json.Unmarshal([]byte(imported), &records); err != nil {
				t.Fatal(err)
			}
			candidate, err := recordset.New("r", "l", 2, records)
			if err != nil {
				t.Fatal(err)
			}
			provenance := fmt.Sprintf(`"operator_supplied_provenance":{"profile":"%s","source_sha256":"%s","content_sha256":"%s"}`, recordset.RouterOSExactExplicitProfile, strings.Repeat("b", 64), candidate.Metadata().ContentSHA256)
			body := func(op, extra string) string {
				return `{"expected":{"ruleset_id":"r","lineage_id":"l","revision":"2"},"operation_id":"` + op + `","records":` + imported + `,` + provenance + extra + `}`
			}
			expectError := func(b, code string) {
				t.Helper()
				res := do(h, "POST", "/admin/snapshot", testToken, b)
				if res.Code != 409 || !strings.Contains(res.Body.String(), `"`+code+`"`) {
					t.Fatalf("want 409 %s, got %d %s", code, res.Code, res.Body.String())
				}
				view, _ := store.Acquire()
				if view.Metadata().Revision != 2 || len(view.Records()) != 7 {
					t.Fatalf("rejected import changed the store: revision %d, %d records", view.Metadata().Revision, len(view.Records()))
				}
			}
			expectError(body("missing", ""), "removal_confirmation_required")
			expectError(body("low", `,"confirm_removals":4`), "removal_confirmation_mismatch")
			expectError(body("high", `,"confirm_removals":6`), "removal_confirmation_mismatch")
			expectError(body("zero", `,"confirm_removals":0`), "removal_confirmation_mismatch")
			if res := do(h, "POST", "/admin/snapshot", testToken, body("bad", `,"confirm_removals":"5"`)); res.Code != 400 {
				t.Fatalf("malformed confirm_removals: %d %s", res.Code, res.Body.String())
			}
			good := body("confirmed", `,"confirm_removals":5`)
			first := do(h, "POST", "/admin/snapshot", testToken, good)
			if first.Code != 200 {
				t.Fatalf("confirmed import rejected: %d %s", first.Code, first.Body.String())
			}
			// an identical retry after commit stays an idempotent replay, not a new rejection
			replay := do(h, "POST", "/admin/snapshot", testToken, good)
			if replay.Code != 200 || replay.Body.String() != first.Body.String() {
				t.Fatalf("replay changed: %d %s", replay.Code, replay.Body.String())
			}
			view, _ := store.Acquire()
			if view.Metadata().Revision != 3 || len(view.Records()) != 3 {
				t.Fatalf("import not applied: revision %d, %d records", view.Metadata().Revision, len(view.Records()))
			}
		})
	}
}

// Plain snapshot replacements keep their API: no confirmation needed, but a stated
// count must be right. An exact import that removes nothing needs no field.
func TestSnapshotReplacementRemovalConfirmationCompatibility(t *testing.T) {
	store, err := recordstore.NewVersionedMemory(recordstore.Enrollment{RulesetID: "r", LineageID: "l"})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	h := &HTTPAdminServer{Token: testToken, versioned: store}
	two := `[{"name":"a.invalid.","type":"A","values":["192.0.2.1"],"ttl_seconds":60},{"name":"b.invalid.","type":"A","values":["192.0.2.2"],"ttl_seconds":60}]`
	one := `[{"name":"a.invalid.","type":"A","values":["192.0.2.1"],"ttl_seconds":60}]`
	post := func(rev, op, records, extra string) int {
		return do(h, "POST", "/admin/snapshot", testToken, `{"expected":{"ruleset_id":"r","lineage_id":"l","revision":"`+rev+`"},"operation_id":"`+op+`","records":`+records+extra+`}`).Code
	}
	if c := post("1", "p1", two, ""); c != 200 {
		t.Fatal("seed", c)
	}
	if c := post("2", "p2", one, `,"confirm_removals":2`); c != 409 {
		t.Fatal("wrong stated count accepted", c)
	}
	if c := post("2", "p3", one, ""); c != 200 {
		t.Fatal("plain replacement now needs confirmation", c)
	}
	if c := post("3", "p4", two, `,"confirm_removals":0`); c != 200 {
		t.Fatal("correct zero count rejected", c)
	}
	var records []recordset.Record
	json.Unmarshal([]byte(two+""), &records)
	records = append(records, recordset.Record{Name: "c.invalid.", Type: "A", Values: []string{"192.0.2.3"}, TTLSeconds: 60})
	candidate, err := recordset.New("r", "l", 4, records)
	if err != nil {
		t.Fatal(err)
	}
	three, _ := json.Marshal(candidate.Records())
	prov := fmt.Sprintf(`,"operator_supplied_provenance":{"profile":"%s","source_sha256":"%s","content_sha256":"%s"}`, recordset.RouterOSExactExplicitProfile, strings.Repeat("c", 64), candidate.Metadata().ContentSHA256)
	if c := post("4", "p5", string(three), prov); c != 200 {
		t.Fatal("additive exact import needs a confirmation", c)
	}
}

// The console reaches records through the gateway; the record authority behind it may be an
// older build whose strict parser rejects confirm_removals. The gateway enforces the rule
// against the authority's current generation and forwards the request without the field.
func TestRecordGatewayRemovalConfirmationOlderAuthority(t *testing.T) {
	store, err := recordstore.NewVersionedMemory(recordstore.Enrollment{RulesetID: "r", LineageID: "l"})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var seed []recordset.Record
	for i := 1; i <= 6; i++ {
		seed = append(seed, recordset.Record{Name: fmt.Sprintf("g%d.invalid.", i), Type: "A", Values: []string{fmt.Sprintf("192.0.2.%d", i)}, TTLSeconds: 60})
	}
	if _, err = store.Replace(recordstore.Expected{RulesetID: "r", LineageID: "l", Revision: 1}, "seed", seed); err != nil {
		t.Fatal(err)
	}
	upstream := &HTTPAdminServer{Token: strings.Repeat("u", 32), versioned: store}
	var forwarded, headers []string
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			raw, _ := io.ReadAll(r.Body)
			forwarded = append(forwarded, string(raw))
			headers = append(headers, strings.Join(r.Header.Values(confirmRemovalsHeader), ","))
			if strings.Contains(string(raw), "confirm_removals") {
				// an authority built before confirm_removals existed
				w.WriteHeader(400)
				w.Write([]byte(`{"error":"invalid_snapshot_request"}`))
				return
			}
			r.Body = io.NopCloser(strings.NewReader(string(raw)))
		}
		upstream.routes().ServeHTTP(w, r)
	}))
	defer remote.Close()
	h := &HTTPAdminServer{RecordAuthorityURL: remote.URL + "/admin", recordAuthorityCredential: upstream.Token}
	post := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/admin/snapshot", strings.NewReader(body))
		w := httptest.NewRecorder()
		h.forwardRecordRequest(w, r, "POST", "/snapshot")
		return w
	}
	imported := `[{"name":"g1.invalid.","type":"A","values":["192.0.2.1"],"ttl_seconds":60},{"name":"n.invalid.","type":"TXT","values":["<a&b>"],"ttl_seconds":60}]`
	var records []recordset.Record
	if err = json.Unmarshal([]byte(imported), &records); err != nil {
		t.Fatal(err)
	}
	candidate, err := recordset.New("r", "l", 2, records)
	if err != nil {
		t.Fatal(err)
	}
	prov := fmt.Sprintf(`"operator_supplied_provenance":{"profile":"%s","source_sha256":"%s","content_sha256":"%s"}`, recordset.RouterOSExactExplicitProfile, strings.Repeat("d", 64), candidate.Metadata().ContentSHA256)
	body := func(op, extra string) string {
		return `{"expected":{"ruleset_id":"r","lineage_id":"l","revision":"2"},"operation_id":"` + op + `","records":` + imported + `,` + prov + extra + `}`
	}
	for _, c := range []struct{ body, code string }{
		{body("g-missing", ""), "removal_confirmation_required"},
		{body("g-wrong", `,"confirm_removals":4`), "removal_confirmation_mismatch"},
	} {
		if w := post(c.body); w.Code != 409 || !strings.Contains(w.Body.String(), c.code) {
			t.Fatalf("want 409 %s, got %d %s", c.code, w.Code, w.Body.String())
		}
	}
	if len(forwarded) != 0 {
		t.Fatalf("rejected requests reached the authority: %v", forwarded)
	}
	w := post(body("g-ok", `,"confirm_removals":5`))
	if w.Code != 200 {
		t.Fatalf("confirmed import through the gateway: %d %s", w.Code, w.Body.String())
	}
	if len(forwarded) != 1 || strings.Contains(forwarded[0], "confirm_removals") || !strings.Contains(forwarded[0], `"<a&b>"`) || headers[0] != "5" {
		t.Fatalf("forwarded body: %v", forwarded)
	}
	view, _ := store.Acquire()
	if view.Metadata().Revision != 3 || len(view.Records()) != 2 {
		t.Fatalf("authority not updated: revision %d, %d records", view.Metadata().Revision, len(view.Records()))
	}
	// a plain replacement without the field passes through byte-for-byte, with no extra read
	plain := `{"expected":{"ruleset_id":"r","lineage_id":"l","revision":"3"},"operation_id":"g-plain","records":[{"name":"g1.invalid.","type":"A","values":["192.0.2.1"],"ttl_seconds":60}]}`
	if w := post(plain); w.Code != 200 || forwarded[len(forwarded)-1] != plain {
		t.Fatalf("plain replacement through the gateway: %d %s", w.Code, w.Body.String())
	}
}

// A current authority accepts the count from the gateway header and checks it.
func TestSnapshotRemovalConfirmationHeader(t *testing.T) {
	store, err := recordstore.NewVersionedMemory(recordstore.Enrollment{RulesetID: "r", LineageID: "l"})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	h := &HTTPAdminServer{Token: testToken, versioned: store}
	two := `[{"name":"a.invalid.","type":"A","values":["192.0.2.1"],"ttl_seconds":60},{"name":"b.invalid.","type":"A","values":["192.0.2.2"],"ttl_seconds":60}]`
	one := `[{"name":"a.invalid.","type":"A","values":["192.0.2.1"],"ttl_seconds":60}]`
	post := func(rev, op, records string, header ...string) int {
		r := httptest.NewRequest("POST", "/admin/snapshot", strings.NewReader(`{"expected":{"ruleset_id":"r","lineage_id":"l","revision":"`+rev+`"},"operation_id":"`+op+`","records":`+records+`}`))
		r.Header.Set("Authorization", "Bearer "+testToken)
		r.Header.Set("Content-Type", "application/json")
		for _, v := range header {
			r.Header.Add(confirmRemovalsHeader, v)
		}
		w := httptest.NewRecorder()
		h.routes().ServeHTTP(w, r)
		return w.Code
	}
	if c := post("1", "h1", two); c != 200 {
		t.Fatal("seed", c)
	}
	for _, bad := range [][]string{{"x"}, {"-1"}, {"01"}, {"1", "1"}} {
		if c := post("2", "hbad", one, bad...); c != 400 {
			t.Fatalf("header %v: %d", bad, c)
		}
	}
	if c := post("2", "hwrong", one, "2"); c != 409 {
		t.Fatal("wrong header count accepted", c)
	}
	if c := post("2", "hright", one, "1"); c != 200 {
		t.Fatal("right header count rejected", c)
	}
}

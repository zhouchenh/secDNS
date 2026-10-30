package server

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/zhouchenh/secDNS/internal/recordset"
	"github.com/zhouchenh/secDNS/internal/recordstore"
)

// gatewayRemovalFixture is a record gateway in front of an authority that behaves like the
// older DNS-unit build: it rejects any body carrying confirm_removals (it does not know the
// field) and otherwise serves a real versioned memory store with targeted RRset writes.
type gatewayRemovalFixture struct {
	t         *testing.T
	store     *recordstore.VersionedStore
	gateway   *HTTPAdminServer
	remote    *httptest.Server
	mu        sync.Mutex
	gets      int
	posts     []string
	headers   []string
	brokenGET bool
}

func newGatewayRemovalFixture(t *testing.T, records int) *gatewayRemovalFixture {
	t.Helper()
	store, err := recordstore.NewVersionedMemory(recordstore.Enrollment{RulesetID: "r", LineageID: "l"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	var seed []recordset.Record
	for i := 1; i <= records; i++ {
		seed = append(seed, recordset.Record{Name: fmt.Sprintf("g%d.invalid.", i), Type: "A", Values: []string{fmt.Sprintf("192.0.2.%d", i)}, TTLSeconds: 60})
	}
	if _, err = store.Replace(recordstore.Expected{RulesetID: "r", LineageID: "l", Revision: 1}, "seed", seed); err != nil {
		t.Fatal(err)
	}
	f := &gatewayRemovalFixture{t: t, store: store}
	upstream := &HTTPAdminServer{Token: strings.Repeat("u", 32), versioned: store}
	f.remote = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		if r.Method == "GET" {
			f.gets++
			broken := f.brokenGET
			f.mu.Unlock()
			if broken {
				w.WriteHeader(503)
				w.Write([]byte(`{"error":"snapshot_unavailable"}`))
				return
			}
			upstream.routes().ServeHTTP(w, r)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		f.posts = append(f.posts, string(raw))
		f.headers = append(f.headers, strings.Join(r.Header.Values(confirmRemovalsHeader), ","))
		f.mu.Unlock()
		if strings.Contains(string(raw), "confirm_removals") {
			w.WriteHeader(400)
			w.Write([]byte(`{"error":"invalid_snapshot_request"}`))
			return
		}
		// Present the request exactly as an older authority sees it: no confirmation header.
		r.Header.Del(confirmRemovalsHeader)
		r.Body = io.NopCloser(strings.NewReader(string(raw)))
		upstream.routes().ServeHTTP(w, r)
	}))
	t.Cleanup(f.remote.Close)
	f.gateway = &HTTPAdminServer{RecordAuthorityURL: f.remote.URL + "/admin", recordAuthorityCredential: upstream.Token}
	return f
}

func (f *gatewayRemovalFixture) post(path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/admin"+path, strings.NewReader(body))
	w := httptest.NewRecorder()
	f.gateway.forwardRecordRequest(w, r, "POST", path)
	return w
}

func (f *gatewayRemovalFixture) forwardedCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.posts)
}

func (f *gatewayRemovalFixture) last() (string, string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.posts[len(f.posts)-1], f.headers[len(f.headers)-1]
}

func (f *gatewayRemovalFixture) revision() (uint64, int) {
	view, err := f.store.Acquire()
	if err != nil {
		f.t.Fatal(err)
	}
	return view.Metadata().Revision, len(view.Records())
}

func gatewayRecords(names ...int) string {
	var out []string
	for _, i := range names {
		out = append(out, fmt.Sprintf(`{"name":"g%d.invalid.","type":"A","values":["192.0.2.%d"],"ttl_seconds":60}`, i, i))
	}
	return "[" + strings.Join(out, ",") + "]"
}

func gatewayReplacement(revision, op, records, extra string) string {
	return `{"expected":{"ruleset_id":"r","lineage_id":"l","revision":"` + revision + `"},"operation_id":"` + op + `","records":` + records + extra + `}`
}

func gatewayDeletion(revision, op, name, extra string) string {
	return `{"expected":{"ruleset_id":"r","lineage_id":"l","revision":"` + revision + `"},"operation_id":"` + op + `","action":"delete","key":{"name":"` + name + `","type":"A"}` + extra + `}`
}

// Slice 2 (C20 remainder, review R2/R4): the record gateway requires a confirmation for every
// write that removes records, on every removal path, and refuses before forwarding anything.
func TestRecordGatewayRequiresConfirmationForEveryRemoval(t *testing.T) {
	t.Run("plain replacement and multi-delete", func(t *testing.T) {
		f := newGatewayRemovalFixture(t, 4)
		for _, c := range []struct{ name, body, code string }{
			// one record removed, no count stated (an older or third-party client)
			{"single removal unstated", gatewayReplacement("2", "p1", gatewayRecords(1, 2, 3), ""), "removal_confirmation_required"},
			// a multi-delete: two removed, no count stated
			{"multi-delete unstated", gatewayReplacement("2", "p2", gatewayRecords(1, 2), ""), "removal_confirmation_required"},
			// every record removed, no count stated
			{"remove all unstated", gatewayReplacement("2", "p3", `[]`, ""), "removal_confirmation_required"},
			{"wrong count", gatewayReplacement("2", "p4", gatewayRecords(1, 2), `,"confirm_removals":1`), "removal_confirmation_mismatch"},
			{"count on an additive replacement", gatewayReplacement("2", "p5", gatewayRecords(1, 2, 3, 4, 5), `,"confirm_removals":1`), "removal_confirmation_mismatch"},
		} {
			w := f.post("/snapshot", c.body)
			if w.Code != 409 || !strings.Contains(w.Body.String(), c.code) {
				t.Fatalf("%s: want 409 %s, got %d %s", c.name, c.code, w.Code, w.Body.String())
			}
		}
		if n := f.forwardedCount(); n != 0 {
			t.Fatalf("refused removals reached the authority: %d", n)
		}
		if rev, n := f.revision(); rev != 2 || n != 4 {
			t.Fatalf("store changed: revision %d, %d records", rev, n)
		}
		// confirmed multi-delete: forwarded with the field moved into the header
		w := f.post("/snapshot", gatewayReplacement("2", "p6", gatewayRecords(1, 2), `,"confirm_removals":2`))
		if w.Code != 200 {
			t.Fatalf("confirmed multi-delete: %d %s", w.Code, w.Body.String())
		}
		body, header := f.last()
		if strings.Contains(body, "confirm_removals") || header != "2" {
			t.Fatalf("forwarded %q with header %q", body, header)
		}
		if rev, n := f.revision(); rev != 3 || n != 2 {
			t.Fatalf("confirmed multi-delete not applied: revision %d, %d records", rev, n)
		}
		// an additive replacement needs no count and is forwarded byte-for-byte
		additive := gatewayReplacement("3", "p7", gatewayRecords(1, 2, 9), "")
		if w = f.post("/snapshot", additive); w.Code != 200 {
			t.Fatalf("additive: %d %s", w.Code, w.Body.String())
		}
		if body, header = f.last(); body != additive || header != "" {
			t.Fatalf("additive forwarded %q header %q", body, header)
		}
		// A stale expected revision is left to the authority's CAS: forwarded, refused there.
		before := f.forwardedCount()
		if w = f.post("/snapshot", gatewayReplacement("2", "p8", gatewayRecords(1), "")); w.Code != 409 || !strings.Contains(w.Body.String(), "revision_conflict") || f.forwardedCount() != before+1 {
			t.Fatalf("stale replacement: %d %s", w.Code, w.Body.String())
		}
		// The idempotent replay of the committed multi-delete keeps returning its receipt.
		if w = f.post("/snapshot", gatewayReplacement("2", "p6", gatewayRecords(1, 2), `,"confirm_removals":2`)); w.Code != 200 {
			t.Fatalf("replay of a confirmed removal: %d %s", w.Code, w.Body.String())
		}
		if rev, n := f.revision(); rev != 4 || n != 3 {
			t.Fatalf("final state: revision %d, %d records", rev, n)
		}
	})
	t.Run("rrset deletion", func(t *testing.T) {
		f := newGatewayRemovalFixture(t, 3)
		for _, c := range []struct{ name, body, code string }{
			{"existing record unstated", gatewayDeletion("2", "d1", "g1.invalid.", ""), "removal_confirmation_required"},
			{"existing record stated 0", gatewayDeletion("2", "d2", "G1.invalid", `,"confirm_removals":0`), "removal_confirmation_mismatch"},
			{"absent record stated 1", gatewayDeletion("2", "d3", "absent.invalid.", `,"confirm_removals":1`), "removal_confirmation_mismatch"},
		} {
			w := f.post("/snapshot/rrset", c.body)
			if w.Code != 409 || !strings.Contains(w.Body.String(), c.code) {
				t.Fatalf("%s: want 409 %s, got %d %s", c.name, c.code, w.Code, w.Body.String())
			}
		}
		for _, bad := range []string{
			gatewayDeletion("2", "d4", "g1.invalid.", `,"confirm_removals":2`),
			gatewayDeletion("2", "d5", "g1.invalid.", `,"confirm_removals":"1"`),
			`{"expected":{"ruleset_id":"r","lineage_id":"l","revision":"2"},"operation_id":"d6","action":"upsert","record":{"name":"g1.invalid.","type":"A","values":["192.0.2.1"],"ttl_seconds":1},"confirm_removals":0}`,
			`{"expected":`,
		} {
			if w := f.post("/snapshot/rrset", bad); w.Code != 400 || !strings.Contains(w.Body.String(), "invalid_snapshot_request") {
				t.Fatalf("malformed %s: %d %s", bad, w.Code, w.Body.String())
			}
		}
		if n := f.forwardedCount(); n != 0 {
			t.Fatalf("refused deletions reached the authority: %d", n)
		}
		w := f.post("/snapshot/rrset", gatewayDeletion("2", "d7", "g1.invalid.", `,"confirm_removals":1`))
		if w.Code != 200 {
			t.Fatalf("confirmed deletion: %d %s", w.Code, w.Body.String())
		}
		body, header := f.last()
		if strings.Contains(body, "confirm_removals") || header != "1" {
			t.Fatalf("forwarded %q header %q", body, header)
		}
		if rev, n := f.revision(); rev != 3 || n != 2 {
			t.Fatalf("deletion not applied: revision %d, %d records", rev, n)
		}
		// deleting an absent key removes nothing: no count needed, forwarded unchanged
		absent := gatewayDeletion("3", "d8", "absent.invalid.", "")
		if w = f.post("/snapshot/rrset", absent); w.Code != 200 {
			t.Fatalf("absent deletion: %d %s", w.Code, w.Body.String())
		}
		if body, _ = f.last(); body != absent {
			t.Fatalf("absent deletion forwarded %q", body)
		}
		// an upsert removes nothing and needs no pre-check read
		f.mu.Lock()
		gets := f.gets
		f.mu.Unlock()
		upsert := `{"expected":{"ruleset_id":"r","lineage_id":"l","revision":"4"},"operation_id":"u1","action":"upsert","record":{"name":"g2.invalid.","type":"A","values":["192.0.2.22"],"ttl_seconds":1}}`
		if w = f.post("/snapshot/rrset", upsert); w.Code != 200 {
			t.Fatalf("upsert: %d %s", w.Code, w.Body.String())
		}
		f.mu.Lock()
		if f.gets != gets {
			t.Error("upsert made a pre-check read")
		}
		f.mu.Unlock()
		if body, _ = f.last(); body != upsert {
			t.Fatalf("upsert forwarded %q", body)
		}
	})
	t.Run("exact import", func(t *testing.T) {
		f := newGatewayRemovalFixture(t, 3)
		records := gatewayRecords(1)
		parsed, err := recordset.ParseReplacement([]byte(gatewayReplacement("2", "x", records, "")))
		if err != nil {
			t.Fatal(err)
		}
		candidate, err := recordset.New("r", "l", 2, parsed.Records)
		if err != nil {
			t.Fatal(err)
		}
		prov := fmt.Sprintf(`,"operator_supplied_provenance":{"profile":"%s","source_sha256":"%s","content_sha256":"%s"}`, recordset.RouterOSExactExplicitProfile, strings.Repeat("e", 64), candidate.Metadata().ContentSHA256)
		if w := f.post("/snapshot", gatewayReplacement("2", "x1", records, prov)); w.Code != 409 || !strings.Contains(w.Body.String(), "removal_confirmation_required") {
			t.Fatalf("unconfirmed exact import: %d %s", w.Code, w.Body.String())
		}
		if f.forwardedCount() != 0 {
			t.Fatal("refused import reached the authority")
		}
		if w := f.post("/snapshot", gatewayReplacement("2", "x2", records, prov+`,"confirm_removals":2`)); w.Code != 200 {
			t.Fatalf("confirmed exact import: %d %s", w.Code, w.Body.String())
		}
	})
	t.Run("authority unreachable for the pre-check", func(t *testing.T) {
		f := newGatewayRemovalFixture(t, 3)
		f.mu.Lock()
		f.brokenGET = true
		f.mu.Unlock()
		for _, c := range []struct{ path, body string }{
			{"/snapshot", gatewayReplacement("2", "a1", gatewayRecords(1), `,"confirm_removals":2`)},
			{"/snapshot", gatewayReplacement("2", "a2", gatewayRecords(1, 2, 3, 4), "")},
			{"/snapshot/rrset", gatewayDeletion("2", "a3", "g1.invalid.", `,"confirm_removals":1`)},
		} {
			w := f.post(c.path, c.body)
			// definitive: refused before forwarding, distinct from an uncertain 502
			if w.Code != 503 || !strings.Contains(w.Body.String(), "removal_check_unavailable") {
				t.Fatalf("%s: %d %s", c.path, w.Code, w.Body.String())
			}
		}
		if f.forwardedCount() != 0 {
			t.Fatal("a write was forwarded without its removal check")
		}
		if rev, n := f.revision(); rev != 2 || n != 3 {
			t.Fatalf("store changed: revision %d, %d records", rev, n)
		}
	})
	t.Run("unparseable bodies are refused, not forwarded", func(t *testing.T) {
		f := newGatewayRemovalFixture(t, 2)
		for _, body := range []string{`{`, `{"expected":{"ruleset_id":"r","lineage_id":"l","revision":"2"},"operation_id":"z","records":[],"extra":1}`, `{"expected":{"ruleset_id":"r","lineage_id":"l","revision":"2"},"operation_id":"z","records":[],"confirm_removals":-1}`} {
			if w := f.post("/snapshot", body); w.Code != 400 || !strings.Contains(w.Body.String(), "invalid_snapshot_request") {
				t.Fatalf("%s: %d %s", body, w.Code, w.Body.String())
			}
		}
		if f.forwardedCount() != 0 {
			t.Fatal("unparseable body forwarded")
		}
	})
}

// A current authority checks an RRset deletion's stated count from the body or from the
// gateway header; an unstated deletion keeps working there (the gateway is the gate).
func TestRRsetDeletionRemovalConfirmationAuthority(t *testing.T) {
	h := &HTTPAdminServer{Token: testToken}
	bindRRsetTest(t, h)
	seed := do(h, "POST", "/admin/snapshot/rrset", testToken, rrsetBody)
	if seed.Code != 200 {
		t.Fatal(seed.Code, seed.Body.String())
	}
	post := func(body string, header ...string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/admin/snapshot/rrset", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+testToken)
		r.Header.Set("Content-Type", "application/json")
		for _, v := range header {
			r.Header.Add(confirmRemovalsHeader, v)
		}
		w := httptest.NewRecorder()
		h.routes().ServeHTTP(w, r)
		return w
	}
	del := func(op, extra string) string {
		return `{"expected":{"ruleset_id":"r","lineage_id":"l","revision":"2"},"operation_id":"` + op + `","action":"delete","key":{"name":"x.invalid.","type":"A"}` + extra + `}`
	}
	if w := post(del("a", `,"confirm_removals":0`)); w.Code != 409 || !strings.Contains(w.Body.String(), "removal_confirmation_mismatch") {
		t.Fatal("wrong body count", w.Code, w.Body.String())
	}
	if w := post(del("b", ""), "0"); w.Code != 409 {
		t.Fatal("wrong header count", w.Code)
	}
	for _, bad := range [][]string{{"x"}, {"2"}, {"1", "1"}} {
		if w := post(del("c", ""), bad...); w.Code != 400 {
			t.Fatalf("header %v: %d", bad, w.Code)
		}
	}
	upsert := strings.Replace(strings.Replace(rrsetBody, `"revision":"1"`, `"revision":"2"`, 1), `"op"`, `"u"`, 1)
	if w := post(upsert, "0"); w.Code != 400 {
		t.Fatal("upsert with a removal header", w.Code)
	}
	if w := post(del("d", ""), "1"); w.Code != 200 {
		t.Fatal("right header count", w.Code, w.Body.String())
	}
	view, _ := h.versioned.Acquire()
	if view.Metadata().Revision != 3 || len(view.Records()) != 0 {
		t.Fatalf("deletion: revision %d, %d records", view.Metadata().Revision, len(view.Records()))
	}
	// replaying the committed deletion returns its receipt (the generation has moved on)
	if w := post(del("d", `,"confirm_removals":1`)); w.Code != 200 {
		t.Fatal("replay", w.Code, w.Body.String())
	}
}

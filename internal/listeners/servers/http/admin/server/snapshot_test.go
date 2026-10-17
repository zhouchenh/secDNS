package server

import (
	"encoding/json"
	"errors"
	"github.com/zhouchenh/secDNS/internal/recordset"
	"github.com/zhouchenh/secDNS/internal/recordstore"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestSnapshotAPIBothBackends(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			var v *recordstore.VersionedStore
			var e error
			enrollment := recordstore.Enrollment{RulesetID: "r", LineageID: "l"}
			if backend == "memory" {
				v, e = recordstore.NewVersionedMemory(enrollment)
			} else {
				v, e = recordstore.OpenVersionedSQLite(filepath.Join(t.TempDir(), "db"), enrollment)
			}
			if e != nil {
				t.Fatal(e)
			}
			t.Cleanup(func() { _ = v.Close() })
			h := &HTTPAdminServer{Token: testToken, versioned: v, UI: true}
			body := `{"expected":{"ruleset_id":"r","lineage_id":"l","revision":"1"},"operation_id":"op","records":[{"name":"x.invalid.","type":"A","values":["192.0.2.1"],"ttl_seconds":0,"expires_at":"2000-01-01T00:00:00.123456789Z"}]}`
			if r := do(h, "GET", "/admin/snapshot", "", ""); r.Code != 401 {
				t.Fatal(r.Code)
			}
			first := do(h, "POST", "/admin/snapshot", testToken, body)
			if first.Code != 200 {
				t.Fatal(first.Code, first.Body.String())
			}
			get := do(h, "GET", "/admin/snapshot", testToken, "")
			s, e := recordset.Parse(get.Body.Bytes())
			if e != nil || len(s.Records()) != 1 || s.Metadata().Revision != 2 {
				t.Fatal(e, get.Body.String())
			}
			second := strings.ReplaceAll(strings.ReplaceAll(body, `"revision":"1"`, `"revision":"2"`), `"operation_id":"op"`, `"operation_id":"second"`)
			if r := do(h, "POST", "/admin/snapshot", testToken, second); r.Code != 200 {
				t.Fatal(r.Code)
			}
			replay := do(h, "POST", "/admin/snapshot", testToken, body)
			if replay.Body.String() != first.Body.String() {
				t.Fatal("replay receipt changed")
			}
			for _, bad := range []string{strings.Replace(body, `"operation_id":"op"`, `"operation_id":"stale"`, 1), strings.Replace(body, `192.0.2.1`, `192.0.2.2`, 1)} {
				if r := do(h, "POST", "/admin/snapshot", testToken, bad); r.Code != 409 {
					t.Fatal(r.Code)
				}
			}
			for _, method := range []string{"GET", "POST", "DELETE"} {
				path := "/admin/records"
				if method == "DELETE" {
					path += "/x.invalid./A"
				}
				if r := do(h, method, path, testToken, body); r.Code != 409 {
					t.Fatal("legacy bypass", r.Code)
				}
			}
			for _, path := range []string{"/admin/ui", "/admin/ui/", "/admin/ui/app.js", "/admin/ui/style.css"} {
				if r := do(h, "GET", path, testToken, ""); r.Code != 404 {
					t.Fatal("editor exposed", path, r.Code)
				}
			}
			if r := do(h, "POST", "/admin/snapshot", testToken, strings.Repeat(" ", recordset.MaxBytes+1)); r.Code != 413 {
				t.Fatal(r.Code)
			}
			if r := do(h, "POST", "/admin/snapshot", testToken, `{"expected":null}`); r.Code != 400 {
				t.Fatal(r.Code)
			}
			if e = v.Close(); e != nil {
				t.Fatal(e)
			}
			for _, method := range []string{"GET", "POST"} {
				r := do(h, method, "/admin/snapshot", testToken, body)
				if r.Code != 503 {
					t.Fatal(r.Code)
				}
				var out map[string]string
				if json.Unmarshal(r.Body.Bytes(), &out) != nil || out["error"] != "snapshot_unavailable" {
					t.Fatal(r.Body.String())
				}
			}
		})
	}
}

func TestSnapshotErrorMappings(t *testing.T) {
	for _, tc := range []struct {
		err    error
		status int
		code   string
	}{
		{recordstore.ErrIdentity, 409, "identity_conflict"}, {recordstore.ErrRevisionConflict, 409, "revision_conflict"}, {recordstore.ErrOperationConflict, 409, "operation_conflict"}, {recordstore.ErrReceiptCapacity, 409, "receipt_capacity"}, {recordstore.ErrRevisionOverflow, 409, "revision_exhausted"}, {recordstore.ErrVersionedStorage, 503, "snapshot_unavailable"}, {errors.New("private backend detail"), 503, "snapshot_unavailable"},
	} {
		w := httptest.NewRecorder()
		snapshotError(w, tc.err)
		var body map[string]string
		if json.Unmarshal(w.Body.Bytes(), &body) != nil || w.Code != tc.status || body["error"] != tc.code {
			t.Fatal(w.Code, w.Body.String())
		}
	}
}
func TestSnapshotPostAuthenticationAndIdentity(t *testing.T) {
	v, e := recordstore.NewVersionedMemory(recordstore.Enrollment{RulesetID: "r", LineageID: "l"})
	if e != nil {
		t.Fatal(e)
	}
	defer v.Close()
	h := &HTTPAdminServer{Token: testToken, versioned: v}
	body := `{"expected":{"ruleset_id":"wrong","lineage_id":"l","revision":"1"},"operation_id":"op","records":[]}`
	for _, tc := range []struct {
		token  string
		status int
	}{{"", 401}, {"wrong", 403}, {testToken, 409}} {
		r := do(h, "POST", "/admin/snapshot", tc.token, body)
		if r.Code != tc.status {
			t.Fatal(r.Code)
		}
		if tc.status == 409 && !strings.Contains(r.Body.String(), "identity_conflict") {
			t.Fatal(r.Body.String())
		}
	}
	view, e := v.Acquire()
	if e != nil || view.Metadata().Revision != 1 || len(view.Records()) != 0 {
		t.Fatal("rejected request mutated state", e)
	}
}

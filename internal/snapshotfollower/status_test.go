package snapshotfollower

import (
	"context"
	"github.com/zhouchenh/secDNS/internal/recordstore"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestStatusContactNoChangeAndRetainedGeneration(t *testing.T) {
	mode := 0
	wire := testSnapshot(t, 3, "192.0.2.3")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mode == 1 {
			w.WriteHeader(304)
			return
		}
		if mode == 2 {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("ETag", `"three"`)
		_, _ = w.Write(wire)
	}))
	defer server.Close()
	store, _ := recordstore.NewFollowerMemory(testEnrollment)
	defer store.Close()
	worker, e := newWithClient(testConfig(server.URL, filepath.Join(t.TempDir(), "unused.db")), store, server.Client())
	if e != nil {
		t.Fatal(e)
	}
	now := time.Unix(1700000000, 0)
	worker.now = func() time.Time { return now }
	if s := worker.Status(); s.StoreState != "not_ready" || !s.LastContact.IsZero() {
		t.Fatal(s)
	}
	etag, ready, category := worker.fetch(context.Background(), "", false)
	if category != "" || !ready {
		t.Fatal(category)
	}
	first := worker.Status()
	mode = 1
	now = now.Add(time.Minute)
	_, _, category = worker.fetch(context.Background(), etag, true)
	if category != "" {
		t.Fatal(category)
	}
	next := worker.Status()
	if !next.LastSuccess.Equal(first.LastSuccess) || !next.LastContact.Equal(now) || next.Revision != 3 {
		t.Fatal(next)
	}
	mode = 2
	now = now.Add(time.Minute)
	_, _, category = worker.fetch(context.Background(), etag, true)
	worker.setFailure(category)
	failed := worker.Status()
	if failed.ErrorCategory != "authentication" || !failed.LastContact.Equal(next.LastContact) || failed.StoreState != "available" || failed.Revision != 3 {
		t.Fatal(failed)
	}
	_ = store.Close()
	if worker.Status().StoreState != "unavailable" {
		t.Fatal("closed store advertised available")
	}
}

func TestStatusStreamContactRequiresValidatedHeaders(t *testing.T) {
	valid := false
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if valid {
			w.Header().Set("Content-Type", "text/event-stream")
		} else {
			w.Header().Set("Content-Type", "text/plain")
		}
		_, _ = w.Write([]byte(": comment\n\n"))
	}))
	defer server.Close()
	store, _ := recordstore.NewFollowerMemory(testEnrollment)
	defer store.Close()
	if _, e := store.Accept(testEnrollment, testSnapshot(t, 1, "192.0.2.1")); e != nil {
		t.Fatal(e)
	}
	worker, e := newWithClient(testConfig(server.URL, filepath.Join(t.TempDir(), "unused.db")), store, server.Client())
	if e != nil {
		t.Fatal(e)
	}
	now := time.Unix(1700000000, 0)
	worker.now = func() time.Time { return now }
	_, _ = worker.stream(context.Background())
	if !worker.Status().LastContact.IsZero() {
		t.Fatal("invalid stream counted as contact")
	}
	valid = true
	_, _ = worker.stream(context.Background())
	s := worker.Status()
	if !s.LastContact.Equal(now) || !s.LastSuccess.IsZero() || s.Revision != 1 {
		t.Fatal(s)
	}
}

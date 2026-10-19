package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zhouchenh/secDNS/internal/recordstore"
)

func TestHumanSchema4Browser(t *testing.T) {
	if os.Getenv("ADMINAUTH_SCHEMA4_BROWSER") != "1" {
		t.Skip("local installed Chromium fixture only")
	}
	h, grant := humanTestServer(t)
	h.UI = true
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	dbpath := filepath.Join(dir, "records.db")
	enrollment := recordstore.Enrollment{RulesetID: "human-browser", LineageID: "synthetic"}
	v, e := recordstore.OpenVersionedSQLite(dbpath, enrollment)
	if e != nil {
		t.Fatal(e)
	}
	if e = v.Close(); e != nil {
		t.Fatal(e)
	}
	if e = recordstore.EnableRRsetMutationsSQLite(dbpath, enrollment); e != nil {
		t.Fatal(e)
	}
	v, e = recordstore.OpenVersionedSQLite(dbpath, enrollment)
	if e != nil {
		t.Fatal(e)
	}
	defer v.Close()
	h.versioned = v
	var seconds atomic.Int64
	seconds.Store(time.Now().Unix())
	h.agent.now = func() time.Time { return time.Unix(seconds.Load(), 0) }
	routes := h.routes()
	var dropped atomic.Bool
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/__test-clock" {
			if r.Method == "POST" {
				if r.URL.Query().Get("expire") == "1" {
					seconds.Add(13 * 60 * 60)
				} else {
					seconds.Add(30)
				}
			}
			json.NewEncoder(w).Encode(map[string]int64{"now": seconds.Load()})
			return
		}
		if r.Method == "POST" && r.URL.Path == "/admin/snapshot/rrset" {
			recorder := httptest.NewRecorder()
			routes.ServeHTTP(recorder, r)
			if recorder.Code == http.StatusOK && dropped.CompareAndSwap(false, true) {
				connection, buffered, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				buffered.WriteString("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100\r\nConnection: close\r\n\r\n{")
				buffered.Flush()
				connection.Close()
				return
			}
			for k, values := range recorder.Header() {
				w.Header()[k] = values
			}
			w.WriteHeader(recorder.Code)
			w.Write(recorder.Body.Bytes())
			return
		}
		routes.ServeHTTP(w, r)
	})
	ts := httptest.NewUnstartedServer(handler)
	h.agent.origin = "https://" + ts.Listener.Addr().String()
	ts.Config.ErrorLog = log.New(io.Discard, "", 0)
	ts.StartTLS()
	defer ts.Close()
	script, e := filepath.Abs("../../../../../../scripts/test-human-schema4-browser.cjs")
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "node", script)
	cmd.Env = append(os.Environ(), "HUMAN_TEST_URL="+ts.URL+"/admin/ui/", "HUMAN_TEST_GRANT="+grant)
	if out, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("human browser: %v\n%s", e, out)
	} else {
		t.Log(string(out))
	}
	ts.Close()
	if !dropped.Load() {
		t.Fatal("successful response was not dropped")
	}
	before, e := v.Acquire()
	if e != nil {
		t.Fatal(e)
	}
	if before.Metadata().Revision != 3 || len(before.Records()) != 13 {
		t.Fatal("unexpected durable operation count")
	}
	if e = v.Close(); e != nil {
		t.Fatal(e)
	}
	reopened, e := recordstore.OpenVersionedSQLite(dbpath, enrollment)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	after, e := reopened.Acquire()
	if e != nil {
		t.Fatal(e)
	}
	if after.Metadata() != before.Metadata() || !reflect.DeepEqual(after.Records(), before.Records()) {
		t.Fatal("snapshot changed after restart")
	}
	if e = reopened.Close(); e != nil {
		t.Fatal(e)
	}
	db, e := sql.Open("sqlite", "file:"+filepath.ToSlash(dbpath)+"?mode=ro")
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	var count, targeted int
	if e = db.QueryRow("SELECT count(*), count(rrset_request) FROM operation_receipts").Scan(&count, &targeted); e != nil {
		t.Fatal(e)
	}
	if count != 2 || targeted != 1 {
		t.Fatal("CSRF refusals/retry created extra receipts")
	}

}

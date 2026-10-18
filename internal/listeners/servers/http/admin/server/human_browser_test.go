package server

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zhouchenh/secDNS/internal/recordstore"
)

func TestHumanBrowser(t *testing.T) {
	if os.Getenv("ADMINAUTH_BROWSER") != "1" {
		t.Skip("local installed Chromium fixture only")
	}
	h, grant := humanTestServer(t)
	h.UI = true
	v, e := recordstore.NewVersionedMemory(recordstore.Enrollment{RulesetID: "human-browser", LineageID: "synthetic"})
	if e != nil {
		t.Fatal(e)
	}
	defer v.Close()
	h.versioned = v
	var seconds atomic.Int64
	seconds.Store(time.Now().Unix())
	h.agent.now = func() time.Time { return time.Unix(seconds.Load(), 0) }
	routes := h.routes()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/__test-clock" {
			if r.Method == "POST" {
				seconds.Add(30)
			}
			json.NewEncoder(w).Encode(map[string]int64{"now": seconds.Load()})
			return
		}
		routes.ServeHTTP(w, r)
	})
	ts := httptest.NewUnstartedServer(handler)
	h.agent.origin = "https://" + ts.Listener.Addr().String()
	ts.Config.ErrorLog = log.New(io.Discard, "", 0)
	ts.StartTLS()
	defer ts.Close()
	script, e := filepath.Abs("../../../../../../scripts/test-human-session-browser.cjs")
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
}

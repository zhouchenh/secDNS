package server

import (
	"context"
	"github.com/zhouchenh/secDNS/internal/adminauth"
	"github.com/zhouchenh/secDNS/internal/recordstore"
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
)

// Opt-in only: the installed browser talks to this temporary TLS listener and
// synthetic records. No persistent service, external resolver or CA is changed.
func TestAgentBrowser(t *testing.T) {
	if os.Getenv("ADMINAUTH_BROWSER") != "1" {
		t.Skip("set ADMINAUTH_BROWSER=1 with existing Playwright")
	}
	h, token := agentTestServer(t, []adminauth.Scope{adminauth.UIView, adminauth.RecordsRead, adminauth.RecordsWrite, adminauth.RouterOSPreview})
	grant, e := h.agent.store.CreateBootstrap(adminauth.BootstrapEnvelope{Scopes: []adminauth.Scope{adminauth.UIView, adminauth.RecordsRead}}, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	readToken, _, e := h.agent.store.BootstrapIssueAgent(grant, adminauth.CredentialRequest{Name: "read-only", Scopes: []adminauth.Scope{adminauth.UIView, adminauth.RecordsRead}}, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	v, e := recordstore.NewVersionedMemory(recordstore.Enrollment{RulesetID: "browser", LineageID: "synthetic"})
	if e != nil {
		t.Fatal(e)
	}
	defer v.Close()
	h.versioned = v
	h.UI = true
	h.Path = "/admin"
	routes := h.routes()
	var dropped atomic.Bool
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && (r.URL.Path == "/admin/snapshot" || r.URL.Path == "/admin/snapshot/rrset") && dropped.CompareAndSwap(false, true) {
			record := httptest.NewRecorder()
			routes.ServeHTTP(record, r)
			if record.Code != 200 {
				w.WriteHeader(record.Code)
				w.Write(record.Body.Bytes())
				return
			}
			w.WriteHeader(http.StatusBadGateway)
			w.Write([]byte(`{"error":"synthetic_lost_acknowledgement"}`))
			return
		}
		routes.ServeHTTP(w, r)
	})
	ts := httptest.NewUnstartedServer(handler)
	h.agent.origin = "https://" + ts.Listener.Addr().String()
	ts.Config.ErrorLog = log.New(io.Discard, "", 0)
	ts.StartTLS()
	defer ts.Close()
	alternate := httptest.NewServer(handler)
	defer alternate.Close()
	script, e := filepath.Abs("../../../../../../scripts/test-agent-session-browser.cjs")
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "node", script)
	command.Env = append(os.Environ(), "AGENT_TEST_URL="+ts.URL+"/admin/ui/", "AGENT_TEST_TOKEN="+token, "AGENT_TEST_READ_TOKEN="+readToken, "AGENT_TEST_ALTERNATE="+alternate.URL+"/admin/ui/")
	if output, e := command.CombinedOutput(); e != nil {
		t.Fatalf("synthetic browser: %v\n%s", e, output)
	} else {
		t.Log(string(output))
	}
}

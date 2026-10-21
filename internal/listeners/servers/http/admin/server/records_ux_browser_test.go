package server

import (
	"context"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/zhouchenh/secDNS/internal/recordstore"
)

// The entire account, record store and HTTP server are disposable. No adapter runs.
func TestRecordsImportUXBrowser(t *testing.T) {
	if os.Getenv("ADMINAUTH_BROWSER") != "1" {
		t.Skip("opt-in local Chromium")
	}
	h, session := nodeTestSetup(t)
	h.UI = true
	h.NodeAdapterExecutable = ""
	h.NodeAdapterScript = ""
	store, err := recordstore.NewVersionedMemory(recordstore.Enrollment{RulesetID: "ux-review", LineageID: "disposable"})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	h.versioned = store
	server := httptest.NewUnstartedServer(h.routes())
	h.agent.origin = "https://" + server.Listener.Addr().String()
	server.StartTLS()
	defer server.Close()
	script, _ := filepath.Abs("../../../../../../scripts/test-records-import-ux-browser.cjs")
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "node", script)
	cmd.Env = append(os.Environ(), "RECORDS_UX_URL="+server.URL, "RECORDS_UX_COOKIE="+session.Token)
	output, err := cmd.CombinedOutput()
	t.Log(string(output))
	if err != nil {
		t.Fatal(err)
	}
}

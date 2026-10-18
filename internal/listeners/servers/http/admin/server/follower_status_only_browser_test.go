package server

import (
	"context"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestFollowerStatusOnlyBrowser(t *testing.T) {
	if os.Getenv("ADMINAUTH_BROWSER") != "1" {
		t.Skip("set ADMINAUTH_BROWSER=1 with existing Playwright")
	}
	h := statusOnlyServer(t)
	if e := h.prepareRecordBinding(); e != nil {
		t.Fatal(e)
	}
	ts := httptest.NewServer(h.routes())
	defer ts.Close()
	script, e := filepath.Abs("../../../../../../scripts/test-follower-status-only-browser.cjs")
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "node", script)
	cmd.Env = append(os.Environ(), "FOLLOWER_ONLY_URL="+ts.URL+"/owned-static/ui/")
	b, e := cmd.CombinedOutput()
	if e != nil {
		t.Fatalf("browser: %v\n%s", e, b)
	}
	t.Log(string(b))
}

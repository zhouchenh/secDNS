package server

import (
	"github.com/zhouchenh/secDNS/internal/recordstore"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestWorkspaceRoutesBrowser(t *testing.T) {
	if os.Getenv("SECDNS_WORKSPACE_BROWSER") != "1" {
		t.Skip("opt-in synthetic browser")
	}
	mux := http.NewServeMux()
	legacy, _ := validationServer(t, false)
	legacy.UI = true
	legacy.Path = "/legacy"
	legacy.Token = "local-browser-test-only"
	mux.Handle("/legacy/", legacy.routes())
	v, e := recordstore.NewVersionedMemory(recordstore.Enrollment{RulesetID: "browser", LineageID: "synthetic"})
	if e != nil {
		t.Fatal(e)
	}
	defer v.Close()
	h := &HTTPAdminServer{Token: "local-browser-test-only", Path: "/versioned", UI: true, versioned: v}
	mux.Handle("/versioned/", h.routes())
	ts := httptest.NewServer(mux)
	defer ts.Close()
	root, _ := filepath.Abs("../../../../../..")
	cmd := exec.Command("node", filepath.Join(root, "scripts/test-workspace-routes-browser.cjs"))
	cmd.Env = append(os.Environ(), "WORKSPACE_URL="+ts.URL)
	out, e := cmd.CombinedOutput()
	t.Log(string(out))
	if e != nil {
		t.Fatal(e)
	}
}

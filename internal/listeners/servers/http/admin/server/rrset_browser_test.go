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

func TestRRsetEditorBrowser(t *testing.T) {
	if os.Getenv("SECDNS_RRSET_BROWSER") != "1" {
		t.Skip("opt-in local Playwright fixture")
	}
	mux := http.NewServeMux()
	for _, name := range []string{"old", "new"} {
		dir := t.TempDir()
		os.Chmod(dir, 0700)
		path := filepath.Join(dir, "records.db")
		e := recordstore.Enrollment{RulesetID: "r", LineageID: "l"}
		s, err := recordstore.OpenVersionedSQLite(path, e)
		if err != nil {
			t.Fatal(err)
		}
		if name == "new" {
			s.Close()
			if err = recordstore.EnableRRsetMutationsSQLite(path, e); err != nil {
				t.Fatal(err)
			}
			s, err = recordstore.OpenVersionedSQLite(path, e)
			if err != nil {
				t.Fatal(err)
			}
		}
		defer s.Close()
		h := &HTTPAdminServer{Token: "local-browser-test-only", Path: "/" + name, UI: true, versioned: s}
		mux.Handle("/"+name+"/", h.routes())
	}
	server := httptest.NewServer(mux)
	defer server.Close()
	root, err := filepath.Abs("../../../../../..")
	if err != nil {
		t.Fatal(err)
	}
	for _, script := range []string{"test-versioned-editor-browser.cjs", "test-versioned-rrset-browser.cjs"} {
		cmd := exec.Command("node", filepath.Join(root, "scripts", script))
		cmd.Env = append(os.Environ(), "RRSET_BROWSER_URL="+server.URL, "EDITOR_TEST_URL="+server.URL+"/old/ui/")
		out, err := cmd.CombinedOutput()
		t.Log(string(out))
		if err != nil {
			t.Fatal(err)
		}
	}
}

package server

import (
	"github.com/zhouchenh/secDNS/internal/recordstore"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestConsoleActualRoutes(t *testing.T) {
	for _, base := range []string{"/admin", "/custom/admin", ""} {
		t.Run(base, func(t *testing.T) {
			v, e := recordstore.NewVersionedMemory(recordstore.Enrollment{RulesetID: "r", LineageID: "l"})
			if e != nil {
				t.Fatal(e)
			}
			defer v.Close()
			h := &HTTPAdminServer{Token: testToken, UI: true, Path: base, versioned: v}
			if base == "" {
				h.Path = "/"
			}
			for _, route := range []string{"/ui/", "/ui/import-preview/"} {
				r := do(h, "GET", base+route, "", "")
				if r.Code != 200 {
					t.Fatal(route, r.Code)
				}
				body := r.Body.String()
				if !utf8.ValidString(body) || strings.ContainsRune(body, '\uFFFD') {
					t.Fatal("console page contains invalid or replacement UTF-8 text", route)
				}
				for _, want := range []string{`class="console-sidebar"`, `href="` + base + `/ui/console.css"`, `src="` + base + `/ui/console.js"`, `href="` + base + `/ui/"`, `href="` + base + `/ui/import-preview/"`} {
					if !strings.Contains(body, want) {
						t.Fatal("missing shell binding", want)
					}
				}
				if strings.Contains(body, "Local replication") {
					t.Fatal("unconfigured follower navigation")
				}
			}
			for _, asset := range []string{"console.css", "console.js"} {
				r := do(h, "GET", base+"/ui/"+asset, "", "")
				if r.Code != 200 || r.Header().Get("Content-Security-Policy") != editorCSP || r.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("asset safety")
				}
			}
			h.UI = false
			if r := do(h, "GET", base+"/ui/console.js", "", ""); r.Code != http.StatusNotFound {
				t.Fatal("UI disabled exposes shell")
			}
		})
	}
	h := statusOnlyServer(t)
	r := do(h, "GET", "/owned-static/ui/followers/", "", "")
	if r.Code != 200 {
		t.Fatal(r.Code)
	}
	body := r.Body.String()
	if !regexp.MustCompile(`aria-current="page"><svg[^>]*><path[^>]*/></svg><span>Local replication</span>`).MatchString(body) || strings.Contains(body, `>DNS records</span></a>`) || strings.Contains(body, `>Import records</span></a>`) || strings.Contains(body, `id="console-account"`) {
		t.Fatal("follower-only role navigation")
	}
	if r := do(h, "GET", "/owned-static/ui/console.css", "", ""); r.Code != 200 {
		t.Fatal("follower shell asset")
	}
}

func TestConsoleHandoffPreservesExistingMechanism(t *testing.T) {
	data, e := editorAssets.ReadFile("console_ui/console.js")
	if e != nil {
		t.Fatal(e)
	}
	for _, contract := range []string{`document.getElementById("open-import")`, `event.preventDefault();handoff.click();`} {
		if !strings.Contains(string(data), contract) {
			t.Fatal("missing existing handoff delegation", contract)
		}
	}
}

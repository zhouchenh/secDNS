package server

import (
	"github.com/zhouchenh/secDNS/internal/recordstore"
	"strings"
	"testing"
)

func TestVersionedEditorModeAndHeaders(t *testing.T) {
	for _, base := range []string{"/admin", "/custom/admin", ""} {
		t.Run(base, func(t *testing.T) {
			v, e := recordstore.NewVersionedMemory(recordstore.Enrollment{RulesetID: "r", LineageID: "l"})
			if e != nil {
				t.Fatal(e)
			}
			defer v.Close()
			h := &HTTPAdminServer{Token: testToken, versioned: v, Path: base}
			if base == "" {
				h.Path = "/"
			}
			for _, route := range []string{"/ui/", "/ui/app.js", "/ui/state.js", "/ui/style.css"} {
				if r := do(h, "GET", base+route, "", ""); r.Code != 404 {
					t.Fatal("default exposed")
				}
			}
			h.UI = true
			for _, route := range []string{"/ui/", "/ui/app.js", "/ui/state.js", "/ui/style.css"} {
				r := do(h, "GET", base+route, "", "")
				if r.Code != 200 {
					t.Fatal(route, r.Code)
				}
				for k, want := range map[string]string{"Content-Security-Policy": editorCSP, "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer"} {
					if r.Header().Get(k) != want {
						t.Fatal(k)
					}
				}
				if strings.Contains(r.Body.String(), testToken) {
					t.Fatal("token in assets")
				}
			}
			if r := do(h, "GET", base+"/ui/", "", ""); !strings.Contains(r.Body.String(), "DNS MANAGEMENT") {
				t.Fatal("wrong bundle")
			}
			if r := do(h, "GET", base+"/records", testToken, ""); r.Code != 409 {
				t.Fatal("CRUD enabled")
			}
			if r := do(h, "GET", base+"/snapshot", "", ""); r.Code != 401 {
				t.Fatal("auth bypass")
			}
			if r := do(h, "GET", base+"/ui/unknown", "", ""); r.Code != 404 {
				t.Fatal("unknown asset")
			}
		})
	}
	legacy := newServer(t, t.Name())
	legacy.UI = true
	if r := do(legacy, "GET", "/admin/ui/state.js", "", ""); r.Code != 404 {
		t.Fatal("versioned state leaked into legacy")
	}
}

package server

import (
	"net/http"
	"strings"
	"testing"
)

func TestEditorRoutesAndHeaders(t *testing.T) {
	for _, base := range []string{"/admin", "/custom/admin", ""} {
		t.Run(base, func(t *testing.T) {
			h := newServer(t, "editor"+base)
			h.Path = base
			if base == "" {
				h.Path = "/"
			}
			for _, route := range []string{"/ui/", "/ui/app.js", "/ui/console.css"} {
				if got := do(h, "GET", base+route, "", ""); got.Code != http.StatusNotFound {
					t.Fatalf("default editor exposed: %d", got.Code)
				}
			}
			h.UI = true
			for _, route := range []string{"/ui/", "/ui/app.js", "/ui/console.css"} {
				got := do(h, "GET", base+route, "", "")
				if got.Code != 200 {
					t.Fatalf("%s: %d", route, got.Code)
				}
				for key, want := range map[string]string{"Content-Security-Policy": editorCSP, "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer"} {
					if got.Header().Get(key) != want {
						t.Errorf("%s missing", key)
					}
				}
				if strings.Contains(got.Body.String(), testToken) {
					t.Fatal("configured token leaked")
				}
			}
			if got := do(h, "GET", base+"/ui", "", ""); got.Code != 303 || got.Header().Get("Location") != base+"/ui/" {
				t.Fatal("bad canonical redirect")
			}
			if got := do(h, "GET", base+"/ui/unknown", "", ""); got.Code != 404 {
				t.Fatal("unknown asset exposed")
			}
			for _, token := range []string{"", testToken} {
				got := do(h, "GET", base+"/records", token, "")
				want := 401
				if token != "" {
					want = 200
				}
				if got.Code != want || got.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("API auth/cache changed")
				}
			}
		})
	}
}

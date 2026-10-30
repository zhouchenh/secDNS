package server

import (
	"bytes"
	"embed"
	"net/http"
)

//go:embed ui/* versioned_ui/* preview_ui/* auth_ui/* follower_ui/* console_ui/*
var editorAssets embed.FS

const editorCSP = "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; connect-src 'self'; img-src data:; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

func editorHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Security-Policy", editorCSP)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
}

func (h *HTTPAdminServer) editorRoutes(mux *http.ServeMux, base string) {
	if len(h.followerStatusNames) > 0 {
		h.followerUIRoutes(mux, base)
	}
	for _, name := range []string{"agent.js", "human.js", "passkey.js"} {
		data, _ := editorAssets.ReadFile("auth_ui/" + name)
		mux.HandleFunc("GET "+base+"/auth/"+name, func(w http.ResponseWriter, r *http.Request) {
			editorHeaders(w)
			w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
			w.Write(data)
		})
	}
	mux.HandleFunc("GET "+base+"/ui", func(w http.ResponseWriter, r *http.Request) {
		editorHeaders(w)
		http.Redirect(w, r, base+"/ui/", http.StatusSeeOther)
	})
	assets := []struct{ route, file, contentType string }{
		{"/{$}", "index.html", "text/html; charset=utf-8"},
		{"/app.js", "app.js", "text/javascript; charset=utf-8"},
	}
	folder := "ui/"
	if h.versioned != nil || h.recordGatewayEnabled() {
		folder = "versioned_ui/"
		assets = append(assets, struct{ route, file, contentType string }{"/state.js", "state.js", "text/javascript; charset=utf-8"})
	}
	for _, asset := range assets {
		data, err := editorAssets.ReadFile(folder + asset.file)
		if err != nil {
			panic(err)
		} // Embedded assets are verified at build time.
		if asset.file == "index.html" {
			link := []byte(nil)
			if len(h.followerStatusNames) > 0 {
				link = []byte(`<p><a href="followers/" target="_blank" rel="noopener noreferrer">Local follower status</a> opens a separate read-only page.</p>`)
			}
			data = bytes.ReplaceAll(data, []byte("<!-- follower-status-link -->"), link)
			data = h.consolePage(data, base, "records")
		}
		ssoData := data
		if asset.file == "index.html" {
			ssoData = withoutLegacyTokenForm(data)
		}
		mux.HandleFunc("GET "+base+"/ui"+asset.route, func(w http.ResponseWriter, r *http.Request) {
			editorHeaders(w)
			w.Header().Set("Content-Type", asset.contentType)
			// The single sign-on path never receives a credential form, not even hidden.
			if h.trustedSSOAvailable(r) {
				_, _ = w.Write(ssoData)
				return
			}
			_, _ = w.Write(data)
		})
	}
}

// withoutLegacyImportToken does the same for the import page: the legacy token
// section is hidden and its password field becomes a hidden input with the same ID.
func withoutLegacyImportToken(page []byte) []byte {
	out := bytes.Replace(page, []byte(`<details id="legacy-import">`), []byte(`<details id="legacy-import" hidden>`), 1)
	return bytes.Replace(out, []byte(`<input id="token" type="password"`), []byte(`<input id="token" type="hidden"`), 1)
}

// withoutLegacyTokenForm neutralizes the legacy token access section on the
// records page served on the single sign-on path: the section is hidden and its
// password field becomes a hidden input (the element IDs the page script uses
// stay), so no credential entry field is ever delivered there.
func withoutLegacyTokenForm(page []byte) []byte {
	out := bytes.Replace(page, []byte(`<section id="login" class="card">`), []byte(`<section id="login" class="card" hidden>`), 1)
	return bytes.Replace(out, []byte(`<input id="token" type="password"`), []byte(`<input id="token" type="hidden"`), 1)
}

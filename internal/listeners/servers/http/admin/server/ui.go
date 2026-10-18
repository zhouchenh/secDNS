package server

import (
	"embed"
	"net/http"
)

//go:embed ui/* versioned_ui/* preview_ui/* auth_ui/*
var editorAssets embed.FS

const editorCSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

func editorHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Security-Policy", editorCSP)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
}

func (h *HTTPAdminServer) editorRoutes(mux *http.ServeMux, base string) {
	for _, name := range []string{"agent.js", "human.js", "auth.css"} {
		data, _ := editorAssets.ReadFile("auth_ui/" + name)
		mux.HandleFunc("GET "+base+"/auth/"+name, func(w http.ResponseWriter, r *http.Request) {
			editorHeaders(w)
			w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
			if name == "auth.css" {
				w.Header().Set("Content-Type", "text/css; charset=utf-8")
			}
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
		{"/style.css", "style.css", "text/css; charset=utf-8"},
	}
	folder := "ui/"
	if h.versioned != nil {
		folder = "versioned_ui/"
		assets = append(assets, struct{ route, file, contentType string }{"/state.js", "state.js", "text/javascript; charset=utf-8"})
	}
	for _, asset := range assets {
		data, err := editorAssets.ReadFile(folder + asset.file)
		if err != nil {
			panic(err)
		} // Embedded assets are verified at build time.
		mux.HandleFunc("GET "+base+"/ui"+asset.route, func(w http.ResponseWriter, r *http.Request) {
			editorHeaders(w)
			w.Header().Set("Content-Type", asset.contentType)
			_, _ = w.Write(data)
		})
	}
}

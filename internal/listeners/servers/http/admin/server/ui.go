package server

import (
	"embed"
	"net/http"
)

//go:embed ui/*
var editorAssets embed.FS

const editorCSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

func editorHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Security-Policy", editorCSP)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
}

func (h *HTTPAdminServer) editorRoutes(mux *http.ServeMux, base string) {
	mux.HandleFunc("GET "+base+"/ui", func(w http.ResponseWriter, r *http.Request) {
		editorHeaders(w)
		http.Redirect(w, r, base+"/ui/", http.StatusSeeOther)
	})
	for _, asset := range []struct{ route, file, contentType string }{
		{"/{$}", "index.html", "text/html; charset=utf-8"},
		{"/app.js", "app.js", "text/javascript; charset=utf-8"},
		{"/style.css", "style.css", "text/css; charset=utf-8"},
	} {
		data, err := editorAssets.ReadFile("ui/" + asset.file)
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

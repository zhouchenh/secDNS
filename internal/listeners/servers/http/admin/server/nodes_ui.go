package server

import (
	"bytes"
	"net/http"
)

func (h *HTTPAdminServer) nodeUIRoutes(mux *http.ServeMux, base string) {
	if !h.nodesEnabled() {
		return
	}
	for _, page := range []string{"nodes", "health", "routing"} {
		data, _ := editorAssets.ReadFile("console_ui/nodes.html")
		data = bytes.ReplaceAll(data, []byte("NODEPAGE"), []byte(page))
		data = h.consolePage(data, base, page)
		mux.HandleFunc("GET "+base+"/ui/"+page+"/{$}", func(w http.ResponseWriter, r *http.Request) {
			editorHeaders(w)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write(data)
		})
	}
	for _, asset := range []string{"nodes.js", "nodes-bgp.js", "nodes-health.js", "nodes.css"} {
		data, _ := editorAssets.ReadFile("console_ui/" + asset)
		mux.HandleFunc("GET "+base+"/ui/"+asset, func(w http.ResponseWriter, r *http.Request) {
			editorHeaders(w)
			kind := "text/javascript"
			if asset == "nodes.css" {
				kind = "text/css"
			}
			w.Header().Set("Content-Type", kind+"; charset=utf-8")
			w.Write(data)
		})
	}
}

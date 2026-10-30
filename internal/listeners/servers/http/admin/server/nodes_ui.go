package server

import (
	"bytes"
	"encoding/json"
	"html"
	"net/http"
)

// nodeInventoryEntry is what the node pages show about a node: its inventory ID and the
// addresses the BGP candidate check already pins for it. It comes from the same inventory
// the node API accepts (nodeIDs, nodeBGPIdentities); the page scripts hold no node names
// or addresses of their own.
type nodeInventoryEntry struct {
	ID       string `json:"id"`
	RouterID string `json:"router_id,omitempty"`
	IPv6     string `json:"ipv6,omitempty"`
}

func nodeInventory() []nodeInventoryEntry {
	out := make([]nodeInventoryEntry, 0, len(nodeIDs))
	for _, id := range nodeIDs {
		entry := nodeInventoryEntry{ID: id}
		if identity, ok := nodeBGPIdentities[id]; ok {
			entry.RouterID, entry.IPv6 = identity.IPv4, identity.IPv6
		}
		out = append(out, entry)
	}
	return out
}

func nodeInventoryAttribute() []byte {
	data, err := json.Marshal(nodeInventory())
	if err != nil {
		panic(err)
	}
	return []byte(html.EscapeString(string(data)))
}

func (h *HTTPAdminServer) nodeUIRoutes(mux *http.ServeMux, base string) {
	if !h.nodesEnabled() {
		return
	}
	inventory := nodeInventoryAttribute()
	for _, page := range []string{"nodes", "health", "routing"} {
		data, _ := editorAssets.ReadFile("console_ui/nodes.html")
		data = bytes.ReplaceAll(data, []byte("NODEPAGE"), []byte(page))
		data = bytes.ReplaceAll(data, []byte("NODEINVENTORY"), inventory)
		data = h.consolePage(data, base, page)
		mux.HandleFunc("GET "+base+"/ui/"+page+"/{$}", func(w http.ResponseWriter, r *http.Request) {
			editorHeaders(w)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write(data)
		})
	}
	for _, asset := range []string{"nodes.js", "nodes-bgp.js", "nodes-health.js"} {
		data, _ := editorAssets.ReadFile("console_ui/" + asset)
		mux.HandleFunc("GET "+base+"/ui/"+asset, func(w http.ResponseWriter, r *http.Request) {
			editorHeaders(w)
			w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
			w.Write(data)
		})
	}
}

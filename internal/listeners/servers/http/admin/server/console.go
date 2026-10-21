package server

import (
	"bytes"
	"html"
	"net/http"
)

func (h *HTTPAdminServer) consoleRoutes(mux *http.ServeMux, base string) {
	h.nodeUIRoutes(mux, base)
	for _, asset := range []struct{ name, kind string }{{"console.css", "text/css"}, {"console.js", "text/javascript"}} {
		data, err := editorAssets.ReadFile("console_ui/" + asset.name)
		if err != nil {
			panic(err)
		}
		mux.HandleFunc("GET "+base+"/ui/"+asset.name, func(w http.ResponseWriter, r *http.Request) {
			editorHeaders(w)
			w.Header().Set("Content-Type", asset.kind+"; charset=utf-8")
			w.Write(data)
		})
	}
}

// consolePage composes only navigation supported by this listener. It never adds APIs.
func (h *HTTPAdminServer) consolePage(data []byte, base, active string) []byte {
	escaped := html.EscapeString(base)
	links := ""
	link := func(path, label, id string) {
		current := ""
		if active == id {
			current = ` aria-current="page"`
		}
		links += `<a href="` + escaped + path + `"` + current + `>` + label + `</a>`
	}
	if !h.FollowerStatusOnly {
		link("/ui/", "DNS records", "records")
		link("/ui/import-preview/", "Import records", "import")
	}
	if h.nodesEnabled() {
		link("/ui/nodes/", "Nodes", "nodes")
		link("/ui/health/", "DNS health", "health")
		link("/ui/routing/", "Routing", "routing")
	}
	if len(h.followerStatusNames) > 0 {
		link("/ui/followers/", "Local replication", "followers")
	}
	role := "Record administration"
	if h.versioned != nil {
		role = "DNS server"
	}
	if h.recordGatewayEnabled() {
		role = "Connected DNS server"
	}
	if h.FollowerStatusOnly {
		role = "Read-only follower"
	}
	account := ""
	if !h.FollowerStatusOnly {
		account = `<button type="button" id="console-account">Access &amp; security</button>`
	}
	sidebar := `<aside class="console-sidebar"><div class="console-brand">sec<span>DNS</span></div><p class="console-label">ADMINISTRATION</p><nav aria-label="Administration">` + links + `</nav><div class="console-divider"></div>` + account + `<div class="console-sidebar-foot"><strong>` + role + `</strong><span>This instance only</span></div></aside>`
	head := `<link rel="stylesheet" href="` + escaped + `/ui/console.css"><script defer src="` + escaped + `/ui/console.js"></script>`
	data = bytes.Replace(data, []byte("</head>"), []byte(head+"</head>"), 1)
	gateway := ""
	if h.recordGatewayEnabled() {
		gateway = ` data-record-gateway="true"`
	}
	data = bytes.Replace(data, []byte("<body>"), []byte(`<body class="console-layout" data-console-page="`+active+`"`+gateway+`>`+sidebar), 1)
	return data
}

package server

import (
	"bytes"
	"html"
	"net/http"
	"strings"
)

// consoleAssets is the shared console shell: one token file, one component layer, the
// pre-paint theme/language script, the language runtime with its core catalogue, and
// the shell script. Every console page loads exactly these, in this order.
var consoleAssets = []struct{ name, kind string }{
	{"theme.js", "text/javascript"},
	{"tokens.css", "text/css"},
	{"console.css", "text/css"},
	{"strings.js", "text/javascript"},
	{"console.js", "text/javascript"},
	{"i18n.js", "text/javascript"},
}

// consoleFonts are the self-hosted Hanken Grotesk faces (SIL OFL 1.1, latin subset).
var consoleFonts = []string{"hanken-grotesk-latin-400-normal.woff2", "hanken-grotesk-latin-500-normal.woff2", "hanken-grotesk-latin-600-normal.woff2"}

// localStringsStub replaces the local sign-in catalogue on the single sign-on path, where
// the console's own credential surfaces never exist.
const localStringsStub = "// Local sign-in strings are served only on the private console path.\n"

func (h *HTTPAdminServer) consoleRoutes(mux *http.ServeMux, base string) {
	h.nodeUIRoutes(mux, base)
	for _, asset := range consoleAssets {
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
	for _, name := range consoleFonts {
		data, err := editorAssets.ReadFile("console_ui/fonts/" + name)
		if err != nil {
			panic(err)
		}
		mux.HandleFunc("GET "+base+"/ui/fonts/"+name, func(w http.ResponseWriter, r *http.Request) {
			editorHeaders(w)
			w.Header().Set("Content-Type", "font/woff2")
			w.Write(data)
		})
	}
	local, err := editorAssets.ReadFile("auth_ui/strings-local.js")
	if err != nil {
		panic(err)
	}
	mux.HandleFunc("GET "+base+"/ui/strings-local.js", func(w http.ResponseWriter, r *http.Request) {
		editorHeaders(w)
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		// The single sign-on path never receives the local credential vocabulary.
		if h.trustedSSOAvailable(r) {
			_, _ = w.Write([]byte(localStringsStub))
			return
		}
		_, _ = w.Write(local)
	})
}

// navIcons are 16 px stroke icons for the sidebar (inline SVG; no external resources).
var navIcons = map[string]string{
	"records":   `M4 6h16M4 12h16M4 18h10`,
	"import":    `M12 4v11m0 0-4-4m4 4 4-4M5 20h14`,
	"nodes":     `M4 5h16v6H4zM4 13h16v6H4zM8 8h.01M8 16h.01`,
	"health":    `M3 12h4l3-7 4 14 3-7h4`,
	"routing":   `M6 19a2 2 0 1 0 0-4 2 2 0 0 0 0 4Zm12-10a2 2 0 1 0 0-4 2 2 0 0 0 0 4ZM6 15V9a4 4 0 0 1 4-4h6M18 9v6a4 4 0 0 1-4 4H8`,
	"followers": `M20 12a8 8 0 0 1-14 5.3M4 12a8 8 0 0 1 14-5.3M18 3v4h-4M6 21v-4h4`,
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
		icon := `<svg viewBox="0 0 24 24" width="16" height="16" aria-hidden="true" focusable="false"><path d="` + navIcons[id] + `"/></svg>`
		links += `<a href="` + escaped + path + `"` + current + `>` + icon + `<span>` + label + `</span></a>`
	}
	if !h.FollowerStatusOnly {
		links += `<p class="console-label">DNS</p>`
		link("/ui/", "DNS records", "records")
		link("/ui/import-preview/", "Import records", "import")
	}
	if h.nodesEnabled() || len(h.followerStatusNames) > 0 {
		links += `<p class="console-label">Infrastructure</p>`
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
	// Account security lives in the user menu; this entry is its hidden, page-state anchor.
	account := ""
	if !h.FollowerStatusOnly {
		account = `<button type="button" id="console-account" class="console-account-entry" hidden>Access &amp; security</button>`
	}
	footer := "This instance only"
	if active == "nodes" || active == "health" || active == "routing" {
		role = "Candidate cluster"
		footer = "3 managed nodes"
	}
	brand := `<div class="console-brand" translate="no"><span class="brand-mark" aria-hidden="true"></span><span class="brand-name">secDNS</span></div>`
	sidebar := `<aside class="console-sidebar">` + brand + `<nav aria-label="Main navigation">` + links + `</nav>` + account + `<div class="console-sidebar-foot"><strong>` + role + `</strong><span>` + footer + `</span></div></aside>`
	var head strings.Builder
	for _, asset := range consoleAssets {
		switch {
		case asset.name == "theme.js":
			// Synchronous: theme and language apply before the first paint.
			head.WriteString(`<script src="` + escaped + `/ui/theme.js"></script>`)
		case strings.HasSuffix(asset.name, ".css"):
			head.WriteString(`<link rel="stylesheet" href="` + escaped + `/ui/` + asset.name + `">`)
		case asset.name == "strings.js":
			head.WriteString(`<script defer src="` + escaped + `/ui/strings.js"></script><script defer src="` + escaped + `/ui/strings-local.js"></script>`)
		default:
			head.WriteString(`<script defer src="` + escaped + `/ui/` + asset.name + `"></script>`)
		}
	}
	data = bytes.Replace(data, []byte("</head>"), []byte(head.String()+"</head>"), 1)
	gateway := ""
	if h.recordGatewayEnabled() {
		gateway = ` data-record-gateway="true"`
	}
	data = bytes.Replace(data, []byte("<body>"), []byte(`<body class="console-layout" data-console-page="`+active+`"`+gateway+`>`+sidebar), 1)
	return data
}

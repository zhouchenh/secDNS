package server

import (
	"encoding/json"
	"html"
	"math"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// Console revamp slice 3: layout, states and accessibility. Static checks of the embedded
// assets and the served pages only (no browser, no listener), so CI runs them on every
// change; the opt-in browser test and the Lab1 screenshot gate cover rendering.

// oklchLuminance converts an OKLCH colour to its WCAG relative luminance (linear sRGB,
// clamped to the sRGB gamut).
func oklchLuminance(l, c, hDeg float64) float64 {
	h := hDeg * math.Pi / 180
	a, b := c*math.Cos(h), c*math.Sin(h)
	l_ := l + 0.3963377774*a + 0.2158037573*b
	m_ := l - 0.1055613458*a - 0.0638541728*b
	s_ := l - 0.0894841775*a - 1.2914855480*b
	L, M, S := l_*l_*l_, m_*m_*m_, s_*s_*s_
	r := 4.0767416621*L - 3.3077115913*M + 0.2309699292*S
	g := -1.2684380046*L + 2.6097574011*M - 0.3413193965*S
	bl := -0.0041960863*L - 0.7034186147*M + 1.7076147010*S
	clamp := func(x float64) float64 { return math.Max(0, math.Min(1, x)) }
	return 0.2126*clamp(r) + 0.7152*clamp(g) + 0.0722*clamp(bl)
}

func contrast(a, b float64) float64 {
	if a < b {
		a, b = b, a
	}
	return (a + 0.05) / (b + 0.05)
}

// paletteLuminance reads every solid oklch() token of one palette block; "white" is 1.
func paletteLuminance(t *testing.T, block string) map[string]float64 {
	t.Helper()
	out := map[string]float64{}
	for _, m := range regexp.MustCompile(`(--[a-z0-9-]+):oklch\(([0-9.]+) ([0-9.]+) ([0-9.]+)\);`).FindAllStringSubmatch(block, -1) {
		l, _ := strconv.ParseFloat(m[2], 64)
		c, _ := strconv.ParseFloat(m[3], 64)
		h, _ := strconv.ParseFloat(m[4], 64)
		out[m[1]] = oklchLuminance(l, c, h)
	}
	for _, m := range regexp.MustCompile(`(--[a-z0-9-]+):white;`).FindAllStringSubmatch(block, -1) {
		out[m[1]] = 1
	}
	return out
}

func TestConsoleSlice3Static(t *testing.T) {
	read := func(name string) string {
		t.Helper()
		data, err := editorAssets.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	tokens, css, nodesJS, nodesHTML, app, state, index, preview, console := read("console_ui/tokens.css"), read("console_ui/console.css"), read("console_ui/nodes.js"),
		read("console_ui/nodes.html"), read("versioned_ui/app.js"), read("versioned_ui/state.js"), read("versioned_ui/index.html"), read("preview_ui/app.js"), read("console_ui/console.js")

	// C40/C34: contrast of the tokens in both themes. Field borders >= 3:1 against the surfaces
	// they sit on; status and body inks >= 4.5:1 against their backgrounds.
	block := func(selector string) string {
		i := strings.Index(tokens, selector)
		if i < 0 {
			t.Fatalf("tokens.css: %s missing", selector)
		}
		rest := tokens[i+len(selector):]
		return rest[:strings.Index(rest, "}")]
	}
	for name, decls := range map[string]string{"light": block("/* ===== .ad-light (default) ===== */\n:root{"), "dark": block(`:root[data-theme="dark"]{`)} {
		p := paletteLuminance(t, decls)
		check := func(fg, bg string, min float64) {
			f, okF := p[fg]
			b, okB := p[bg]
			if !okF || !okB {
				t.Fatalf("%s: token %s or %s is not a solid colour", name, fg, bg)
			}
			if r := contrast(f, b); r < min {
				t.Errorf("%s theme: %s on %s is %.2f:1 (< %.1f:1)", name, fg, bg, r, min)
			}
		}
		for _, bg := range []string{"--bg", "--bg-elev", "--surface"} {
			check("--field-line", bg, 3)
			for _, fg := range []string{"--ink", "--ink-2", "--muted", "--link"} {
				check(fg, bg, 4.5)
			}
		}
		check("--ink-2", "--surface-2", 4.5)
		for _, tone := range []string{"ok", "warn", "err", "info"} {
			check("--"+tone+"-ink", "--"+tone+"-bg", 4.5)
		}
		check("--action-fg", "--action", 4.5)
		check("--danger-fg", "--danger", 4.5)
		check("--primary", "--surface", 3) // focus ring and selected tab marker
		check("--danger-line", "--surface", 3)
	}

	// C41: a 12 px text floor; inputs 16 px on touch screens and phones.
	for _, m := range regexp.MustCompile(`font-size:([0-9.]+)px`).FindAllStringSubmatch(css+tokens, -1) {
		if v, _ := strconv.ParseFloat(m[1], 64); v < 12 {
			t.Errorf("font size %s px is below the 12 px floor", m[1])
		}
	}
	for _, want := range []string{"--fs-xs:12px", "--fs-md:14px", "--fs-lg:16px"} {
		if !strings.Contains(tokens, want) {
			t.Errorf("type scale: %s missing", want)
		}
	}
	coarse := css[strings.Index(css, "@media (pointer:coarse){"):]
	coarse = coarse[:strings.Index(coarse, "\n}")]
	if !strings.Contains(coarse, "min-height:var(--control-h-touch)") || !strings.Contains(coarse, ":where(input,select,textarea){font-size:var(--fs-lg)}") || !strings.Contains(tokens, "--control-h-touch:44px") {
		t.Error("C13: coarse pointers need 44 px targets and 16 px inputs")
	}
	// C10: page scroll, sticky toolbar and header; no fixed-height inner scroll for records.
	if strings.Contains(css, "max-height:calc(100dvh - 300px)") || !strings.Contains(css, ".records-sticky{position:sticky;top:var(--topbar-h)") ||
		!strings.Contains(css, ".console-record-table th{position:sticky;top:calc(var(--topbar-h) + var(--records-sticky-h,0px))") {
		t.Error("C10: records must scroll with the page, with a sticky toolbar and table header")
	}
	// C9 / C11 / C14: stacked rows below 1100 px, ListRows on phones, an overlay editor sheet,
	// a spanned-Duo two-pane rule with a fallback.
	for _, want := range []string{"@media (max-width:1099px){", ".row-edit::after{content:\"\";position:absolute;inset:0", ".record-sheet{position:fixed", "@media (horizontal-viewport-segments:2){", "env(viewport-segment-width 1 0,50vw)"} {
		if !strings.Contains(css, want) {
			t.Errorf("layout rule missing: %s", want)
		}
	}
	if strings.Contains(css, "#workspace.editing>.grid{display:grid") {
		t.Error("C14: the editor must not reflow the records table")
	}
	// C43: one focus ring; dialogs and programmatically focused regions show none.
	if !strings.Contains(css, ":focus-visible{outline:2px solid var(--primary);outline-offset:2px}") || !strings.Contains(css, "dialog:focus,dialog:focus-visible{outline:none}") {
		t.Error("C43: single 2 px focus ring")
	}

	// C16/C17: node identities come from the server inventory, never from the page scripts.
	hardcoded := regexp.MustCompile(`amd103|intel108|cix106|100\.91\.|2001:470|"AMD"|CIX ARM64`)
	for name, src := range map[string]string{"nodes.js": nodesJS, "nodes.html": nodesHTML, "nodes-bgp.js": read("console_ui/nodes-bgp.js"), "nodes-health.js": read("console_ui/nodes-health.js")} {
		if m := hardcoded.FindString(src); m != "" {
			t.Errorf("%s hard-codes a node identity: %q", name, m)
		}
	}
	h := &HTTPAdminServer{AgentAuthConfigured: true, NodeAdapterExecutable: "/x", NodeAdapterScript: "/x", NodeAuditDirectory: "/x"}
	for _, page := range []string{"nodes", "health", "routing"} {
		data := strings.ReplaceAll(strings.ReplaceAll(nodesHTML, "NODEPAGE", page), "NODEINVENTORY", string(nodeInventoryAttribute()))
		served := string(h.consolePage([]byte(data), "/admin", page))
		m := regexp.MustCompile(`data-nodes="([^"]*)"`).FindStringSubmatch(served)
		if m == nil {
			t.Fatalf("%s: no node inventory on the page", page)
		}
		var inv []nodeInventoryEntry
		if err := json.Unmarshal([]byte(html.UnescapeString(m[1])), &inv); err != nil || len(inv) != len(nodeIDs) {
			t.Fatalf("%s: inventory %q: %v", page, m[1], err)
		}
		for i, n := range inv {
			if n.ID != nodeIDs[i] || n.RouterID != nodeBGPIdentities[n.ID].IPv4 || n.IPv6 != nodeBGPIdentities[n.ID].IPv6 {
				t.Errorf("%s: inventory entry %d = %+v, not the server inventory", page, i, n)
			}
		}
		// Slice-1 open item: the description sits under the title, not beside it.
		if !strings.Contains(served, `<div class="heading"><div><h1 id="page-title">`) || !strings.Contains(served, `</h1><p id="page-description"></p></div>`) {
			t.Errorf("%s: heading and description are not grouped", page)
		}
		// C42: the header names the section before any script runs.
		if !regexp.MustCompile(`<header><strong class="topbar-title">[^<]+</strong></header>`).MatchString(served) {
			t.Errorf("%s: header is empty before scripts run", page)
		}
		if strings.Count(served, "<main") != 1 {
			t.Errorf("%s: exactly one main landmark expected", page)
		}
	}
	if !strings.Contains(nodesJS, "JSON.parse(main.dataset.nodes") || strings.Contains(nodesHTML, `id="node-filter"`) {
		t.Error("node pages must read the served inventory and drop the duplicate node filter")
	}
	footer := string(h.consolePage([]byte("<html><head></head><body><main></main></body></html>"), "/admin", "nodes"))
	if !strings.Contains(footer, strconv.Itoa(len(nodeIDs))+" managed nodes") {
		t.Error("the managed-node count must come from the inventory")
	}

	// C34/C35/C36/C38: four-state status with icon and word; failures first; page-level error
	// with Try again; disabled actions say why.
	for _, want := range []string{`const WORD={ok:"OK",degraded:"Degraded",down:"Down",unknown:"Unknown"}`, "badge(state", "const ordered=()=>ids.map(info).sort((a,b)=>RANK[a.state.level]-RANK[b.state.level]",
		"'Couldn’t reach any node'", "'Try again','primary'", "function blockedReason(x)", "setAttribute('aria-describedby',line.id)", "setAttribute('role','tablist')", "'Last known: failing'"} {
		if !strings.Contains(nodesJS, want) {
			t.Errorf("nodes.js: missing %s", want)
		}
	}
	// Records: C33 per-field errors, C32/C39 loading and error states, C37 empty state, C15 URL state.
	for _, want := range []string{"S.draftIssues(record,model.draft,selected)", `target.setAttribute("aria-invalid","true")`, `"Fix {n} problems before adding this record"`,
		`"Records could not be loaded"`, `"Loading records…"`, `"DNS server unreachable"`, "function retryLoad()", `$("records-empty").hidden=!none`, "history.replaceState(history.state", "const PAGE=50"} {
		if !strings.Contains(app, want) {
			t.Errorf("versioned_ui/app.js: missing %s", want)
		}
	}
	if !strings.Contains(state, "function draftIssues(") || !strings.Contains(state, "const api = {draftIssue, draftIssues,") {
		t.Error("state.js: draftIssues must be exported")
	}
	for _, want := range []string{`<form id="editor" novalidate>`, `<p id="name-error" class="field-error" hidden></p>`, `<p id="ttl-error" class="field-error" hidden></p>`, `<p id="expiry-error" class="field-error" hidden></p>`,
		`<button id="delete-in-editor" type="button" class="danger" hidden>Delete record</button>`, `<div id="records-empty" class="empty-state" hidden>`, `<button id="show-more" type="button">Show more</button>`} {
		if !strings.Contains(index, want) {
			t.Errorf("versioned_ui/index.html: missing %s", want)
		}
	}
	if !strings.Contains(preview, `$("attention-only").checked=true`) || !strings.Contains(console, "main.inert=open") {
		t.Error("C18 attention filter or C42 inert drawer missing")
	}
	// Slice-2 guarantees are untouched (spot checks; TestConsoleSlice2Static has the full set).
	if !strings.Contains(app, `503:["snapshot_unavailable","removal_check_unavailable"]`) || !strings.Contains(nodesJS, "is the last healthy node serving") {
		t.Error("slice-2 safety behaviour changed")
	}

	// Every sentence the slice-3 scripts compose is in the catalogue (both languages are checked by
	// TestConsoleCatalogueComplete), and none is captured by a broader pattern by mistake.
	core := embeddedCatalogue(t, "console_ui/strings.js")
	for _, text := range []string{"OK", "Degraded", "Down", "No data yet", "Couldn’t reach any node", "Not refreshed: cix106. Their last values are kept and marked out of date.",
		"This observation is out of date. Refresh before changing this node.", "Checking 3 nodes…", "3 nodes", "DNS process: Running", "Healthy checks: 4 / 4", "Overview", "Node details",
		"Why checks are not passing", "Last known: failing", "Upstream did not answer in time", "Unlisted peer", "Value 2", "Fix 2 problems before adding this record",
		"Fix 1 problem before adding this record", "192.0.2.300 is not a valid IPv4 address: each part must be 0 to 255.", "Enter a whole number of seconds from 0 to 4294967295.",
		"Records could not be loaded", "Records could not be refreshed", "DNS server unreachable", "Loading records…", "Show 50 more", "Showing 50 of 51", "Copy name", "Name copied.",
		"No records yet", "Add a record or import an export to get started.", "Only entries that need attention", "Source fields", "Remote DNS server", "3 managed nodes"} {
		if !catalogueHas(core, text) {
			t.Errorf("slice-3 text %q is not in the core catalogue", text)
		}
	}
	for text, key := range map[string]string{"This observation is out of date. Refresh before changing this node.": "nodes.blocked.stale", "Show 50 more": "records.showMore.n",
		"Unlisted peer": "nodes.peer.unlisted", "Showing 50 of 51": "records.showing", "Health result is out of date": "nodes.reason.staleHealth"} {
		if got := catalogueWinner(core, text); got != key {
			t.Errorf("%q is translated by %q, want %q", text, got, key)
		}
	}
}

// catalogueWinner returns the key the runtime translator uses for text: an exact entry, else
// the pattern with the most literal text (i18n.js sorts patterns by that weight).
func catalogueWinner(c consoleCatalogue, text string) string {
	best, weight := "", -1
	for key, en := range c.EN {
		if !cataloguePlaceholder.MatchString(en) {
			if en == text {
				return key
			}
			continue
		}
		parts := cataloguePlaceholder.Split(en, -1)
		for i := range parts {
			parts[i] = regexp.QuoteMeta(parts[i])
		}
		if regexp.MustCompile(`(?s)^`+strings.Join(parts, "(.+?)")+`$`).MatchString(text) {
			if w := len(cataloguePlaceholder.ReplaceAllString(en, "")); w > weight {
				best, weight = key, w
			}
		}
	}
	return best
}

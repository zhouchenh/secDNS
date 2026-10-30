package server

import (
	"bytes"
	"encoding/json"
	"html"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Console revamp slice 1: design system, theme, UI language and the single sign-on
// wording guard. These tests read the embedded assets and the served pages only; they
// need no browser, so CI runs them on every change.

var (
	// Local sign-in vocabulary that must never reach the single sign-on path.
	localCredentialWording   = regexp.MustCompile(`(?i)break[- ]?glass|recovery code|recover with|local grant|local recovery|password|totp|authenticator|human session`)
	localCredentialWordingZH = regexp.MustCompile(`密碼|驗證器|復原碼|緊急`)
	cataloguePlaceholder     = regexp.MustCompile(`\{[a-zA-Z0-9_]+\}`)
)

type consoleCatalogue struct {
	EN map[string]string `json:"en"`
	ZH map[string]string `json:"zh-Hant"`
}

func readCatalogue(t *testing.T, name string, data []byte) consoleCatalogue {
	t.Helper()
	s := string(data)
	i, j := strings.Index(s, ".push("), strings.LastIndex(s, ");")
	if i < 0 || j < i {
		t.Fatalf("%s: not a catalogue file", name)
	}
	var c consoleCatalogue
	if e := json.Unmarshal([]byte(s[i+len(".push("):j]), &c); e != nil {
		t.Fatalf("%s: %v", name, e)
	}
	return c
}

func embeddedCatalogue(t *testing.T, path string) consoleCatalogue {
	t.Helper()
	data, e := editorAssets.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	return readCatalogue(t, path, data)
}

func placeholders(s string) string {
	p := cataloguePlaceholder.FindAllString(s, -1)
	sort.Strings(p)
	return strings.Join(p, ",")
}

func TestConsoleCatalogueComplete(t *testing.T) {
	core, local := embeddedCatalogue(t, "console_ui/strings.js"), embeddedCatalogue(t, "auth_ui/strings-local.js")
	seen := map[string]string{}
	for name, c := range map[string]consoleCatalogue{"core": core, "local": local} {
		if len(c.EN) == 0 {
			t.Fatalf("%s catalogue is empty", name)
		}
		for key, en := range c.EN {
			zh, ok := c.ZH[key]
			if !ok {
				t.Errorf("%s: %q has no zh-Hant entry", name, key)
				continue
			}
			if strings.TrimSpace(en) == "" || strings.TrimSpace(zh) == "" {
				t.Errorf("%s: %q has an empty value", name, key)
			}
			if placeholders(en) != placeholders(zh) {
				t.Errorf("%s: %q placeholders differ: %q vs %q", name, key, en, zh)
			}
			if other, dup := seen[en]; dup {
				t.Errorf("English text %q is defined twice (%s, %s)", en, other, name+":"+key)
			}
			seen[en] = name + ":" + key
		}
		for key := range c.ZH {
			if _, ok := c.EN[key]; !ok {
				t.Errorf("%s: zh-Hant %q has no English entry", name, key)
			}
		}
	}
	for key, en := range core.EN {
		if localCredentialWording.MatchString(en) || localCredentialWordingZH.MatchString(core.ZH[key]) {
			t.Errorf("core catalogue (served on the SSO path) carries local sign-in wording: %s", key)
		}
	}
	// Every text node and label the server composes into the shell is translatable.
	h := &HTTPAdminServer{AgentAuthConfigured: true, NodeAdapterExecutable: "/x", NodeAdapterScript: "/x", NodeAuditDirectory: "/x"}
	h.ConfigureFollowerStatus([]string{"replica"})
	page := string(h.consolePage([]byte("<html><head></head><body><main></main></body></html>"), "/admin", "records"))
	for _, text := range composedTexts(page) {
		if text != "secDNS" && !catalogueHas(core, text) {
			t.Errorf("shell text %q is not in the catalogue", text)
		}
	}
	// Static page markup is covered as well.
	for _, file := range []string{"versioned_ui/index.html", "preview_ui/index.html", "console_ui/nodes.html"} {
		data, e := editorAssets.ReadFile(file)
		if e != nil {
			t.Fatal(e)
		}
		for _, text := range composedTexts(string(data)) {
			if !catalogueHas(core, text) && !catalogueHas(local, text) && !consoleUntranslated(text) {
				t.Errorf("%s: text %q is not in the catalogue", file, text)
			}
		}
	}
	// Shell strings created by console.js.
	for _, text := range []string{"Account security", "Theme", "System", "Light", "Dark", "Language", "Sign out", "Signed in with WithMy ID",
		"Skip to content", "Open navigation", "Close navigation", "Account menu", "Advanced session details", "Agent access", "Back to DNS records"} {
		if !catalogueHas(core, text) && !(text == "Agent access" && catalogueHas(local, text)) {
			t.Errorf("console.js text %q is not in the catalogue", text)
		}
	}
}

var (
	markupText = regexp.MustCompile(`>([^<>]+)<`)
	markupAttr = regexp.MustCompile(`\s(?:aria-label|placeholder|title|alt)="([^"]*)"`)
)

// composedTexts lists the visible text nodes and translatable attributes of markup
// (script and style bodies excluded), trimmed and whitespace-collapsed.
func composedTexts(markup string) []string {
	markup = regexp.MustCompile(`(?s)<(script|style|textarea)[^>]*>.*?</(script|style|textarea)>`).ReplaceAllString(markup, "<x></x>")
	markup = regexp.MustCompile(`(?s)<!--.*?-->`).ReplaceAllString(markup, "")
	var out []string
	add := func(s string) {
		s = strings.Join(strings.Fields(html.UnescapeString(s)), " ")
		if s != "" {
			out = append(out, s)
		}
	}
	for _, m := range markupText.FindAllStringSubmatch(markup, -1) {
		add(m[1])
	}
	for _, m := range markupAttr.FindAllStringSubmatch(markup, -1) {
		add(m[1])
	}
	return out
}

// catalogueHas reports whether text is an exact catalogue entry or matches a pattern
// entry ("{name}" placeholders), as the runtime translator matches it.
func catalogueHas(c consoleCatalogue, text string) bool {
	for _, en := range c.EN {
		if en == text {
			return true
		}
		if cataloguePlaceholder.MatchString(en) {
			parts := cataloguePlaceholder.Split(en, -1)
			for i := range parts {
				parts[i] = regexp.QuoteMeta(parts[i])
			}
			if regexp.MustCompile(`(?s)^` + strings.Join(parts, "(.+?)") + `$`).MatchString(text) {
				return true
			}
		}
	}
	return false
}

// consoleUntranslated is text that stays as is in every language: DNS technical terms,
// product names, sample data and separators.
func consoleUntranslated(text string) bool {
	switch text {
	case "A", "AAAA", "CNAME", "TXT", "TTL", "secDNS", "AMD", "Intel", "CIX ARM64", "·", "/", "|":
		return true
	}
	return strings.HasPrefix(text, "/ip dns static") || strings.HasPrefix(text, "host.invalid") || strings.HasPrefix(text, "2030-") || strings.HasPrefix(text, "routeros.")
}

func TestConsoleThemeAndTokens(t *testing.T) {
	read := func(name string) string {
		data, e := editorAssets.ReadFile(name)
		if e != nil {
			t.Fatal(e)
		}
		return string(data)
	}
	theme, i18n, tokens, css := read("console_ui/theme.js"), read("console_ui/i18n.js"), read("console_ui/tokens.css"), read("console_ui/console.css")
	// Storage may be unavailable (private mode, blocked site data): every access is guarded.
	for name, src := range map[string]string{"theme.js": theme, "i18n.js": i18n} {
		guard := regexp.MustCompile(`try \{ (?:if \([^)]*\) )?(?:return )?window\.localStorage\.\w+\([^)]*\);(?: else window\.localStorage\.\w+\([^)]*\);)? \} catch`)
		if !strings.Contains(src, "localStorage") || strings.Contains(guard.ReplaceAllString(src, ""), "localStorage") {
			t.Fatalf("%s: a storage access is not wrapped in try/catch", name)
		}
	}
	// Only the two forced themes are ever written to <html data-theme>; "system" removes it.
	for _, src := range []string{theme, i18n} {
		if !strings.Contains(src, `=== "light" || `) || !strings.Contains(src, "delete root.dataset.theme") {
			t.Fatal("theme values are not restricted to light/dark with system as the default")
		}
	}
	// Applied before paint: theme.js is a synchronous head script ahead of the stylesheets.
	h := &HTTPAdminServer{}
	page := string(h.consolePage([]byte("<html><head><title>x</title></head><body><header></header><main></main></body></html>"), "/admin", "records"))
	script, sheet, body := strings.Index(page, `<script src="/admin/ui/theme.js"></script>`), strings.Index(page, `<link rel="stylesheet" href="/admin/ui/tokens.css">`), strings.Index(page, "<body")
	if script < 0 || sheet < 0 || !(script < sheet && sheet < body) || strings.Contains(page, `defer src="/admin/ui/theme.js"`) {
		t.Fatal("theme.js must run synchronously in <head> before the stylesheets")
	}
	for _, want := range []string{"/admin/ui/console.css", "/admin/ui/strings.js", "/admin/ui/strings-local.js", "/admin/ui/i18n.js", "/admin/ui/console.js"} {
		if !strings.Contains(page, want) {
			t.Fatal("shell asset not linked:", want)
		}
	}
	// Dark mode: the system preference (unless forced light) and the forced dark theme
	// define exactly the same palette, and it covers every light palette variable.
	block := func(selector string) string {
		i := strings.Index(tokens, selector)
		if i < 0 {
			t.Fatalf("tokens.css: %s missing", selector)
		}
		rest := tokens[i+len(selector):]
		return rest[:strings.Index(rest, "}")]
	}
	vars := func(decls string) []string {
		var names []string
		for _, m := range regexp.MustCompile(`(--[a-z0-9-]+):`).FindAllStringSubmatch(decls, -1) {
			names = append(names, m[1])
		}
		sort.Strings(names)
		return names
	}
	system, forced := block(`:root:not([data-theme="light"]){`), block(`:root[data-theme="dark"]{`)
	if strings.Join(strings.Fields(system), "") != strings.Join(strings.Fields(forced), "") {
		t.Fatal("system-dark and forced-dark palettes differ")
	}
	light := block("/* ===== .ad-light (default) ===== */\n:root{")
	if strings.Join(vars(light), ",") != strings.Join(vars(forced), ",") || !strings.Contains(forced, "color-scheme:dark") || !strings.Contains(light, "color-scheme:light") {
		t.Fatalf("light and dark palettes define different variables:\n%v\n%v", vars(light), vars(forced))
	}
	// The component layer uses tokens only: no colour literals, every variable defined.
	noLiterals := regexp.MustCompile(`#[0-9a-fA-F]{3,8}\b|\brgba?\(|\bhsla?\(|\boklch\(|:\s*(white|black)\b`)
	if m := noLiterals.FindString(css); m != "" {
		t.Fatalf("console.css has a colour literal: %q", m)
	}
	defined := map[string]bool{}
	for _, m := range regexp.MustCompile(`(--[a-z0-9-]+):`).FindAllStringSubmatch(tokens, -1) {
		defined[m[1]] = true
	}
	for _, m := range regexp.MustCompile(`var\((--[a-z0-9-]+)`).FindAllStringSubmatch(css, -1) {
		if !defined[m[1]] {
			t.Errorf("console.css uses undefined token %s", m[1])
		}
	}
	// No external resources: the CSP allows self only, fonts are served locally.
	for name, src := range map[string]string{"tokens.css": tokens, "console.css": css, "theme.js": theme, "i18n.js": i18n,
		"console.js": strings.ReplaceAll(read("console_ui/console.js"), "http://www.w3.org/2000/svg", "")} {
		if strings.Contains(src, "http://") || strings.Contains(src, "https://") || strings.Contains(src, "@import") {
			t.Fatalf("%s references an external resource", name)
		}
	}
	if !strings.Contains(editorCSP, "font-src 'self'") || strings.Contains(editorCSP, "http") {
		t.Fatal("CSP must allow only self-hosted fonts")
	}
	v := newVersionedUIServer(t)
	for _, name := range consoleFonts {
		w := do(v, "GET", "/admin/ui/fonts/"+name, "", "")
		if w.Code != 200 || w.Header().Get("Content-Type") != "font/woff2" || !bytes.HasPrefix(w.Body.Bytes(), []byte("wOF2")) || w.Header().Get("Content-Security-Policy") != editorCSP {
			t.Fatalf("font %s: %d %s", name, w.Code, w.Header().Get("Content-Type"))
		}
	}
	for _, asset := range consoleAssets {
		if w := do(v, "GET", "/admin/ui/"+asset.name, "", ""); w.Code != 200 || !strings.HasPrefix(w.Header().Get("Content-Type"), asset.kind) {
			t.Fatalf("asset %s: %d", asset.name, w.Code)
		}
	}
	// Language: the saved choice, then the browser language, then English; <html lang> follows.
	for _, want := range []string{`read("secdns.lang")`, "navigator.languages", `lang = lang || "en"`, "root.lang = lang"} {
		if !strings.Contains(theme, want) {
			t.Fatal("theme.js language selection missing", want)
		}
	}
	for _, want := range []string{"Intl.DateTimeFormat(intlLocale()", "root.lang = next", `store.set("secdns.lang", next)`} {
		if !strings.Contains(i18n, want) {
			t.Fatal("i18n.js missing", want)
		}
	}
}

func newVersionedUIServer(t *testing.T) *HTTPAdminServer {
	t.Helper()
	h := newServer(t, "console-revamp")
	h.UI = true
	h.Path = "/admin"
	return h
}

// The single sign-on path (a valid WithMy ID edge assertion) never serves local
// sign-in vocabulary: not in any page, not in the shell, not in the catalogue. The
// private break-glass path keeps it. Replaces the opt-in browser check for CI.
func TestSSOPathServesNoLocalCredentialWording(t *testing.T) {
	h, _ := ssoTestServer(t, true)
	h.UI = true
	get := func(path string, sso bool) *httptest.ResponseRecorder {
		r := ssoRequest(h, "GET", path, "")
		r.Header.Del("Content-Type")
		if !sso {
			r = httptest.NewRequest("GET", "https://example.invalid/admin"+path, nil)
			r.RemoteAddr = "127.0.0.1:40000"
		}
		return serve(h, r)
	}
	pages := []string{"/ui/", "/ui/import-preview/"}
	if h.nodesEnabled() {
		pages = append(pages, "/ui/nodes/", "/ui/health/", "/ui/routing/")
	}
	for _, path := range pages {
		w := get(path, true)
		if w.Code != http.StatusOK {
			t.Fatalf("%s on the SSO path: %d", path, w.Code)
		}
		body := w.Body.String()
		if strings.Contains(body, `type="password"`) {
			t.Fatalf("%s on the SSO path carries a password field", path)
		}
		for _, text := range composedTexts(body) {
			if localCredentialWording.MatchString(text) {
				t.Fatalf("%s on the SSO path carries local sign-in wording: %q", path, text)
			}
		}
	}
	for _, asset := range []string{"/ui/strings.js", "/ui/strings-local.js", "/ui/console.js", "/ui/i18n.js", "/ui/theme.js"} {
		w := get(asset, true)
		if w.Code != 200 || localCredentialWording.MatchString(w.Body.String()) || localCredentialWordingZH.MatchString(w.Body.String()) {
			t.Fatalf("%s on the SSO path: %d or local sign-in wording", asset, w.Code)
		}
	}
	if w := get("/ui/strings-local.js", true); w.Body.String() != localStringsStub {
		t.Fatal("SSO path must receive the local catalogue stub")
	}
	if w := get("/ui/strings-local.js", false); w.Code != 200 || !localCredentialWording.MatchString(w.Body.String()) || !strings.Contains(w.Body.String(), "zh-Hant") {
		t.Fatal("break-glass path must keep the local catalogue")
	}
	// human.js: the SSO path detaches every local credential surface; the strings it shows there are neutral.
	src := get("/auth/human.js", true).Body.String()
	if strings.Contains(src, "managed only on the local break-glass path") || !strings.Contains(src, "if(ssoMode)purgeForSSO();") {
		t.Fatal("human.js lost the SSO purge")
	}
	purge := between(t, src, "function purgeForSSO(){", "\n  }")
	for _, part := range []string{"form", "alternatives", "recovery", "dismiss", "download", "ssoUI.groups.password", "ssoUI.groups.totp", "ssoUI.groups.codes", "...ssoUI.reauthLocal", "el.remove()", `passkeys.replaceChildren()`} {
		if !strings.Contains(purge, part) {
			t.Fatalf("purgeForSSO no longer detaches %s", part)
		}
	}
	for _, fn := range []string{between(t, src, "function applySSO(human){", "\n  }"), purge} {
		for _, literal := range regexp.MustCompile(`"([^"\\]*)"`).FindAllStringSubmatch(fn, -1) {
			if localCredentialWording.MatchString(literal[1]) {
				t.Fatalf("SSO-only human.js text carries local sign-in wording: %q", literal[1])
			}
		}
	}
	signedOut := between(t, src, `const signedOut=document.createElement("p")`, "const reauthLocal=")
	for _, literal := range regexp.MustCompile(`"([^"\\]*)"`).FindAllStringSubmatch(signedOut, -1) {
		if localCredentialWording.MatchString(literal[1]) {
			t.Fatalf("SSO signed-out / step-up text carries local sign-in wording: %q", literal[1])
		}
	}
	// Audit labels that name local credentials are replaced by a neutral label on the SSO path.
	neutral := between(t, src, "const ssoAuditNeutral=new Set([", "]);")
	for _, m := range regexp.MustCompile(`(\w+):"([^"]*)"`).FindAllStringSubmatch(between(t, src, "const auditLabels={", "};"), -1) {
		if localCredentialWording.MatchString(m[2]) && !strings.Contains(neutral, `"`+m[1]+`"`) {
			t.Fatalf("audit label %s (%q) is shown on the SSO path", m[1], m[2])
		}
	}
	if !strings.Contains(get("/auth/passkey.js", true).Body.String(), "s?.sso_login===true){section.replaceChildren();section.hidden=true;") {
		t.Fatal("passkey.js lost the SSO early return")
	}
	// The break-glass page on the private path is unchanged.
	for _, path := range []string{"/ui/", "/ui/import-preview/"} {
		if w := get(path, false); w.Code != 200 || !strings.Contains(w.Body.String(), `type="password"`) {
			t.Fatal("break-glass page changed", path)
		}
	}
}

func between(t *testing.T, s, start, end string) string {
	t.Helper()
	i := strings.Index(s, start)
	if i < 0 {
		t.Fatalf("missing %q", start)
	}
	rest := s[i+len(start):]
	j := strings.Index(rest, end)
	if j < 0 {
		t.Fatalf("missing end %q after %q", end, start)
	}
	return rest[:j]
}

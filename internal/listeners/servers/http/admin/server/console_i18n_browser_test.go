package server

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/zhouchenh/secDNS/internal/recordset"
	"github.com/zhouchenh/secDNS/internal/recordstore"
)

// consoleI18nFixture runs inside the real console page. With ?zh=1 the page is first
// brought up in Traditional Chinese (saved choice, then one reload), as a returning user
// would see it. It then records what is displayed, switches the language in place
// (zh-Hant -> en -> zh-Hant) and records again. It never fills a sign-in form.
const consoleI18nFixture = `(()=>{const q=new URLSearchParams(location.search);
const T=e=>e?e.textContent.trim():null,sleep=ms=>new Promise(r=>setTimeout(r,ms));
const until=async(f,ms=9000)=>{const t=Date.now();while(Date.now()-t<ms){try{if(f())return true}catch(e){}await sleep(100)}return false};
const put=o=>{const out=document.createElement("pre");out.id="fixture-result";out.textContent=JSON.stringify(o);document.body.append(out);};
if(q.get("zh")&&document.documentElement.lang!=="zh-Hant"){try{localStorage.setItem("secdns.lang","zh-Hant")}catch(e){}location.reload();return;}
const snap=()=>({lang:document.documentElement.lang,title:T(document.querySelector(".topbar-title")),badge:T(document.querySelector(".env-badge")),
 doc:document.title,security:T([...document.querySelectorAll("#user-menu-panel .menu-item")][0]),newRecord:T(document.getElementById("new-record")),
 values:[...document.querySelectorAll("#rows .record-value")].map(T),types:[...document.querySelectorAll("#rows tr td:nth-child(2)")].map(T),
 candidates:[...document.querySelectorAll("#candidate-rows td")].map(T),status:T(document.getElementById("status")),blockers:T(document.getElementById("blockers")),
 logoutInMenu:!!document.querySelector("#user-menu-panel #agent-logout"),logoutInHeader:!!document.querySelector("body>header>#agent-logout")});
addEventListener("load",async()=>{const o={};try{
 if(q.get("bg")){await until(()=>window.secDNSI18n&&document.getElementById("agent-logout"));await sleep(400);}
 else if(location.pathname.endsWith("/import-preview/")){await until(()=>window.secDNSAgent?.kind==="human");await sleep(300);
  // Exact import converts only A/AAAA/CNAME, whose canonical names and values cannot equal a
  // catalogue word; rows are written exactly as preview_ui/app.js writes them (td.textContent).
  for(const w of JSON.parse(q.get("words"))){const tr=document.createElement("tr");for(const v of [w,"TXT",w,"300 s"]){const td=document.createElement("td");td.textContent=v;tr.append(td);}document.getElementById("candidate-rows").append(tr);}
  await sleep(300);}
 else{await until(()=>window.secDNSAgent?.kind==="human"&&document.querySelectorAll("#rows tr").length>=4);await sleep(400);}
 o.first=snap();window.secDNSI18n.setLanguage("en");await sleep(400);o.en=snap();
 window.secDNSI18n.setLanguage("zh-Hant");await sleep(400);o.zh=snap();
 window.secDNSI18n.setLanguage("en");await sleep(300);o.back=snap();
}catch(e){o.error=String(e)}try{localStorage.removeItem("secdns.lang")}catch(e){}put(o);});})();`

// Data values that are also catalogue words. They must be displayed byte-identical in
// every language, in the records table and in the import candidate table.
var i18nDataWords = []string{"none", "Active", "Sign out", "Delete", "Stale"}

// TestConsoleI18nBrowser checks, in headless Chromium, that the language pass never alters
// displayed record data and that switching language in place leaves no stale strings
// (top-bar title, environment badge, Sign out placement on the private break-glass path).
// Opt-in, like TestSSOConsoleUXBrowser: SECDNS_SSO_UX_BROWSER=1 with SECDNS_CHROME.
func TestConsoleI18nBrowser(t *testing.T) {
	if os.Getenv("SECDNS_SSO_UX_BROWSER") != "1" {
		t.Skip("opt-in headless Chromium")
	}
	chrome := os.Getenv("SECDNS_CHROME")
	core := embeddedCatalogue(t, "console_ui/strings.js")
	for _, w := range i18nDataWords {
		if w != "Active" && !catalogueHas(core, w) { // "Active" is plain data; the others are catalogue words
			t.Fatalf("precondition: %q must be a catalogue word for this test to mean anything", w)
		}
	}
	start := func(sso bool) (string, *recordstore.VersionedStore) {
		h, _ := ssoTestServer(t, true)
		h.UI = true
		h.NodeAdapterExecutable, h.NodeAdapterScript = "", ""
		store, err := recordstore.NewVersionedMemory(recordstore.Enrollment{RulesetID: "i18n-check", LineageID: "disposable"})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { store.Close() })
		h.versioned = store
		var records []recordset.Record
		for i, w := range i18nDataWords {
			records = append(records, recordset.Record{Name: string(rune('a'+i)) + ".i18n.invalid.", Type: "TXT", Values: []string{w}, TTLSeconds: 300})
		}
		if _, err = store.Replace(recordstore.Expected{RulesetID: "i18n-check", LineageID: "disposable", Revision: 1}, "seed", records); err != nil {
			t.Fatal(err)
		}
		srv := httptest.NewUnstartedServer(nil)
		host := srv.Listener.Addr().String()
		_, port, _ := net.SplitHostPort(host)
		h.agent.origin = "https://" + host
		routes := h.routes()
		srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/fixture.js" {
				w.Header().Set("Content-Type", "text/javascript")
				w.Write([]byte(consoleI18nFixture))
				return
			}
			r = r.WithContext(context.WithValue(r.Context(), unixPeerKey{}, true))
			r.Header.Set("X-Forwarded-For", "203.0.113.7")
			r.Header.Set("X-Real-IP", "203.0.113.7")
			r.Header.Set("X-Forwarded-Proto", "https")
			r.Header.Set("X-Forwarded-Host", host)
			r.Header.Set("X-Forwarded-Port", port)
			if sso {
				r.Header.Set("X-Secdns-SSO-Secret", ssoTestSecret)
				r.Header.Set("X-Secdns-SSO-User", ssoTestUser)
				r.Header.Set("X-Secdns-SSO-Username", ssoTestName)
				r.Header.Set("X-Secdns-SSO-Roles", ssoTestRole)
				r.Header.Set("X-Secdns-SSO-Id-Token", "Bearer "+ssoTestJWT(map[string]any{"sub": ssoTestUser}))
				r.Header.Set("X-Secdns-SSO-Access-Token", ssoTestJWT(map[string]any{"sub": ssoTestUser}))
			}
			if r.URL.Path == "/admin/ui/" || r.URL.Path == "/admin/ui/import-preview/" {
				rec := &captureWriter{header: http.Header{}}
				routes.ServeHTTP(rec, r)
				for k, v := range rec.header {
					w.Header()[k] = v
				}
				w.WriteHeader(rec.status())
				w.Write([]byte(strings.Replace(rec.body.String(), "</body>", `<script src="/fixture.js"></script></body>`, 1)))
				return
			}
			routes.ServeHTTP(w, r)
		})
		srv.StartTLS()
		t.Cleanup(srv.Close)
		return "https://" + host, store
	}
	type view struct {
		Lang, Title, Badge, Doc, Security, NewRecord, Status, Blockers string
		Values, Types, Candidates                    []string
		LogoutInMenu, LogoutInHeader                 bool
	}
	type result struct {
		First, En, Zh, Back view
		Error               string
	}
	run := func(url string) result {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		profile := t.TempDir()
		cmd := exec.CommandContext(ctx, chrome, "--no-sandbox", "--ignore-certificate-errors", "--disable-gpu", "--hide-scrollbars",
			"--user-data-dir="+profile, "--window-size=1280,900", "--virtual-time-budget=20000", "--dump-dom", url)
		cmd.Env = append(os.Environ(), "LD_LIBRARY_PATH="+os.Getenv("SECDNS_CHROME_LIBS"))
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("chrome %s: %v", url, err)
		}
		m := regexp.MustCompile(`<pre id="fixture-result">([^<]*)</pre>`).FindSubmatch(out)
		if m == nil {
			t.Fatalf("no fixture result for %s (%d bytes)", url, len(out))
		}
		var r result
		raw := strings.NewReplacer("&quot;", `"`, "&amp;", "&", "&lt;", "<", "&gt;", ">").Replace(string(m[1]))
		if err := json.Unmarshal([]byte(raw), &r); err != nil || r.Error != "" {
			t.Fatalf("fixture %s: %v %s", url, err, raw)
		}
		t.Logf("%s: %s", url, raw)
		return r
	}
	same := func(where string, got []string) {
		t.Helper()
		if strings.Join(got, "|") != strings.Join(i18nDataWords, "|") {
			t.Fatalf("%s: data changed by the language pass: %q (want %q)", where, got, i18nDataWords)
		}
	}
	sso, _ := start(true)

	// Records page, loaded in Traditional Chinese, switched in place to English and back.
	r := run(sso + "/admin/ui/?zh=1")
	if r.First.Lang != "zh-Hant" || r.Zh.Lang != "zh-Hant" || r.En.Lang != "en" || r.Back.Lang != "en" {
		t.Fatalf("language did not apply: %+v", r)
	}
	for name, v := range map[string]view{"zh load": r.First, "en": r.En, "zh in place": r.Zh, "en again": r.Back} {
		same("records "+name, v.Values)
		if strings.Join(v.Types, "|") != "TXT|TXT|TXT|TXT|TXT" {
			t.Fatalf("records %s: types changed: %q", name, v.Types)
		}
	}
	for name, v := range map[string]view{"en": r.En, "en again": r.Back} {
		if v.Title != "DNS records" || v.Badge != "DNS server" || v.Security != "Account security" || v.NewRecord != "New record" || !strings.HasPrefix(v.Doc, "DNS records") {
			t.Fatalf("stale strings after switching to English in place (%s): %+v", name, v)
		}
	}
	for name, v := range map[string]view{"zh load": r.First, "zh in place": r.Zh} {
		if v.Title == "DNS records" || v.Badge == "DNS server" || v.NewRecord == "New record" || v.Title == "" {
			t.Fatalf("shell not translated (%s): %+v", name, v)
		}
	}
	if r.First.Title != r.Zh.Title || r.First.Badge != r.Zh.Badge {
		t.Fatalf("zh-Hant shell differs between load and in-place switch: %+v / %+v", r.First, r.Zh)
	}

	// Import candidate table: rows carrying catalogue words as names and values.
	words, _ := json.Marshal(i18nDataWords)
	r = run(sso + "/admin/ui/import-preview/?zh=1&words=" + url.QueryEscape(string(words)))
	for name, v := range map[string]view{"zh load": r.First, "en": r.En, "zh in place": r.Zh} {
		if len(v.Candidates) != 4*len(i18nDataWords) {
			t.Fatalf("import %s: %d candidate cells: %q", name, len(v.Candidates), v.Candidates)
		}
		var names, values []string
		for i := 0; i+2 < len(v.Candidates); i += 4 {
			names, values = append(names, v.Candidates[i]), append(values, v.Candidates[i+2])
		}
		same("import candidate names "+name, names)
		same("import candidate values "+name, values)
	}

	// Private break-glass path in Traditional Chinese: Sign out sits in the user menu, and
	// switching to English in place leaves no Chinese shell strings.
	bg, _ := start(false)
	r = run(bg + "/admin/ui/?zh=1&bg=1")
	if r.First.Lang != "zh-Hant" || !r.First.LogoutInMenu || r.First.LogoutInHeader || !r.Zh.LogoutInMenu {
		t.Fatalf("break-glass path: Sign out is not in the user menu in zh-Hant: %+v", r)
	}
	if r.En.Title != "DNS records" || r.Back.Title != "DNS records" || r.En.Badge != "DNS server" {
		t.Fatalf("break-glass path: stale shell strings after switching to English: %+v", r)
	}
}

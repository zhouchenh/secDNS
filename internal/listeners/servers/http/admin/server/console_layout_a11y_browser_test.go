package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zhouchenh/secDNS/internal/recordset"
	"github.com/zhouchenh/secDNS/internal/recordstore"
)

// consoleLayoutFixture drives the real console pages (stubbed sessions only: the stand-in
// edge adds the synthetic SSO assertion server-side; no sign-in page, no passkey). Each
// scenario returns facts about layout, states and accessibility; the Go side asserts them.
const consoleLayoutFixture = `(()=>{const q=new URLSearchParams(location.search);const sc=q.get("scenario");
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const until=async(f,ms=12000)=>{const t=Date.now();while(Date.now()-t<ms){try{if(f())return true}catch(e){}await sleep(100)}return false};
const vis=e=>!!e&&!e.closest("[hidden]")&&getComputedStyle(e).display!=="none"&&getComputedStyle(e).visibility!=="hidden"&&e.getClientRects().length>0;
const T=e=>e?e.textContent.trim().replace(/\s+/g," "):null;
const put=o=>{const out=document.createElement("pre");out.id="fixture-result";out.textContent=JSON.stringify(o);document.body.append(out);};
const human=()=>window.secDNSAgent?.kind==="human";
const common=o=>{o.hscroll=document.documentElement.scrollWidth>innerWidth;o.width=innerWidth;
 o.mains=[...document.querySelectorAll("main,[role=main]")].filter(vis).length;o.banner=!!document.querySelector("body>header");o.nav=!!document.querySelector("nav[aria-label]");
 const fields=[...document.querySelectorAll("main input:not([type=hidden]),main select,main textarea")].filter(vis);
 o.unlabelled=fields.filter(f=>!(f.labels&&f.labels.length)&&!f.getAttribute("aria-label")&&!f.getAttribute("aria-labelledby")).map(f=>f.id||f.outerHTML.slice(0,60));
 o.positiveTabindex=document.querySelectorAll("[tabindex]:not([tabindex='0']):not([tabindex='-1'])").length;
 const first=[...document.querySelectorAll("a[href],button,input,select,textarea,[tabindex='0']")].find(e=>!e.closest("[hidden]")&&getComputedStyle(e).display!=="none");o.firstFocusable=first?first.className:"";
 o.offscreenActions=[...document.querySelectorAll("main button,main a[href]")].filter(vis).filter(b=>{const r=b.getBoundingClientRect();return r.right>innerWidth+0.5||r.left<-0.5;}).length;
 o.textBelow12=[...document.querySelectorAll("main *")].filter(e=>vis(e)&&[...e.childNodes].some(n=>n.nodeType===3&&n.nodeValue.trim())&&parseFloat(getComputedStyle(e).fontSize)<12).length;
 o.badge=document.querySelector(".env-badge")?.dataset.state||"";};
const S={
 async records(o){
  await until(()=>human()&&document.querySelectorAll("#rows tr").length>=50);await sleep(300);common(o);
  o.rows=document.querySelectorAll("#rows tr").length;o.showMore=vis(document.getElementById("show-more"))?T(document.getElementById("show-more")):"";o.showing=T(document.getElementById("show-more-info"));
  document.getElementById("show-more").click();await sleep(300);o.rowsAfter=document.querySelectorAll("#rows tr").length;o.showMoreAfter=vis(document.getElementById("show-more"));
  const row=document.querySelector("#rows tr"),edit=row.querySelector(".row-edit"),del=row.querySelector(".row-delete");
  o.deleteVisible=vis(del);o.editStretch=getComputedStyle(edit,"::after").position;o.copy=!!row.querySelector(".copy-name[aria-label]");
  o.innerScroll=(()=>{const w=document.querySelector(".console-record-table");const cs=getComputedStyle(w);return w.scrollHeight>w.clientHeight+2&&cs.overflowY!=="visible";})();
  o.stickyToolbar=getComputedStyle(document.getElementById("records-sticky")).position;
  const tb=document.querySelector(".console-record-table").getBoundingClientRect();
  edit.click();await until(()=>vis(document.getElementById("record-editor")));await sleep(200);
  const sheet=document.getElementById("record-editor"),sr=sheet.getBoundingClientRect(),tb2=document.querySelector(".console-record-table").getBoundingClientRect();
  o.sheetFixed=getComputedStyle(sheet).position==="fixed";o.sheetFull=Math.abs(sr.width-innerWidth)<2;o.tableReflow=Math.abs(tb.width-tb2.width)>1;o.deleteInSheet=vis(document.getElementById("delete-in-editor"));
  o.sheetFocus=document.activeElement?.id;
  document.getElementById("record-editor").dispatchEvent(new KeyboardEvent("keydown",{key:"Escape",bubbles:true}));await sleep(200);o.sheetClosed=!vis(sheet);
  // C33: three problems at once, each field marked and described, one summary.
  document.getElementById("new-record").click();await until(()=>vis(sheet));
  const set=(el,v)=>{el.value=v;el.dispatchEvent(new Event("input",{bubbles:true}));};
  set(document.getElementById("name"),"bad..name");set(document.getElementById("ttl"),"-1");set(document.querySelector("#values textarea"),"192.0.2.300");
  document.getElementById("stage").click();await sleep(300);
  const summary=document.getElementById("record-error");o.summaryVisible=vis(summary);o.summaryTitle=T(summary.querySelector("strong"));o.summaryItems=summary.querySelectorAll("li").length;o.summaryFocused=document.activeElement===summary;
  o.invalid=[...document.querySelectorAll("#editor [aria-invalid=true]")].map(f=>{const ids=(f.getAttribute("aria-describedby")||"").split(" ").filter(Boolean);return f.id.replace(/-\d+$/,"")+":"+ids.map(id=>vis(document.getElementById(id))?T(document.getElementById(id)):"HIDDEN:"+id).join("|");});
  set(document.getElementById("name"),"good.office.invalid.");set(document.getElementById("ttl"),"300");set(document.querySelector("#values textarea"),"192.0.2.30");
  document.getElementById("stage").click();await sleep(300);o.stagedAfterFix=!!document.querySelector('#rows tr[data-record-key="good.office.invalid/A"]');o.summaryCleared=!vis(summary);
  // C15: sort and filters in the address.
  const sort=document.getElementById("record-sort");sort.value="name";sort.dispatchEvent(new Event("change",{bubbles:true}));await sleep(200);
  o.url=location.search;o.firstName=T(document.querySelector("#rows tr .record-name"));
  return o;
 },
 async unreachable(o){
  await until(()=>vis(document.querySelector("#records-state .error-state")));await sleep(200);common(o);
  o.title=T(document.querySelector("#records-state h2"));o.cause=T(document.querySelector("#records-state p"));o.connection=T(document.getElementById("connection"));
  o.retry=T(document.getElementById("records-retry"));o.workspaceHidden=document.getElementById("workspace").hidden;o.statusShown=vis(document.getElementById("status"));
  await fetch("/fixture/ok",{cache:"no-store"});document.getElementById("records-retry").click();
  await until(()=>document.querySelectorAll("#rows tr").length>0);await sleep(300);o.recovered=document.querySelectorAll("#rows tr").length;o.errorGone=!document.querySelector("#records-state .error-state");o.connectionAfter=T(document.getElementById("connection"));o.badgeAfter=document.querySelector(".env-badge")?.dataset.state;
  return o;
 },
 async loading(o){
  // The snapshot request is held by the server; virtual time does not advance meanwhile, so
  // wait with a MutationObserver (no timers) and release it once the state is captured.
  await new Promise(res=>{const box=document.getElementById("records-state");let obs;const check=()=>{if(box.querySelector(".loading-state")){obs?.disconnect();res();return true;}return false;};if(!check()){obs=new MutationObserver(check);obs.observe(box,{childList:true,subtree:true});}});common(o);o.loading=T(document.querySelector("#records-state .loading-state"));o.connection=T(document.getElementById("connection"));o.skeleton=document.querySelectorAll(".skeleton-row").length;
  await fetch("/fixture/release",{cache:"no-store"});await until(()=>document.querySelectorAll("#rows tr").length>0);o.loadingGone=!document.querySelector(".loading-state");return o;
 },
 async empty(o){
  await until(()=>human()&&vis(document.getElementById("records-empty")));await sleep(200);common(o);
  o.title=T(document.querySelector("#records-empty h3"));o.actions=[...document.querySelectorAll("#records-empty button")].filter(vis).map(T);o.toolsHidden=!vis(document.querySelector(".console-record-tools"));
  return o;
 },
 async nodes(o){
  await until(()=>document.querySelectorAll(".node-row").length===3&&!/Checking/.test(T(document.getElementById("node-message"))));await sleep(300);common(o);
  o.order=[...document.querySelectorAll(".node-row")].map(a=>a.dataset.nodeRow);o.badges=[...document.querySelectorAll(".node-row .status-badge")].map(b=>(b.querySelector("svg")?"icon:":"")+T(b));
  o.rollup=T(document.getElementById("node-rollup"));o.descBelow=(()=>{const h=document.getElementById("page-title").getBoundingClientRect(),p=document.getElementById("page-description").getBoundingClientRect();return p.top>=h.bottom-1;})();
  o.headerTitle=T(document.querySelector(".topbar-title"));
  o.step="detail";location.hash="node=amd103";await until(()=>document.querySelector(".node-detail"));await sleep(300);
  o.detailFocus=document.activeElement?.tagName+":"+T(document.activeElement);o.tabs=[...document.querySelectorAll("[role=tab]")].map(t=>T(t)+"="+t.getAttribute("aria-selected"));
  o.drainInHeader=!!document.querySelector(".node-header [data-node-action=amd103]");
  o.step="tab";document.querySelectorAll("[role=tab]")[2].click();await until(()=>document.querySelector(".node-peer-table"));await sleep(200);
  o.peers=[...document.querySelectorAll(".node-peer-table tbody tr")].map(tr=>T(tr.querySelector("td strong,td span:not(.cell-label)")));o.selectedTab=T(document.querySelector("[role=tab][aria-selected=true]"));o.tabFocus=document.activeElement?.getAttribute("role");
  common(o);return o;
 },
 async health(o){
  await until(()=>document.querySelectorAll(".health-matrix tbody tr").length===3&&!/Checking/.test(T(document.getElementById("node-message"))));await sleep(300);common(o);
  o.order=[...document.querySelectorAll(".health-matrix tbody tr")].map(tr=>tr.dataset.node);o.cells=[...document.querySelectorAll(".health-matrix tbody tr:first-child td .status-badge")].map(T);
  o.why=T(document.querySelector(".health-reasons"));o.headers=[...document.querySelectorAll(".health-matrix thead th")].map(T);return o;
 },
 async allfail(o){
  await until(()=>vis(document.querySelector("#node-state .error-state")));await sleep(200);common(o);
  o.title=T(document.querySelector("#node-state h2"));o.retry=!!document.querySelector("#node-state button.primary");o.rows=[...document.querySelectorAll(".node-row")].map(T);o.message=T(document.getElementById("node-message"));return o;
 },
 async stale(o){
  await until(()=>document.querySelectorAll("[data-node-action]").length===3&&!/Checking/.test(T(document.getElementById("node-message"))));await sleep(300);common(o);
  const b=document.querySelector('[data-node-action="cix106"]');o.disabled=b.disabled;const ids=(b.getAttribute("aria-describedby")||"");o.reason=ids?T(document.getElementById(ids)):"";
  o.badge=T(document.querySelector('.node-card[data-node="cix106"] .status-badge'));return o;
 }};
addEventListener("load",async()=>{const o={scenario:sc};setTimeout(()=>{if(!document.getElementById("fixture-result")){o.error="timeout at step "+(o.step||"-")+" message="+T(document.getElementById("node-message"))+" rows="+document.querySelectorAll(".node-row").length;put(o);}},34000);try{await S[sc](o);}catch(e){o.error=String(e&&e.stack||e)}put(o);});})();`

func TestConsoleLayoutA11yBrowser(t *testing.T) {
	if os.Getenv("SECDNS_SSO_UX_BROWSER") != "1" {
		t.Skip("opt-in headless Chromium")
	}
	chrome := os.Getenv("SECDNS_CHROME")
	h, _ := ssoTestServer(t, true)
	h.UI = true
	store, err := recordstore.NewVersionedMemory(recordstore.Enrollment{RulesetID: "slice3", LineageID: "disposable"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	h.versioned = store
	var many []recordset.Record
	for i := 0; i < 60; i++ {
		many = append(many, recordset.Record{Name: fmt.Sprintf("host-%02d.branch-office-network.example.invalid.", 59-i), Type: "A", Values: []string{fmt.Sprintf("192.0.2.%d", i+1)}, TTLSeconds: 300})
	}
	seed := func(records []recordset.Record) {
		view, err := store.Acquire()
		if err != nil {
			t.Fatal(err)
		}
		m := view.Metadata()
		if _, err = store.Replace(recordstore.Expected{RulesetID: m.RulesetID, LineageID: m.LineageID, Revision: m.Revision}, fmt.Sprintf("seed-%d", m.Revision), records); err != nil {
			t.Fatal(err)
		}
	}
	var snapshotDown, hold, nodesDown, stale atomic.Bool
	release := make(chan struct{}, 1)
	h.nodeRunner = func(_ context.Context, action, node, id string) (nodeSnapshot, error) {
		if nodesDown.Load() {
			return nodeSnapshot{}, errors.New("fixture: node adapter unreachable")
		}
		return layoutNodeFixture(node, stale.Load() && node == "cix106"), nil
	}
	srv := httptest.NewUnstartedServer(nil)
	host := srv.Listener.Addr().String()
	_, port, _ := net.SplitHostPort(host)
	h.agent.origin = "https://" + host
	routes := h.routes()
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/fixture.js":
			w.Header().Set("Content-Type", "text/javascript")
			w.Write([]byte(consoleLayoutFixture))
			return
		case "/fixture/ok":
			snapshotDown.Store(false)
			w.WriteHeader(204)
			return
		case "/fixture/release":
			select {
			case release <- struct{}{}:
			default:
			}
			w.WriteHeader(204)
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), unixPeerKey{}, true))
		r.Header.Set("X-Forwarded-For", "203.0.113.7")
		r.Header.Set("X-Real-IP", "203.0.113.7")
		r.Header.Set("X-Forwarded-Proto", "https")
		r.Header.Set("X-Forwarded-Host", host)
		r.Header.Set("X-Forwarded-Port", port)
		r.Header.Set("X-Secdns-SSO-Secret", ssoTestSecret)
		r.Header.Set("X-Secdns-SSO-User", ssoTestUser)
		r.Header.Set("X-Secdns-SSO-Username", ssoTestName)
		r.Header.Set("X-Secdns-SSO-Roles", ssoTestRole)
		r.Header.Set("X-Secdns-SSO-Id-Token", "Bearer "+ssoTestJWT(map[string]any{"sub": ssoTestUser}))
		r.Header.Set("X-Secdns-SSO-Access-Token", ssoTestJWT(map[string]any{"sub": ssoTestUser}))
		if r.Method == http.MethodGet && r.URL.Path == "/admin/snapshot" {
			if snapshotDown.Load() {
				agentError(w, http.StatusServiceUnavailable, "snapshot_unavailable")
				return
			}
			if hold.Load() {
				select {
				case <-release:
				case <-time.After(20 * time.Second):
				}
				hold.Store(false)
			}
		}
		if strings.HasPrefix(r.URL.Path, "/admin/ui/") && strings.HasSuffix(r.URL.Path, "/") {
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
	var mu sync.Mutex
	run := func(width, height int, path string) map[string]any {
		t.Helper()
		mu.Lock()
		defer mu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, chrome, "--no-sandbox", "--ignore-certificate-errors", "--disable-gpu", "--hide-scrollbars",
			"--user-data-dir="+t.TempDir(), fmt.Sprintf("--window-size=%d,%d", width, height), "--virtual-time-budget=40000", "--dump-dom", "https://"+host+path)
		cmd.Env = append(os.Environ(), "LD_LIBRARY_PATH="+os.Getenv("SECDNS_CHROME_LIBS"))
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("chrome %s: %v", path, err)
		}
		m := regexp.MustCompile(`<pre id="fixture-result">([^<]*)</pre>`).FindSubmatch(out)
		if m == nil {
			t.Fatalf("%s at %d px: no fixture result (%d bytes)", path, width, len(out))
		}
		var result map[string]any
		text := strings.NewReplacer("&quot;", `"`, "&amp;", "&", "&lt;", "<", "&gt;", ">", "&#39;", "'").Replace(string(m[1]))
		if err := json.Unmarshal([]byte(text), &result); err != nil {
			t.Fatalf("%s: fixture result %s", path, m[1])
		}
		if result["error"] != nil {
			t.Fatalf("%s at %d px: fixture error: %v", path, width, result)
		}
		t.Logf("%s at %d px: %s", path, width, text)
		return result
	}
	str := func(r map[string]any, k string) string { s, _ := r[k].(string); return s }
	num := func(r map[string]any, k string) float64 { n, _ := r[k].(float64); return n }
	shared := func(r map[string]any, what string) {
		t.Helper()
		if r["hscroll"] != false || num(r, "mains") != 1 || r["banner"] != true || r["nav"] != true || num(r, "positiveTabindex") != 0 || num(r, "offscreenActions") != 0 || num(r, "textBelow12") != 0 {
			t.Errorf("%s at %v px: layout/landmarks: %v", what, r["width"], r)
		}
		if u, _ := r["unlabelled"].([]any); len(u) != 0 {
			t.Errorf("%s: unlabelled fields %v", what, u)
		}
		if str(r, "firstFocusable") != "console-skip" {
			t.Errorf("%s: the skip link must be the first focusable element, got %q", what, str(r, "firstFocusable"))
		}
	}

	for _, width := range []int{390, 820, 1280} {
		seed(many)
		r := run(width, 900, "/admin/ui/?scenario=records")
		shared(r, "records")
		if num(r, "rows") != 50 || str(r, "showMore") != "Show 10 more" || str(r, "showing") != "Showing 50 of 60" || num(r, "rowsAfter") != 60 || r["showMoreAfter"] != false {
			t.Errorf("%d px: Show more: %v", width, r)
		}
		if r["innerScroll"] != false || str(r, "stickyToolbar") != "sticky" || r["copy"] != true {
			t.Errorf("%d px: page scroll/sticky toolbar/copy: %v", width, r)
		}
		if r["sheetFixed"] != true || r["tableReflow"] != false || r["deleteInSheet"] != true || str(r, "sheetFocus") != "editor-title" || r["sheetClosed"] != true {
			t.Errorf("%d px: editor sheet: %v", width, r)
		}
		if width == 390 && (r["deleteVisible"] != false || str(r, "editStretch") != "absolute" || r["sheetFull"] != true) {
			t.Errorf("phone ListRow: %v", r)
		}
		if width == 1280 && (r["deleteVisible"] != true || str(r, "editStretch") == "absolute") {
			t.Errorf("desktop row actions: %v", r)
		}
		inv := fmt.Sprint(r["invalid"])
		if r["summaryVisible"] != true || str(r, "summaryTitle") != "Fix 3 problems before adding this record" || num(r, "summaryItems") != 3 || r["summaryFocused"] != true ||
			!strings.Contains(inv, "name:") || !strings.Contains(inv, "ttl:!Enter a whole number") || !strings.Contains(inv, "value:!192.0.2.300 is not a valid IPv4 address") || strings.Contains(inv, "HIDDEN") {
			t.Errorf("%d px: field validation: %v", width, r)
		}
		if r["stagedAfterFix"] != true || r["summaryCleared"] != true || !strings.Contains(str(r, "url"), "sort=name") || !strings.Contains(str(r, "url"), "scenario=records") || str(r, "firstName") != "good.office.invalid." {
			t.Errorf("%d px: staging after a fix / sort in URL: %v", width, r)
		}
	}
	for _, width := range []int{390, 1280} {
		snapshotDown.Store(true)
		r := run(width, 900, "/admin/ui/?scenario=unreachable")
		shared(r, "records unreachable")
		if str(r, "title") != "Records could not be loaded" || !strings.Contains(str(r, "cause"), "unavailable") || str(r, "connection") != "DNS server unreachable" || str(r, "badge") != "error" ||
			!strings.Contains(str(r, "retry"), "Try again") || r["statusShown"] != false {
			t.Errorf("%d px: records error state: %v", width, r)
		}
		if num(r, "recovered") != 50 || r["errorGone"] != true || str(r, "connectionAfter") != "Records loaded" || str(r, "badgeAfter") != "ok" {
			t.Errorf("%d px: Try again did not recover: %v", width, r)
		}
		hold.Store(true)
		r = run(width, 900, "/admin/ui/?scenario=loading")
		if !strings.Contains(str(r, "loading"), "Loading records") || str(r, "connection") != "Loading records…" || num(r, "skeleton") != 4 || r["loadingGone"] != true || r["hscroll"] != false {
			t.Errorf("%d px: loading state: %v", width, r)
		}
		seed([]recordset.Record{})
		r = run(width, 900, "/admin/ui/?scenario=empty")
		shared(r, "records empty")
		if str(r, "title") != "No records yet" || fmt.Sprint(r["actions"]) != "[New record Import records]" || r["toolsHidden"] != true {
			t.Errorf("%d px: empty state: %v", width, r)
		}
		seed(many)
	}
	for _, width := range []int{390, 1280} {
		r := run(width, 900, "/admin/ui/nodes/?scenario=nodes")
		shared(r, "nodes")
		if fmt.Sprint(r["order"]) != "[cix106 amd103 intel108]" || !strings.HasPrefix(fmt.Sprint(r["badges"]), "[icon:Degraded") || !strings.Contains(fmt.Sprint(r["badges"]), "icon:OK") ||
			!strings.Contains(str(r, "rollup"), "3 nodes") || r["descBelow"] != true || str(r, "headerTitle") != "Nodes" {
			t.Errorf("%d px: nodes list: %v", width, r)
		}
		if str(r, "detailFocus") != "H2:amd103" || fmt.Sprint(r["tabs"]) != "[Overview=true DNS health=false Routing=false]" || r["drainInHeader"] != true ||
			fmt.Sprint(r["peers"]) != "[intel108 intel108 cix106 cix106]" || str(r, "selectedTab") != "Routing" || str(r, "tabFocus") != "tab" {
			t.Errorf("%d px: node detail: %v", width, r)
		}
		r = run(width, 900, "/admin/ui/health/?scenario=health")
		shared(r, "health")
		if fmt.Sprint(r["order"]) != "[cix106 amd103 intel108]" || !strings.Contains(fmt.Sprint(r["cells"]), "Failing") || !strings.Contains(str(r, "why"), "Upstream did not answer in time") {
			t.Errorf("%d px: health matrix: %v", width, r)
		}
		nodesDown.Store(true)
		r = run(width, 900, "/admin/ui/nodes/?scenario=allfail")
		nodesDown.Store(false)
		shared(r, "nodes unreachable")
		if str(r, "title") != "Couldn’t reach any node" || r["retry"] != true || !strings.Contains(fmt.Sprint(r["rows"]), "No data yet") || str(r, "message") != "No node could be checked. Try again." || str(r, "badge") != "error" {
			t.Errorf("%d px: nodes error state: %v", width, r)
		}
		stale.Store(true)
		r = run(width, 900, "/admin/ui/routing/?scenario=stale")
		stale.Store(false)
		shared(r, "routing")
		if r["disabled"] != true || str(r, "reason") != "This observation is out of date. Refresh before changing this node.Refresh" || !strings.HasPrefix(str(r, "badge"), "Unknown") {
			t.Errorf("%d px: disabled reason: %v", width, r)
		}
	}
}

// layoutNodeFixture: amd103 and intel108 healthy; cix106 has a failing DNS64 upstream (or a stale
// observation). Peers are the other two nodes of the inventory, by IPv4 and IPv6.
func layoutNodeFixture(node string, old bool) nodeSnapshot {
	var profiles []map[string]any
	for _, role := range []string{"normal", "dns64"} {
		for _, family := range []int{4, 6} {
			ok := !(node == "cix106" && role == "dns64")
			reason := "ready"
			if !ok {
				reason = "upstream_probe_timeout"
			}
			profiles = append(profiles, map[string]any{"role": role, "family": family, "enabled": true, "healthy": ok, "local_healthy": true, "upstream_healthy": ok, "reason": reason, "advertised": ok, "prefix": fmt.Sprintf("192.0.2.%d/32", 50+family+len(role))})
		}
	}
	var peers []map[string]any
	for _, other := range nodeIDs {
		if other == node {
			continue
		}
		id := nodeBGPIdentities[other]
		peers = append(peers, map[string]any{"address": id.IPv4, "family": 4, "state": "Established"}, map[string]any{"address": id.IPv6, "family": 6, "state": "Established"})
	}
	observed := time.Now().UTC()
	if old {
		observed = observed.Add(-10 * time.Minute)
	}
	raw := map[string]any{"schema": 1, "node": node, "observed_at": observed, "reachable": true, "stale": old, "daemon": map[string]any{"active": true, "pid": 100},
		"maintenance": map[string]bool{"withdraw": false}, "profiles": profiles, "peers": peers}
	data, _ := json.Marshal(raw)
	var out nodeSnapshot
	_ = json.Unmarshal(data, &out)
	return out
}

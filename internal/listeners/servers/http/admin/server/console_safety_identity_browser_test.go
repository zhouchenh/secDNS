package server

import (
	"context"
	"encoding/json"
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

// consoleSafetyIdentityFixture drives the real console pages (stubbed sessions only: the
// stand-in edge adds the synthetic SSO assertion server-side and never shows a sign-in page).
// Scenarios: "stepup" (edits, refused action, step-up round trip, kept drafts, replay,
// sign-out clears drafts), "drain" (C22 dialog), "dates" (in-place language switch), "busy"
// (C31) and "expire" (C28). A scenario that navigates stores its state in sessionStorage and
// the next page continues it.
const consoleSafetyIdentityFixture = `(()=>{const q=new URLSearchParams(location.search);
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const until=async(f,ms=9000)=>{const t=Date.now();while(Date.now()-t<ms){try{if(f())return true}catch(e){}await sleep(100)}return false};
const vis=e=>!!e&&!e.closest("[hidden]")&&getComputedStyle(e).display!=="none"&&e.getClientRects().length>0;
const T=e=>e?e.textContent.trim().replace(/\s+/g," "):null;
const put=o=>{const out=document.createElement("pre");out.id="fixture-result";out.textContent=JSON.stringify(o);document.body.append(out);};
let sc=q.get("scenario");if(sc)sessionStorage.setItem("fx-scenario",sc);else sc=sessionStorage.getItem("fx-scenario");
const phase=sessionStorage.getItem("fx-phase")||"1";
const records=()=>until(()=>window.secDNSAgent?.kind==="human"&&document.querySelectorAll("#rows tr").length>=4);
const rowOf=name=>[...document.querySelectorAll("#rows tr")].find(tr=>T(tr.querySelector(".record-name"))===name);
const btn=(root,text)=>root?[...root.querySelectorAll("button")].find(b=>T(b)===text):null;
const S={
 async stepup(o){
  if(phase==="1"){
   await records();await sleep(300);
   btn(rowOf("mail.office.invalid."),"Delete").click();await until(()=>document.getElementById("delete-dialog").open);
   o.deleteDetails=T(document.getElementById("delete-record"));o.deleteClass=document.getElementById("delete-confirm").className;o.deleteTitle=T(document.getElementById("delete-title"));
   document.getElementById("delete-confirm").click();await sleep(300);
   let removed=rowOf("mail.office.invalid.");o.removedMarked=!!removed&&removed.classList.contains("row-removed");o.removedHasUndo=!!btn(removed,"Undo");
   btn(removed,"Undo").click();await sleep(300);o.undoRestored=!rowOf("mail.office.invalid.").classList.contains("row-removed");
   btn(rowOf("mail.office.invalid."),"Delete").click();await until(()=>document.getElementById("delete-dialog").open);document.getElementById("delete-confirm").click();await sleep(300);
   document.getElementById("new-record").click();await sleep(200);
   document.getElementById("name").value="kept.office.invalid.";document.querySelector("#values textarea").value="192.0.2.77";document.getElementById("editor").dispatchEvent(new Event("input",{bubbles:true}));
   document.getElementById("stage").click();await sleep(300);o.addedPending=!!rowOf("kept.office.invalid.");
   o.pendingBar=T(document.getElementById("pending-counts"));o.reviewButtonClass=document.getElementById("review").className;
   document.getElementById("review").click();await until(()=>document.getElementById("review-dialog").open);await sleep(200);
   o.reviewGroups=[...document.querySelectorAll("#review-records .review-group > summary")].map(T);o.reviewConfirmClass=document.getElementById("review-confirm").className;o.reviewConfirm=T(document.getElementById("review-confirm"));
   document.getElementById("review-cancel").click();await sleep(200);
   document.getElementById("console-account").click();await until(()=>vis(document.getElementById("human-security")));await sleep(200);
   o.stepUpStateBefore=T(document.querySelector(".step-up-state"));o.cards=[...document.querySelectorAll("#human-security .sso-card > h3")].map(T);
   btn(document.getElementById("human-security"),"Sign out other sessions").click();
   await until(()=>document.getElementById("step-up-dialog")?.open);o.dialogTitle=T(document.querySelector("#step-up-dialog h2"));o.dialogWarn=document.getElementById("step-up-dialog").classList.contains("warn-dialog");
   sessionStorage.setItem("fx-phase","2");sessionStorage.setItem("fx-phase1",JSON.stringify(o));
   btn(document.getElementById("step-up-dialog"),"Confirm with WithMy ID").click();return null;
  }
  Object.assign(o,JSON.parse(sessionStorage.getItem("fx-phase1")||"{}"));o.phase=2;
  await records();await until(()=>/Your unsaved changes were kept/.test(T(document.getElementById("status"))||""));
  await until(()=>/other sessions are signed out|not renewed/i.test(T(document.querySelector("#human-access > p[role=status]"))||""));await sleep(300);
  o.status=T(document.getElementById("status"));o.note=T(document.querySelector("#human-access > p[role=status]"));
  o.keptAdded=!!rowOf("kept.office.invalid.");o.keptRemoved=!!rowOf("mail.office.invalid.")?.classList.contains("row-removed");
  o.accountOpen=vis(document.getElementById("human-security"));o.stepUpStateAfter=T(document.querySelector(".step-up-state"));
  o.leftover=Object.keys(sessionStorage).filter(k=>k.startsWith("secdns.draft.")).length;
  await window.secDNSAgent.drafts.preserve(null);o.keptBeforeSignOut=Object.keys(sessionStorage).filter(k=>k.startsWith("secdns.draft.")).length;
  sessionStorage.removeItem("fx-phase");sessionStorage.setItem("fx-final",JSON.stringify(o));window.secDNSAgent.logout();return null;
 },
 async drain(o){
  await until(()=>document.querySelectorAll("[data-node-action]").length===3&&[...document.querySelectorAll("[data-node-action]")].every(b=>!b.disabled),15000);await sleep(300);
  const dialog=document.getElementById("maintenance-dialog"),apply=document.getElementById("apply-maintenance"),block=document.getElementById("maintenance-block");
  const open=async id=>{document.querySelector('[data-node-action="'+id+'"]').click();await until(()=>dialog.open);await sleep(200);};
  const stamp=()=>T(document.querySelector('.node-card .meta [data-i18n-at]'));
  o.lastEn=stamp();window.secDNSI18n.setLanguage("zh-Hant");await sleep(300);o.lastZh=stamp();window.secDNSI18n.setLanguage("en");await sleep(300);o.lastBack=stamp();
  await open("cix106");o.blockedTitle=T(document.getElementById("maintenance-title"));o.blockedDisabled=apply.disabled;o.blockVisible=vis(block);o.blockText=T(block);document.getElementById("cancel-maintenance").click();await sleep(200);
  await open("amd103");o.title=T(document.getElementById("maintenance-title"));o.applyText=T(apply);o.applyClass=apply.className;o.applyDisabled=apply.disabled;o.impact=T(document.getElementById("maintenance-impact"));o.blockHidden=!vis(block);
  const r=dialog.getBoundingClientRect();o.sheet=Math.abs(r.bottom-innerHeight)<2&&Math.abs(r.width-innerWidth)<2;
  apply.click();await until(()=>document.querySelector(".node-operation.confirmed"),9000);
  const resume=btn(document.querySelector(".node-operation.confirmed"),"Resume announcements");o.resumeOffered=!!resume;
  if(resume){resume.click();await until(()=>dialog.open);await sleep(200);o.resumeTitle=T(document.getElementById("maintenance-title"));o.resumeText=T(apply);o.resumeClass=apply.className;document.getElementById("cancel-maintenance").click();}
  return o;
 },
 async dates(o){
  await records();await sleep(300);const el=()=>document.querySelector("#rows .record-expiry, #rows .record-expired");
  o.en1=T(el());window.secDNSI18n.setLanguage("zh-Hant");await sleep(300);o.zh=T(el());window.secDNSI18n.setLanguage("en");await sleep(300);o.en2=T(el());
  return o;
 },
 async zh(o){
  await records();await sleep(300);window.secDNSI18n.setLanguage("zh-Hant");await sleep(400);
  const del=[...document.querySelectorAll("#rows button")].find(b=>T(b)==="刪除");o.deleteFound=!!del;
  del.click();await until(()=>document.getElementById("delete-dialog").open);document.getElementById("delete-confirm").click();await sleep(400);
  o.englishButtons=[...document.querySelectorAll("#rows button")].filter(b=>/^(Edit|Delete|Undo)$/.test(T(b))).length;
  o.pendingBar=T(document.getElementById("pending-counts"));o.expiry=T(document.querySelector("#rows .record-expiry"));o.marker=T(document.querySelector("#rows .removal-marker"));
  o.managed=[...document.querySelectorAll("#human-access p")].some(p=>T(p)==="你的登入由 WithMy ID 管理。");o.cards=[...document.querySelectorAll("#human-security .sso-card > h3")].map(T);
  return o;
 },
 async busy(o){
  await until(()=>vis(document.querySelector(".sso-busy")));o.title=T(document.querySelector("#human-access h2"));o.reason=T(document.querySelector(".sso-signed-out-reason"));
  o.signInLinkVisible=vis(document.querySelector(".sso-signed-out"));const retry=btn(document.querySelector(".sso-busy"),"Try again");o.retry=!!retry;
  retry?.click();await until(()=>window.secDNSAgent?.kind==="human");o.human=window.secDNSAgent?.kind==="human";await sleep(200);o.busyHidden=!vis(document.querySelector(".sso-busy"));
  return o;
 },
 async expire(o){
  await records();window.secDNSAgent.expire();await until(()=>vis(document.querySelector(".sso-signed-out")));await sleep(200);
  o.title=T(document.querySelector("#human-access h2"));o.reason=T(document.querySelector(".sso-signed-out-reason"));o.href=document.querySelector(".sso-signed-out a")?.getAttribute("href");o.link=T(document.querySelector(".sso-signed-out a"));
  return o;
 }};
addEventListener("load",async()=>{const o={scenario:sc};let r;try{r=await S[sc](o);}catch(e){o.error=String(e&&e.stack||e);r=o;}try{localStorage.removeItem("secdns.lang")}catch(e){}if(r)put(r);});})();`

// consoleSignedOutStandIn is the page the edge's sign-out lands on ("/"): it reports the
// state the fixture stored before signing out and whether any kept draft survived it.
const consoleSignedOutStandIn = `<!doctype html><title>edge stand-in</title><script>addEventListener("load",()=>{let o={};try{o=JSON.parse(sessionStorage.getItem("fx-final")||"{}")}catch(e){}
o.afterSignOut=Object.keys(sessionStorage).filter(k=>k.startsWith("secdns.draft.")).length;const p=document.createElement("pre");p.id="fixture-result";p.textContent=JSON.stringify(o);document.body.append(p);});</script>`

func safetyNodeFixture(node string, withdraw bool, operation map[string]any) nodeSnapshot {
	type profile struct {
		Role       string `json:"role"`
		Family     int    `json:"family"`
		Enabled    bool   `json:"enabled"`
		Healthy    bool   `json:"healthy"`
		Local      bool   `json:"local_healthy"`
		Upstream   bool   `json:"upstream_healthy"`
		Reason     string `json:"reason"`
		Advertised bool   `json:"advertised"`
		Prefix     string `json:"prefix"`
	}
	prefixes := map[string][]string{
		"amd103":   {"192.0.2.53/32", "192.0.2.64/32"},
		"intel108": {"192.0.2.53/32", "192.0.2.64/32"},
		"cix106":   {"192.0.2.53/32", "192.0.2.99/32"}, // the only provider of 192.0.2.99/32
	}[node]
	var profiles []profile
	for i, p := range prefixes {
		role := "normal"
		if i == 1 {
			role = "dns64"
		}
		profiles = append(profiles, profile{role, 4, true, true, true, true, "ready", !withdraw, p})
	}
	snapshot := map[string]any{"schema": 1, "node": node, "observed_at": time.Now().UTC(), "reachable": true, "stale": false,
		"daemon": map[string]any{"active": true, "pid": 100}, "maintenance": map[string]bool{"withdraw": withdraw}, "profiles": profiles,
		"peers": []map[string]any{{"address": "192.0.2.1", "family": 4, "state": "Established", "prefixes": prefixes}}}
	if operation != nil {
		snapshot["operation"] = operation
	}
	raw, _ := json.Marshal(snapshot)
	var out nodeSnapshot
	json.Unmarshal(raw, &out)
	return out
}

// TestConsoleSafetyIdentityBrowser (slice 2) checks in headless Chromium, with stubbed sessions
// only: step-up keeps drafts and replays the refused action once (and does not when the
// sign-in was not renewed), sign-out clears kept drafts, the delete/review/drain dialogs,
// dates re-rendered on an in-place language switch, the session-cap card and the
// signed-out card. Opt-in, like TestSSOConsoleUXBrowser: SECDNS_SSO_UX_BROWSER=1, SECDNS_CHROME.
func TestConsoleSafetyIdentityBrowser(t *testing.T) {
	if os.Getenv("SECDNS_SSO_UX_BROWSER") != "1" {
		t.Skip("opt-in headless Chromium")
	}
	chrome := os.Getenv("SECDNS_CHROME")
	h, _ := ssoTestServer(t, true)
	h.UI = true
	store, err := recordstore.NewVersionedMemory(recordstore.Enrollment{RulesetID: "slice2", LineageID: "disposable"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	h.versioned = store
	seed := []recordset.Record{
		{Name: "gateway.office.invalid.", Type: "A", Values: []string{"192.0.2.21"}, TTLSeconds: 300},
		{Name: "mail.office.invalid.", Type: "A", Values: []string{"192.0.2.25"}, TTLSeconds: 300},
		{Name: "intranet.office.invalid.", Type: "A", Values: []string{"192.0.2.26"}, TTLSeconds: 300},
		{Name: "printer.office.invalid.", Type: "A", Values: []string{"192.0.2.27"}, TTLSeconds: 300, ExpiresAt: "2030-12-31T12:00:00Z"},
		{Name: "files.office.invalid.", Type: "AAAA", Values: []string{"2001:db8::27"}, TTLSeconds: 300},
	}
	reseed := func() {
		view, err := store.Acquire()
		if err != nil {
			t.Fatal(err)
		}
		m := view.Metadata()
		if _, err = store.Replace(recordstore.Expected{RulesetID: m.RulesetID, LineageID: m.LineageID, Revision: m.Revision}, fmt.Sprintf("seed-%d", m.Revision), seed); err != nil {
			t.Fatal(err)
		}
	}
	var mu sync.Mutex
	withdrawn := map[string]bool{}
	h.nodeRunner = func(_ context.Context, action, node, id string) (nodeSnapshot, error) {
		mu.Lock()
		defer mu.Unlock()
		if action == "drain" || action == "resume" {
			withdrawn[node] = action == "drain"
		}
		var operation map[string]any
		if action == "drain" || action == "resume" {
			operation = map[string]any{"request_id": id, "action": action, "confirmed": true, "status": "confirmed"}
		}
		return safetyNodeFixture(node, withdrawn[node], operation), nil
	}
	var fresh, renew atomic.Bool
	var busyLeft, revokes atomic.Int32
	srv := httptest.NewUnstartedServer(nil)
	host := srv.Listener.Addr().String()
	_, port, _ := net.SplitHostPort(host)
	h.agent.origin = "https://" + host
	routes := h.routes()
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/fixture.js":
			w.Header().Set("Content-Type", "text/javascript")
			w.Write([]byte(consoleSafetyIdentityFixture))
			return
		case r.URL.Path == "/oauth2/sign_out":
			// Edge stand-in: ends the edge session and returns to rd; when renew is set, the
			// next WithMy ID sign-in is interactive (auth_time = now). Never a sign-in page.
			rd := r.URL.Query().Get("rd")
			if rd == "/" {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.Write([]byte(consoleSignedOutStandIn))
				return
			}
			if !strings.HasPrefix(rd, "/admin/") {
				http.Error(w, "unexpected return path", 400)
				return
			}
			fresh.Store(renew.Load())
			http.Redirect(w, r, rd, http.StatusFound)
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), unixPeerKey{}, true))
		r.Header.Set("X-Forwarded-For", "203.0.113.7")
		r.Header.Set("X-Real-IP", "203.0.113.7")
		r.Header.Set("X-Forwarded-Proto", "https")
		r.Header.Set("X-Forwarded-Host", host)
		r.Header.Set("X-Forwarded-Port", port)
		claims := map[string]any{"sub": ssoTestUser}
		if fresh.Load() {
			claims["auth_time"] = time.Now().Unix()
		}
		r.Header.Set("X-Secdns-SSO-Secret", ssoTestSecret)
		r.Header.Set("X-Secdns-SSO-User", ssoTestUser)
		r.Header.Set("X-Secdns-SSO-Username", ssoTestName)
		r.Header.Set("X-Secdns-SSO-Roles", ssoTestRole)
		r.Header.Set("X-Secdns-SSO-Id-Token", "Bearer "+ssoTestJWT(claims))
		r.Header.Set("X-Secdns-SSO-Access-Token", ssoTestJWT(map[string]any{"sub": ssoTestUser}))
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/auth/login/sso") && busyLeft.Load() > 0 {
			busyLeft.Add(-1)
			agentError(w, 503, "auth_unavailable") // all session slots in use
			return
		}
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/auth/sessions/revoke-others") {
			rec := &captureWriter{header: http.Header{}}
			routes.ServeHTTP(rec, r)
			if rec.status() == 200 {
				revokes.Add(1)
			}
			for k, v := range rec.header {
				w.Header()[k] = v
			}
			w.WriteHeader(rec.status())
			w.Write([]byte(rec.body.String()))
			return
		}
		if r.URL.Path == "/admin/ui/" || r.URL.Path == "/admin/ui/routing/" {
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
	run := func(width, height int, path string) map[string]any {
		t.Helper()
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

	for _, width := range []int{390, 1280} {
		// C25/C26/C27 with a renewed sign-in: edits survive the round trip, the refused action runs once.
		reseed()
		fresh.Store(false)
		renew.Store(true)
		before := revokes.Load()
		r := run(width, 900, "/admin/ui/?scenario=stepup")
		if r["phase"] != 2.0 || r["keptAdded"] != true || r["keptRemoved"] != true || !strings.Contains(str(r, "status"), "Your unsaved changes were kept") {
			t.Fatalf("%d px: drafts lost across step-up: %v", width, r)
		}
		if str(r, "note") != "Confirmed. Your other sessions are signed out." || revokes.Load() != before+1 || r["accountOpen"] != true || !strings.HasPrefix(str(r, "stepUpStateAfter"), "Verified at ") {
			t.Fatalf("%d px: refused action not replayed exactly once after a fresh sign-in: %v (revokes %d)", width, r, revokes.Load()-before)
		}
		if str(r, "stepUpStateBefore") != "Not confirmed in the last 5 minutes." || str(r, "dialogTitle") != "Confirm it's you first" || r["dialogWarn"] != true {
			t.Fatalf("%d px: stale step-up state or refusal dialog: %v", width, r)
		}
		if fmt.Sprint(r["cards"]) != "[Signed in as Confirm it's you Sessions]" {
			t.Fatalf("%d px: account security cards: %v", width, r["cards"])
		}
		if num(r, "leftover") != 0 || num(r, "keptBeforeSignOut") != 1 || num(r, "afterSignOut") != 0 {
			t.Fatalf("%d px: kept drafts not consumed or not cleared by sign-out: %v", width, r)
		}
		// C21/C23
		if !strings.Contains(str(r, "deleteDetails"), "mail.office.invalid.") || !strings.Contains(str(r, "deleteDetails"), "192.0.2.25") || str(r, "deleteClass") != "danger-solid" || str(r, "deleteTitle") != "Delete this record?" {
			t.Fatalf("%d px: delete dialog: %v", width, r)
		}
		if r["removedMarked"] != true || r["removedHasUndo"] != true || r["undoRestored"] != true || r["addedPending"] != true {
			t.Fatalf("%d px: row Undo: %v", width, r)
		}
		if str(r, "reviewConfirmClass") != "danger-solid" || str(r, "reviewButtonClass") != "danger-solid" || fmt.Sprint(r["reviewGroups"]) != "[Will be deleted1 Will be added1]" || str(r, "pendingBar") != "1 added1 removed" {
			t.Fatalf("%d px: grouped review / pending bar: %v", width, r)
		}
	}
	// Not renewed (the identity provider did not ask again): drafts kept, nothing replayed.
	reseed()
	fresh.Store(false)
	renew.Store(false)
	before := revokes.Load()
	r := run(390, 900, "/admin/ui/?scenario=stepup")
	if r["keptAdded"] != true || !strings.Contains(str(r, "note"), "was not renewed") || revokes.Load() != before {
		t.Fatalf("stale return replayed the refused action or lost drafts: %v", r)
	}
	// C22 drain dialog: phone sheet and desktop.
	for _, width := range []int{390, 1280} {
		mu.Lock()
		withdrawn = map[string]bool{}
		mu.Unlock()
		fresh.Store(false)
		r := run(width, 900, "/admin/ui/routing/?scenario=drain")
		if r["blockedDisabled"] != true || r["blockVisible"] != true || !strings.Contains(str(r, "blockText"), "cix106 is the last healthy node serving 192.0.2.99/32") {
			t.Fatalf("%d px: draining the last healthy provider is not blocked: %v", width, r)
		}
		if str(r, "title") != "Drain amd103?" || str(r, "applyText") != "Drain amd103" || str(r, "applyClass") != "danger-solid" || r["applyDisabled"] != false || r["blockHidden"] != true ||
			!strings.Contains(str(r, "impact"), "192.0.2.53/32Still served by intel108, cix106") || !strings.Contains(str(r, "impact"), "192.0.2.64/32Still served by intel108") {
			t.Fatalf("%d px: drain dialog: %v", width, r)
		}
		if width == 390 && r["sheet"] != true {
			t.Fatalf("drain dialog is not a bottom sheet on a phone: %v", r)
		}
		if r["resumeOffered"] != true || str(r, "resumeTitle") != "Resume amd103?" || str(r, "resumeText") != "Resume amd103" || str(r, "resumeClass") != "primary" {
			t.Fatalf("%d px: Resume after drain: %v", width, r)
		}
		if !strings.HasPrefix(str(r, "lastEn"), "Last checked: ") || !strings.HasPrefix(str(r, "lastZh"), "上次檢查：") || strings.Contains(str(r, "lastZh"), "AM") || strings.Contains(str(r, "lastZh"), "PM") || !strings.HasPrefix(str(r, "lastBack"), "Last checked: ") {
			t.Fatalf("%d px: node time not re-rendered on a language switch: %v", width, r)
		}
	}
	// Slice-1 leftover: plain-text dates re-render on an in-place language switch.
	reseed()
	r = run(1280, 900, "/admin/ui/?scenario=dates")
	if !strings.Contains(str(r, "en1"), "Dec 31, 2030") || !strings.Contains(str(r, "zh"), "2030年12月31日") || strings.Contains(str(r, "zh"), "Dec") || !strings.HasSuffix(str(r, "zh"), "到期") || str(r, "en2") != str(r, "en1") {
		t.Fatalf("record expiry not re-rendered on a language switch: %v", r)
	}
	// zh-Hant: text built in the same task as a re-rendered date is still translated.
	r = run(1280, 900, "/admin/ui/?scenario=zh")
	if r["deleteFound"] != true || num(r, "englishButtons") != 0 || str(r, "pendingBar") != "移除 1 項" || !strings.HasPrefix(str(r, "expiry"), "於 ") || str(r, "marker") != "將會刪除" ||
		r["managed"] != true || fmt.Sprint(r["cards"]) != "[目前登入身分 確認是你本人 工作階段]" {
		t.Fatalf("zh-Hant page left English text: %v", r)
	}
	// C31: all session slots in use, then Retry in place.
	busyLeft.Store(1)
	r = run(390, 900, "/admin/ui/?scenario=busy")
	if str(r, "title") != "secDNS is busy right now" || r["retry"] != true || r["signInLinkVisible"] != false || r["human"] != true || r["busyHidden"] != true || !strings.HasPrefix(str(r, "reason"), "The sign-in service was busy at ") {
		t.Fatalf("session-cap card: %v", r)
	}
	// C28: signed-out card with reason, time and return-to.
	r = run(390, 900, "/admin/ui/?scenario=expire")
	if str(r, "title") != "Signed out of the console" || !strings.HasPrefix(str(r, "reason"), "Your console session ended at ") || str(r, "href") != "/admin/ui/" || str(r, "link") != "Sign in with WithMy ID" {
		t.Fatalf("signed-out card: %v", r)
	}
}

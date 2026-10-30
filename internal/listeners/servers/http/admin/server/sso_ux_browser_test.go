package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zhouchenh/secDNS/internal/recordset"
	"github.com/zhouchenh/secDNS/internal/recordstore"
)

// ssoUXFixture is injected only by this test server. It waits for the console
// to settle, then reports layout facts; it never fills a sign-in form.
const ssoUXFixture = `(()=>{const q=new URLSearchParams(location.search);const out=document.createElement("pre");out.id="fixture-result";
const vis=e=>!!e&&!e.closest("[hidden]")&&getComputedStyle(e).display!=="none"&&getComputedStyle(e).visibility!=="hidden"&&e.getClientRects().length>0;
const lines=e=>{const r=document.createRange();r.selectNodeContents(e);const tops=[...r.getClientRects()].filter(x=>x.width>0).map(x=>x.top).sort((a,b)=>a-b);let n=0,last=-1e9;for(const t of tops){if(t>last+4){n++;last=t;}}return n;};
const done=()=>{const W=innerWidth,o={width:W};const texts=document.body.innerText;
o.signInForm=vis(document.getElementById("human-password"))||vis(document.getElementById("human-username"))||[...document.querySelectorAll('input[type="password"]')].some(vis)||!!document.querySelector('input[type="password"]#token');
o.agentAccess=vis(document.getElementById("agent-access"))||vis(document.getElementById("agent-credential"));
o.forbiddenText=["Sign in to secDNS","Use a recovery code","Agent access","Current password","Change password","Replace authenticator","Legacy token access","Legacy admin access token","Sign in with a passkey"].filter(t=>texts.includes(t)&&[...document.querySelectorAll("h2,h3,button,label,summary")].some(e=>vis(e)&&e.textContent.trim()===t));
o.signedOutLink=[...document.querySelectorAll("a")].some(a=>vis(a)&&a.textContent==="Sign in with WithMy ID");
o.human=window.secDNSAgent?.kind==="human";o.hscroll=document.documentElement.scrollWidth>W;
const rows=[...document.querySelectorAll("#rows tr")];o.rows=rows.length;
o.actionsOffscreen=[...document.querySelectorAll("#rows button")].filter(b=>{const r=b.getBoundingClientRect();return r.right>W+0.5||r.left<-0.5;}).length;
o.ipMultiLine=[...document.querySelectorAll("#rows .record-ip")].filter(e=>lines(e)>1).length;
o.ttlClipped=rows.filter(r=>r.children[3]).filter(r=>{const t=r.children[3].getBoundingClientRect();return t.right>W+0.5;}).length;
const fq=[...document.querySelectorAll("#rows .record-fqdn,#rows .record-name")];o.fqdnBadBreakList=fq.filter(e=>lines(e)>1&&e.textContent.length<30).map(e=>e.textContent+":"+lines(e));o.fqdnBadBreak=o.fqdnBadBreakList.length;
o.fqdnMidLabel=fq.filter(e=>{const r=document.createRange();const tn=[...e.childNodes].filter(n=>n.nodeType===3);let prev=null,bad=false;for(const n of tn){for(let i=0;i<n.length;i++){r.setStart(n,i);r.setEnd(n,i+1);const t=Math.round(r.getBoundingClientRect().top);if(prev!==null&&t>prev+2){const ch=i>0?n.data[i-1]:"";if(i>0&&ch!=="."&&ch!=="-"&&n.data.split(".")[0].length<40)bad=true;}prev=t;}}return bad;}).length;
const pill=document.querySelector(".account-menu>summary"),conn=document.getElementById("connection");o.pillWidth=pill?Math.round(pill.getBoundingClientRect().width):-1;
o.statusOverlapsPill=!!(pill&&vis(conn)&&(()=>{const a=pill.getBoundingClientRect(),b=conn.getBoundingClientRect();return Math.abs((a.left+a.right)/2-(b.left+b.right)/2)<(a.width+b.width)/2+8&&Math.abs(a.top-b.top)<a.height;})());
const wrap=document.querySelector(".console-record-table");if(wrap){const cs=getComputedStyle(wrap);o.wrap=[cs.maxHeight,cs.overflow,Math.round(wrap.clientHeight),wrap.scrollHeight];o.clipped=wrap.scrollHeight>wrap.clientHeight+2&&cs.overflowY!=="visible";}
const g=[...document.querySelectorAll("#rows tr")].map(r=>{const c=r.children[0];return c?Math.round(c.getBoundingClientRect().width):0;});o.nameWidths=g;
o.stepUp=[...document.querySelectorAll("button")].some(b=>vis(b)&&b.textContent==="Confirm with WithMy ID");o.revokeOthers=[...document.querySelectorAll("button")].some(b=>vis(b)&&b.textContent==="Sign out other sessions");
const forbid=/break[- ]?glass|recovery|password|totp|authenticator|\blocal\b|human session/i,leak=[];
const scan=root=>{if(!root)return;const w=document.createTreeWalker(root,NodeFilter.SHOW_TEXT);for(let n=w.nextNode();n;n=w.nextNode()){if(n.parentElement?.closest("script,style"))continue;if(forbid.test(n.data))leak.push(n.data.trim().slice(0,80));}
for(const e of [root,...root.querySelectorAll("*")]){for(const a of ["id","alt","aria-label","placeholder","title","value"]){const v=e.getAttribute(a);if(v&&forbid.test(v))leak.push(a+"="+v.slice(0,80));}if(e.matches('input[type="password"],textarea'))leak.push("credential field #"+e.id);}};
scan(document.getElementById("human-access"));scan(document.getElementById("passkey-access"));
if(q.get("account")||q.get("expire")){for(const line of document.body.innerText.split(/\n/))if(forbid.test(line))leak.push("visible: "+line.trim().slice(0,80));}
o.identityLeak=leak;o.managedBy=[...document.querySelectorAll("#human-access p")].some(p=>vis(p)&&p.textContent.trim()==="Your sign-in is managed by WithMy ID.");
o.sso=window.secDNSAgent?.state?.sso_login===true;if(window.__replaceResult)o.replace=window.__replaceResult;out.textContent=JSON.stringify(o);document.body.append(out);};
if(q.get("replace")){const sleep=ms=>new Promise(r=>setTimeout(r,ms)),until=async(f,ms=8000)=>{const t=Date.now();while(Date.now()-t<ms){if(f())return true;await sleep(100);}return false;};(async()=>{const r={};try{
await until(()=>window.secDNSAgent?.kind==="human"&&document.querySelectorAll("#rows tr").length>=8);await sleep(1000);
for(let i=0;i<15&&document.querySelectorAll("#rows tr").length>3;i++){const b=[...document.querySelectorAll("#rows button")].find(x=>x.textContent==="Delete");b.click();await sleep(200);document.getElementById("delete-confirm").click();await sleep(250);}
r.rowsBefore=document.querySelectorAll("#rows tr").length;
document.getElementById("review").click();await until(()=>document.getElementById("review-dialog").open);await sleep(400);
const danger=document.getElementById("review-danger"),btn=document.getElementById("review-confirm"),typed=document.getElementById("review-typed");
const inView=e=>{const b=e.getBoundingClientRect();return b.height>0&&b.top>=-0.5&&b.bottom<=innerHeight+0.5;};
r.open=document.getElementById("review-dialog").open;r.dangerVisible=vis(danger);r.dangerText=document.getElementById("review-danger-title").textContent;r.confirmText=btn.textContent;r.confirmClass=btn.className;
r.typedVisible=vis(typed);r.disabledBefore=btn.disabled;r.dangerInView=inView(danger);r.confirmInView=inView(btn);
const list=document.getElementById("review-records");list.scrollTop=list.scrollHeight;await sleep(100);r.dangerInViewScrolled=inView(danger);r.confirmInViewScrolled=inView(btn);
typed.value="4";typed.dispatchEvent(new Event("input"));r.disabledWrong=btn.disabled;typed.value="5";typed.dispatchEvent(new Event("input"));r.disabledRight=btn.disabled;
btn.click();await until(()=>/saved/i.test(document.getElementById("status").textContent));r.status=document.getElementById("status").textContent;r.rowsAfter=document.querySelectorAll("#rows tr").length;
}catch(e){r.error=String(e);}window.__replaceResult=r;})();}
let opened=false,expired=false;const start=Date.now();const tick=()=>{if(q.get("account")&&window.secDNSAgent?.kind==="human"&&!opened){const b=[...document.querySelectorAll("a,button")].find(e=>e.textContent.trim()==="Account security");if(b){b.click();opened=true;}}
const settled=q.get("replace")?!!window.__replaceResult:q.get("account")?(opened&&vis(document.getElementById("human-security"))):q.get("expire")?expired&&document.querySelector(".sso-signed-out")&&!document.querySelector(".sso-signed-out").hidden:(window.secDNSAgent?.kind==="human"&&document.querySelectorAll("#rows tr").length>2);if(settled||Date.now()-start>(q.get("replace")?11000:9000)){setTimeout(done,600);return;}if(q.get("expire")&&window.secDNSAgent?.kind==="human"){window.secDNSAgent.expire();expired=true;}setTimeout(tick,150);};
addEventListener("load",tick);})();`

// TestSSOConsoleUXBrowser renders the real console through a stand-in edge (the
// SSO assertion is added server-side, as nginx would) and checks, at phone and
// desktop widths, that no break-glass form is shown and that the records table
// stays usable. Opt-in: SECDNS_SSO_UX_BROWSER=1 with SECDNS_CHROME (headless shell)
// and optional SECDNS_CHROME_LIBS / SECDNS_SSO_UX_CAPTURE_DIR.
func TestSSOConsoleUXBrowser(t *testing.T) {
	if os.Getenv("SECDNS_SSO_UX_BROWSER") != "1" {
		t.Skip("opt-in headless Chromium")
	}
	chrome := os.Getenv("SECDNS_CHROME")
	h, logs := ssoTestServer(t, true)
	h.UI = true
	h.NodeAdapterExecutable, h.NodeAdapterScript = "", ""
	store, err := recordstore.NewVersionedMemory(recordstore.Enrollment{RulesetID: "sso-ux", LineageID: "disposable"})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	h.versioned = store
	records := []recordset.Record{
		{Name: "gateway.office.invalid.", Type: "A", Values: []string{"172.22.18.231", "172.22.18.232"}, TTLSeconds: 300},
		{Name: "files.office.invalid.", Type: "AAAA", Values: []string{"2001:db8:1234:5678:abcd:ef01:2345:6789"}, TTLSeconds: 86400},
		{Name: "docs.office.invalid.", Type: "CNAME", Values: []string{"a-very-long-service-name.region-one.cdn.provider-example.invalid."}, TTLSeconds: 3600},
		{Name: "an-unusually-long-hostname-for-layout-checks.branch.office.invalid.", Type: "A", Values: []string{"192.0.2.20"}, TTLSeconds: 60},
		{Name: "txt.office.invalid.", Type: "TXT", Values: []string{"v=spf1 include:_spf.provider-example.invalid include:_spf2.provider-example.invalid ~all"}, TTLSeconds: 300},
		{Name: "mail.office.invalid.", Type: "A", Values: []string{"192.0.2.25"}, TTLSeconds: 300},
		{Name: "intranet.office.invalid.", Type: "A", Values: []string{"192.0.2.26"}, TTLSeconds: 300},
		{Name: "printer.office.invalid.", Type: "A", Values: []string{"192.0.2.27"}, TTLSeconds: 300},
	}
	if _, err = store.Replace(recordstore.Expected{RulesetID: "sso-ux", LineageID: "disposable", Revision: 1}, "ux-seed", records); err != nil {
		t.Fatal(err)
	}
	tlsServer := httptest.NewUnstartedServer(nil)
	host := tlsServer.Listener.Addr().String()
	_, port, _ := net.SplitHostPort(host)
	h.agent.origin = "https://" + host
	routes := h.routes()
	scriptTag := regexp.MustCompile(`</body>`)
	var replaceBodies []string
	var replaceMu sync.Mutex
	tlsServer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/fixture.js" {
			w.Header().Set("Content-Type", "text/javascript")
			w.Write([]byte(ssoUXFixture))
			return
		}
		if strings.HasPrefix(r.URL.Path, "/oauth2/") {
			w.Write([]byte("edge sign-out stand-in"))
			return
		}
		// what nginx adds after a successful WithMy ID auth subrequest
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
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/snapshot") {
			raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			replaceMu.Lock()
			replaceBodies = append(replaceBodies, string(raw))
			replaceMu.Unlock()
			r.Body = io.NopCloser(bytes.NewReader(raw))
		}
		if r.URL.Path == "/admin/ui/" {
			rec := &captureWriter{header: http.Header{}}
			routes.ServeHTTP(rec, r)
			for k, v := range rec.header {
				w.Header()[k] = v
			}
			w.WriteHeader(rec.status())
			w.Write(scriptTag.ReplaceAll([]byte(rec.body.String()), []byte(`<script src="/fixture.js"></script></body>`)))
			return
		}
		routes.ServeHTTP(w, r)
	})
	tlsServer.StartTLS()
	defer tlsServer.Close()
	dir := os.Getenv("SECDNS_SSO_UX_CAPTURE_DIR")
	if dir == "" {
		dir = t.TempDir()
	}
	run := func(width int, query, shot string) map[string]any {
		height := 1900
		if strings.Contains(query, "replace=") {
			height = 844
		}
		url := "https://" + host + "/admin/ui/" + query
		args := []string{"--no-sandbox", "--ignore-certificate-errors", "--disable-gpu", "--hide-scrollbars", fmt.Sprintf("--window-size=%d,%d", width, height), "--virtual-time-budget=14000"}
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, chrome, append(args, "--dump-dom", url)...)
		cmd.Env = append(os.Environ(), "LD_LIBRARY_PATH="+os.Getenv("SECDNS_CHROME_LIBS"))
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("chrome: %v", err)
		}
		m := regexp.MustCompile(`<pre id="fixture-result">([^<]*)</pre>`).FindSubmatch(out)
		if m == nil {
			os.WriteFile(filepath.Join(dir, fmt.Sprintf("dump-%d.html", width)), out, 0o600)
			t.Fatalf("no fixture result at %d px (%d bytes dumped; last SSO log %+v)", width, len(out), logs.last())
		}
		var result map[string]any
		if json.Unmarshal([]byte(strings.ReplaceAll(string(m[1]), "&quot;", `"`)), &result) != nil {
			t.Fatalf("fixture result: %s", m[1])
		}
		shotCmd := exec.CommandContext(ctx, chrome, append(args, "--screenshot="+filepath.Join(dir, shot), url)...)
		shotCmd.Env = cmd.Env
		shotCmd.Run()
		t.Logf("%d px %s: %s", width, query, m[1])
		return result
	}
	for _, width := range []int{390, 1280} {
		r := run(width, "", fmt.Sprintf("records-sso-%d.png", width))
		if r["sso"] != true || r["human"] != true {
			t.Fatalf("%d px: SSO exchange did not sign in: %v", width, r)
		}
		if r["signInForm"] != false || r["agentAccess"] != false || len(r["forbiddenText"].([]any)) != 0 || len(r["identityLeak"].([]any)) != 0 {
			t.Fatalf("%d px: break-glass UI on the SSO path: %v", width, r)
		}
		if r["rows"].(float64) < 5 || r["hscroll"] != false || r["actionsOffscreen"].(float64) != 0 || r["ipMultiLine"].(float64) != 0 || r["ttlClipped"].(float64) != 0 || r["fqdnBadBreak"].(float64) != 0 || r["fqdnMidLabel"].(float64) != 0 || r["statusOverlapsPill"] != false || r["clipped"] == true {
			t.Fatalf("%d px: records layout: %v", width, r)
		}
		if width == 390 && r["pillWidth"].(float64) > 390*0.5 {
			t.Fatalf("user pill too wide on a phone: %v", r)
		}
	}
	r := run(390, "?account=1", "account-security-sso-390.png")
	// C24: the SSO account page must not carry any local credential, recovery or
	// break-glass wording in its DOM (hidden nodes included), only the WithMy ID note.
	if leak := r["identityLeak"].([]any); len(leak) != 0 {
		t.Fatalf("SSO account security DOM leaks local credential or break-glass wording: %v", leak)
	}
	if r["managedBy"] != true {
		t.Fatalf("SSO account security does not say the sign-in is managed by WithMy ID: %v", r)
	}
	if r["signInForm"] != false || len(r["forbiddenText"].([]any)) != 0 || r["stepUp"] != true || r["revokeOthers"] != true {
		t.Fatalf("SSO account security offers local credential changes or lacks the WithMy ID step-up: %v", r)
	}
	// C20: replacing the list so that 5 of 8 records disappear is a pinned danger review with
	// a typed count, and the browser sends confirm_removals that the server checks.
	// The screenshot of this run reloads the page; it is taken before the replacement only
	// when the dump run has not yet committed, so the store is checked right after the dump.
	r = run(390, "?replace=1", "replace-review-sso-390.png")
	rep, _ := r["replace"].(map[string]any)
	if rep == nil || rep["error"] != nil || rep["open"] != true || rep["dangerVisible"] != true || rep["typedVisible"] != true ||
		rep["dangerText"] != "This replaces your records: 5 removed, 0 added, 0 changed" || rep["confirmText"] != "Replace — remove 5 records" || rep["confirmClass"] != "danger-solid" ||
		rep["disabledBefore"] != true || rep["disabledWrong"] != true || rep["disabledRight"] != false ||
		rep["dangerInView"] != true || rep["confirmInView"] != true || rep["dangerInViewScrolled"] != true || rep["confirmInViewScrolled"] != true {
		t.Fatalf("destructive replacement review is not a pinned, typed danger confirmation: %v", r["replace"])
	}
	view, err := store.Acquire()
	if err != nil || len(view.Records()) != 3 {
		t.Fatalf("confirmed replacement did not commit 3 records: %v %d (%v)", err, len(view.Records()), rep)
	}
	replaceMu.Lock()
	sent := strings.Join(replaceBodies, " ")
	replaceMu.Unlock()
	if !strings.Contains(sent, `"confirm_removals":5`) {
		t.Fatalf("the console did not send confirm_removals: %s", sent)
	}
	r = run(390, "?expire=1", "signed-out-sso-390.png")
	if r["signInForm"] != false || r["agentAccess"] != false || len(r["forbiddenText"].([]any)) != 0 || len(r["identityLeak"].([]any)) != 0 || r["signedOutLink"] != true {
		t.Fatalf("signed-out SSO view offers break-glass sign-in: %v", r)
	}
}

type captureWriter struct {
	header http.Header
	code   int
	body   strings.Builder
}

func (c *captureWriter) Header() http.Header  { return c.header }
func (c *captureWriter) WriteHeader(code int) { c.code = code }
func (c *captureWriter) Write(b []byte) (int, error) {
	if c.code == 0 {
		c.code = 200
	}
	return c.body.Write(b)
}
func (c *captureWriter) status() int {
	if c.code == 0 {
		return 200
	}
	return c.code
}

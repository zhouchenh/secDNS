package server

import (
	"regexp"
	"strings"
	"testing"
)

// Console slice 2 (destructive-action safety, identity flows): browser-free guards on the
// embedded assets, run in CI on every change. The behaviour itself is exercised by the opt-in
// TestConsoleSafetyIdentityBrowser and the gateway tests.
func TestConsoleSlice2Static(t *testing.T) {
	read := func(name string) string {
		t.Helper()
		data, err := editorAssets.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	core, local := embeddedCatalogue(t, "console_ui/strings.js"), embeddedCatalogue(t, "auth_ui/strings-local.js")
	// Every English sentence the slice-2 scripts compose is in the catalogue (both languages are
	// checked by TestConsoleCatalogueComplete), so nothing stays English in zh-Hant.
	for _, text := range []string{
		"Delete this record?", "Delete record", "Will be deleted", "Will be added", "Will be changed", "Undo", "Undo changes to a.invalid. A",
		"2 added", "1 changed", "3 removed", "No changes yet", "Unfinished record edit", "TTL 300 s", "Apply — delete 1 record", "Apply — delete 2 records",
		"Change undone. The record is back to its saved version.", "Record marked for deletion. Review changes before applying; Undo restores it.",
		"Your unsaved changes were kept while you signed in. Review them before applying.",
		"The DNS server could not be reached to check which records this change removes, so nothing was sent and nothing changed. Try again in a moment.",
		"Expires Dec 31, 2030", "Last checked: Oct 31, 2026, 9:00 AM", "amd103 · DNS process: Running", "Drain amd103?", "Drain amd103", "Resume amd103?", "Resume amd103",
		"Still served by intel108, cix106", "No other healthy node serves this prefix", "Withdrawn from amd103:",
		"cix106 is the last healthy node serving 192.0.2.99/32. Draining it would stop that service. Resume or repair another node first, or refresh if another node recovered.",
		"Confirm it's you first", "Confirm it's you", "Signed in as", "Sessions", "Verified at 9:41 AM", "3 min left", "Not confirmed in the last 5 minutes.",
		"Confirm it's you first. Your WithMy ID sign-in is older than 5 minutes.", "Confirmed. Your other sessions are signed out.",
		"Your console session ended at 9:41 AM.", "Your console session timed out at 9:41 AM.", "secDNS is busy right now", "Try again",
		"Your unsaved changes are too large to keep while you confirm. Apply or discard them first.",
	} {
		if !catalogueHas(core, text) {
			t.Errorf("slice-2 text %q is not in the core catalogue", text)
		}
	}
	if !catalogueHas(local, "Verify your identity first. Sensitive changes need a verification from the last five minutes.") {
		t.Error("break-glass recent-verification refusal is not in the local catalogue")
	}
	agent, human, app, state, i18n := read("auth_ui/agent.js"), read("auth_ui/human.js"), read("versioned_ui/app.js"), read("versioned_ui/state.js"), read("console_ui/i18n.js")
	// C25: a round trip returns only to this console's own path; sign-out clears kept drafts;
	// drafts live in sessionStorage (this tab), never localStorage.
	stepUp := between(t, agent, "async stepUp(intent=null){", "\n    },")
	if !strings.Contains(stepUp, `"/oauth2/sign_out?rd="+encodeURIComponent(returnPath())`) || !strings.Contains(stepUp, "drafts.preserve(intent)") {
		t.Fatal("stepUp must keep drafts and return only to returnPath()")
	}
	if !strings.Contains(between(t, agent, "const returnPath = () =>", "\n"), "location.pathname") {
		t.Fatal("returnPath must derive from location.pathname only")
	}
	if !strings.Contains(between(t, agent, "async logout(){", "\n"), "clearDrafts();") || !strings.Contains(between(t, agent, "async switchToLegacy(){", "\n      if(allowedOrigin)"), "clearDrafts();") {
		t.Fatal("signing out must clear kept drafts")
	}
	if strings.Contains(between(t, agent, "const DRAFTS =", "const drafts ="), "localStorage") {
		t.Fatal("kept drafts must be session-scoped")
	}
	// The step-up never weakens freshness: the replay runs only when the session is fresh, and the
	// server keeps refusing (recent_authentication_required), which reopens the step-up.
	replay := between(t, human, `window.addEventListener("agentconnected",()=>{
      if(!ssoMode`, "\n    });")
	if !strings.Contains(replay, "if(!fresh()){") || !strings.Contains(replay, "takeIntent()") {
		t.Fatal("the refused action must be replayed only with a fresh sign-in, once")
	}
	if !strings.Contains(human, `error.code==="recent_authentication_required"`) {
		t.Fatal("a recent-authentication refusal must open the step-up")
	}
	// No local credential wording in the new SSO block.
	for _, literal := range regexp.MustCompile(`"([^"\\]*)"`).FindAllStringSubmatch(between(t, human, "// --- C25/C26/C27", "ssoUI={"), -1) {
		if localCredentialWording.MatchString(literal[1]) {
			t.Fatalf("SSO step-up text carries local sign-in wording: %q", literal[1])
		}
	}
	// C20 remainder: a single-record deletion states its removal; the gateway's definitive
	// pre-check refusal is not shown as an uncertain outcome.
	if !strings.Contains(state, `{action:"delete",key:{name:row.base.name,type:row.base.type},confirm_removals:1}`) {
		t.Fatal("rrset deletion must carry confirm_removals")
	}
	if !strings.Contains(app, `503:["snapshot_unavailable","removal_check_unavailable"]`) || !strings.Contains(app, `e.message==="removal_check_unavailable"`) {
		t.Fatal("removal_check_unavailable must be a definitive refusal in the editor")
	}
	// Slice-1 leftover: dates inside sentences are re-rendered on an in-place language switch.
	if !strings.Contains(i18n, "[data-i18n-at]") || !strings.Contains(between(t, i18n, "const setLanguage = next => {", "};"), "stamps(document)") {
		t.Fatal("i18n.js must re-render dated sentences on a language switch")
	}
	for _, file := range []string{"versioned_ui/app.js", "console_ui/nodes.js"} {
		if strings.Contains(read(file), `"Expires "+(`) || strings.Contains(read(file), `" · Last checked: "+`) {
			t.Fatalf("%s still renders a date as fixed text", file)
		}
	}
}

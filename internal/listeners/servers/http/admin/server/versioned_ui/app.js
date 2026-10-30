(() => {
  "use strict";
  const S = globalThis.SnapshotEditor, model = new S.Model(), $ = id => document.getElementById(id);
  const endpoint = new URL("../snapshot", document.currentScript.src);
  const previewURL = new URL("import-preview/", document.currentScript.src);
  if (endpoint.origin !== location.origin) throw new Error("Invalid editor origin");
  if (previewURL.origin !== location.origin) throw new Error("Invalid preview origin");
  $("endpoint").textContent = endpoint.origin + endpoint.pathname;
  let token = "", epoch = 0, getID = 0, connected = false, busy = false, selected = null, reviewedEdit = null, reviewGuard = {danger:false,typed:false,removed:0}, importChannel = null, importChannelID = "";
  const requests = new Set();
  let deletion = null;
  // A date shown inside a sentence: i18n.js renders it in the current language from the ISO
  // value and the English template, and renders it again when the language changes in place.
  function stamp(el, iso, template = "{time}", format = "") {
    el.dataset.i18nAt = iso; el.dataset.i18nTemplate = template; if (format) el.dataset.i18nFormat = format; el.title = iso;
    el.textContent = template.split("{time}").join(window.secDNSI18n?.date(iso) || iso);
    window.secDNSI18n?.stamp?.(el); return el;
  }
  function status(text, kind = "", routine = false) { $("status").textContent = text; $("status").className = kind; $("status").hidden = !text || routine; }
  function comparisonVersion(title, record, unavailable = false) {
    const section = document.createElement("section"), heading = document.createElement("h4");
    section.className = "comparison-version"; heading.textContent = title; section.append(heading);
    if (!record) {
      const absent = document.createElement("p"); absent.className = "comparison-absent";
      absent.textContent = unavailable ? "Snapshot not loaded" : "Not present in this snapshot"; section.append(absent); return section;
    }
    const fields = document.createElement("dl");
    for (const [label, value] of [["Name",record.name],["Type",record.type],["TTL (seconds)",String(record.ttl_seconds)],["Expiration",record.expires_at === undefined ? "Permanent (no expiration)" : record.expires_at]]) {
      const term = document.createElement("dt"), detail = document.createElement("dd"); term.textContent = label; if (label === "Expiration" && record.expires_at !== undefined) stamp(detail, record.expires_at); else detail.textContent = value; if (label === "Name") detail.translate = false; fields.append(term,detail);
    }
    const label = document.createElement("p"), values = document.createElement("ol"); label.className = "comparison-value-label"; label.textContent = "Ordered values / TXT chunks"; values.className = "comparison-values";
    for (const value of record.values) { const item = document.createElement("li"), text = document.createElement("code"); text.textContent = JSON.stringify(value); item.append(text); values.append(item); }
    section.append(fields,label,values); return section;
  }
  function renderComparison() {
    $("comparison-revisions").textContent = "Base revision " + (model.base?.revision || "—") + " · Observed server revision " + (model.current?.revision || "not loaded");
    let note = model.identityBlocked ? "Identity mismatch. Showing the last accepted snapshots; writing remains blocked." : !model.current ? "The server comparison has not been loaded." : !connected ? "Disconnected. Showing the last observed server snapshot." : !model.fresh ? "The last observed snapshot is retained. Fetch current state to reconcile." : "Showing the last accepted server snapshot. The server may change again.";
    note += " Unstaged form fields are not included below.";
    if (model.pending?.status === "uncertain") note += " The pending operation is still uncertain; this comparison does not resolve it.";
    $("comparison-note").textContent = note;
    const rows = S.comparisonRows(model.base?.records || [],model.draft,model.current ? model.current.records : null), shown = rows.filter(row => $("show-unchanged").checked || row.changed);
    $("comparison-rows").replaceChildren();
    for (const row of shown) {
      const record = row.draft || row.base || row.current, card = document.createElement("article"), heading = document.createElement("h3"), labels = document.createElement("p"), versions = document.createElement("div");
      card.className = "comparison-record"; card.dataset.recordKey = row.key; heading.textContent = record.name + " · " + record.type; heading.translate = false; labels.className = "comparison-labels";
      for (const [scope, change] of [["Your changes",row.localChange],["Server changes",row.serverChange]]) { const badge = document.createElement("span"); badge.className = "change-badge change-" + change; badge.textContent = scope + ": " + change; labels.append(badge); }
      versions.className = "comparison-versions"; versions.append(comparisonVersion("Saved version",row.base),comparisonVersion("Your changes",row.draft),comparisonVersion("Latest server version",row.current,row.serverChange === "unavailable")); card.append(heading,labels,versions); $("comparison-rows").append(card);
    }
    $("comparison-empty").hidden = shown.length > 0;
    $("comparison-empty").textContent = rows.length ? "No changed rows. Show unchanged rows to inspect the retained snapshots." : "No records to compare.";
  }
  const messages = {
    invalid_snapshot_request:"The proposal is invalid. Your draft is preserved; correct it after reconciliation.",
    snapshot_too_large:"The complete proposal exceeds the size limit. Your draft is preserved.",
    revision_conflict:"The server has newer changes. Your draft is preserved. Refresh to compare versions, then review your work before discarding the draft and re-entering changes.",
    identity_conflict:"The server identity or lineage differs. Writing is blocked. Clear local work only after reviewing it, then reconnect explicitly.",
    operation_conflict:"This operation ID conflicts with another request. The frozen attempt is preserved; no replacement ID was generated.",
    rrset_schema_required:"This store no longer supports targeted edits. Your draft is preserved; reconcile and review explicitly. No replacement was sent.",
    review_changed:"The reviewed proposal changed. Review it again before applying.",
    removal_confirmation_required:"The server requires an explicit confirmation of how many records this replacement removes. Nothing was changed; review it again.",
    removal_confirmation_mismatch:"The confirmed number of removed records does not match the server. Nothing was changed; refresh and review again.",
    removal_check_unavailable:"The DNS server could not be reached to check which records this change removes, so nothing was sent and nothing changed. Try again in a moment.",
    draft_restore_refused:"Your kept changes could not be restored because the DNS server's records changed identity. Nothing was applied.",
    operator_provenance_unavailable:"This store has not been explicitly migrated for operator-supplied provenance. Nothing was changed.",
    receipt_capacity:"The operation receipt ledger is full. Operator intervention is required.",
    revision_exhausted:"The revision range is exhausted. Operator intervention is required.",
    snapshot_unavailable:"The store is unavailable. Local work is preserved.",
    authentication:"Authentication failed. Sign in or reconnect; local work and pending recovery are preserved.",
    stale_snapshot_response:"An older snapshot response was ignored. Fetch current state again.",
    duplicate_record:"That name and type already exist in the draft. Edit the existing row.",
    reconciliation_required:"Stage unfinished fields and reconcile current state before preparing another operation.",
    uncertain:"Could not confirm whether the change was saved. Your draft is preserved. Use Check submitted change to send the identical request and check its result safely. Signing out does not undo a submitted change.",
    invalid_snapshot_response:"The server returned an invalid snapshot. Local work is preserved.",
    handoff_reconciliation_required:"Exact candidate not transferred. Finish, apply or explicitly discard existing local work first.",
    handoff_identity_conflict:"Exact candidate not transferred. Its ruleset ID does not match this editor.",
    invalid_draft_handoff:"Exact candidate transfer was invalid or stale. Nothing changed.",
    editor_unavailable:"Exact candidate not transferred. Wait for current work to finish, or connect and fetch a fresh snapshot first."
  };
  const message = e => messages[e.message] || "Unexpected response or connection failure. Local work is preserved.";
  const locked = () => (window.secDNSAgent && !window.secDNSAgent.allows("records:write")) || busy || !connected || !!model.pending || model.identityBlocked;
  function controls() {
    const work=model.dirty()||!!model.pending||model.identityBlocked||(!!model.base&&!model.fresh);
    $("pending-actions").hidden=!work;$("change-summary").hidden=!work;$("change-review").hidden=!work;
    $("local-work-warning").hidden=!(model.dirty()||model.pending);
    $("workspace").classList.toggle("editing",!$("record-editor").hidden);$("editor-scrim").hidden=$("record-editor").hidden;document.body.classList.toggle("sheet-open",!$("record-editor").hidden);
    $("delete-in-editor").hidden=!selected;$("delete-in-editor").disabled=locked();
    const changes=S.changes(model.base?.records||[],model.draft);pendingCounts(changes);$("review").className=changes.removed>0?"danger-solid":"primary";$("change-count").textContent=model.pending?.status==="uncertain"?"Change outcome uncertain":model.formDirty?"Unfinished record edit — add it to changes before review":`Unsaved changes: ${changes.added} added / ${changes.changed} changed / ${changes.removed} removed`;
    for (const c of $("editor").querySelectorAll("input, select, textarea, button")) c.disabled = locked();
    $("name").disabled = $("type").disabled = locked() || !!selected;
    $("expiry").disabled = locked() || $("expiry-mode").value === "permanent";
    $("expiry").hidden=document.querySelector('label[for="expiry"]').hidden=$("expiry-mode").value==="permanent";
    $("new-record").disabled = locked();
    for (const b of $("rows").querySelectorAll("button")) b.disabled = locked();
    $("review").disabled = locked() || !model.fresh || !model.dirty() || model.formDirty;
    $("retry").hidden = !model.pending || model.pending.status !== "uncertain";
    $("review").hidden=model.pending?.status==="uncertain";$("retry").classList.toggle("primary",model.pending?.status==="uncertain");$("adopt").hidden=!(model.pending||model.identityBlocked||(model.base&&!model.fresh));$("recovery-tools").hidden=!(model.dirty()||model.pending||model.identityBlocked);
    $("retry").disabled = (window.secDNSAgent && !window.secDNSAgent.allows("records:write")) || busy || !connected || model.identityBlocked;
    $("adopt").disabled = busy || !connected || !model.current || !model.fresh || model.identityBlocked || ["sending","uncertain"].includes(model.pending?.status);
    $("refresh").disabled = busy || !connected;
    $("connect").disabled = busy;
    $("review-confirm").disabled = busy;
    $("review-cancel").disabled = busy;
    $("clear").disabled = busy;
  }
  // Toned counts in the sticky pending bar: added (ok), changed (warn), removed (danger).
  function pendingCounts(d) {
    const box=$("pending-counts");box.replaceChildren();
    for (const [kind,n,label] of [["added",d.added,"{n} added"],["changed",d.changed,"{n} changed"],["removed",d.removed,"{n} removed"]]) {
      if (!n) continue; const chip=document.createElement("span");chip.className="count-chip change-"+kind;chip.textContent=label.replace("{n}",String(n));box.append(chip);
    }
    if (!box.children.length) { const none=document.createElement("span");none.className="count-chip";none.textContent=model.formDirty?"Unfinished record edit":"No changes yet";box.append(none); }
  }
  let valueSeq=0;
  function valueRow(text) {
    const row = document.createElement("div"); row.className = "value-row"; const n=++valueSeq;
    const input = document.createElement("textarea"); input.value = text; input.setAttribute("aria-label", "Record value"); input.spellcheck = false; input.setAttribute("autocapitalize","off"); input.id="value-"+n;
    const remove = document.createElement("button"); remove.type = "button"; remove.textContent = "Remove";
    remove.addEventListener("click", () => { if (locked()) return; row.remove(); model.touch(); controls(); });
    const error=document.createElement("p");error.className="field-error";error.id="value-error-"+n;error.hidden=true;
    const line=document.createElement("div");line.className="value-line";line.append(input,remove);row.append(line,error); $("values").append(row);
  }
  // C33: every invalid field is marked (aria-invalid, its own message linked by aria-describedby)
  // and listed in an error summary whose entries move focus to the field.
  const FIELD_LABELS={name:"DNS name",ttl:"TTL (seconds)",expiry:"RFC3339 timestamp",values:"Value {n}"};
  function clearRecordError(){ $("record-error").hidden=true;$("record-error").replaceChildren();for(const e of $("editor").querySelectorAll(".field-error")){e.hidden=true;e.replaceChildren();}for(const field of $("editor").querySelectorAll("[aria-invalid]")){field.removeAttribute("aria-invalid");const described=(field.getAttribute("aria-describedby")||"").split(/\s+/).filter(id=>id&&id!=="record-error"&&!/-error(-\d+)?$/.test(id));if(described.length)field.setAttribute("aria-describedby",described.join(" "));else field.removeAttribute("aria-describedby");}}
  function showIssues(issues){
    clearRecordError();const summary=$("record-error"),list=document.createElement("ul"),marked=[];
    for(const issue of issues){
      const field=issue.field==="values"?$("values").querySelectorAll("textarea")[issue.index||0]:$(issue.field);
      const target=field&&!field.disabled?field:$("name");const error=issue.field==="values"?target.closest(".value-row")?.querySelector(".field-error"):$(issue.field+"-error");
      if(error&&!error.childNodes.length){const mark=document.createElement("span");mark.className="field-error-icon";mark.setAttribute("aria-hidden","true");mark.textContent="!";const text=document.createElement("span");text.textContent=issue.text;error.append(mark,text);error.hidden=false;}
      if(target&&!marked.includes(target)){target.setAttribute("aria-invalid","true");target.setAttribute("aria-describedby",[...(target.getAttribute("aria-describedby")||"").split(/\s+/).filter(Boolean),error?.id||"record-error"].join(" "));marked.push(target);}
      const item=document.createElement("li"),link=document.createElement("a");link.href="#"+(target?.id||"name");
      const where=document.createElement("span");where.textContent=(FIELD_LABELS[issue.field]||FIELD_LABELS.name).replace("{n}",String((issue.index||0)+1));const what=document.createElement("span");what.textContent=issue.text;link.append(where,document.createTextNode(": "),what);
      link.addEventListener("click",ev=>{ev.preventDefault();target?.focus();});item.append(link);list.append(item);
    }
    const title=document.createElement("strong");title.textContent=issues.length===1?"Fix 1 problem before adding this record":"Fix {n} problems before adding this record".replace("{n}",String(issues.length));
    summary.append(title,list);summary.hidden=false;controls();summary.focus();
  }
  const VALUE_HINTS={A:"One IPv4 address per value, for example 192.0.2.10.",AAAA:"One IPv6 address per value, for example 2001:db8::10.",CNAME:"Exactly one destination name.",TXT:"Each value is one TXT string; their order is kept."};
  function valueHint(){$("values-hint").textContent=VALUE_HINTS[$("type").value]||"";}
  let editorOpener=null;
  function edit(record = null, force = false, open = false) {
    if (!force && model.formDirty && !confirm("Discard unfinished record fields? The staged snapshot draft is retained.")) return;
    clearRecordError();
    if(open&&$("record-editor").hidden)editorOpener=document.activeElement;
    selected = record ? S.key(record) : null; model.formDirty = false;$("record-editor").hidden=!open;
    $("editor-title").textContent = record ? "Edit record" : "New record";$("stage").textContent=record?"Update changes":"Add to changes";
    $("name").value = record?.name || ""; $("type").value = record?.type || "A"; $("ttl").value = String(record?.ttl_seconds ?? 300);
    $("values").replaceChildren(); for (const value of record?.values || [""]) valueRow(value);valueHint();
    $("expiry-mode").value = record?.expires_at ? "absolute" : "permanent"; $("expiry").value = record?.expires_at || ""; controls();if(open)$("editor-title").focus();
  }
  function closeEditor(){if(model.formDirty&&!confirm("Discard unfinished fields? Staged changes are retained."))return;const back=editorOpener;editorOpener=null;edit(null,true);if(back?.isConnected&&!back.disabled&&back.getClientRects().length)back.focus();else $("new-record").focus();}
  window.addEventListener("beforeunload",event=>{if((model.dirty()||model.pending)&&!window.secDNSAgent?.leaving){event.preventDefault();event.returnValue="";}});
  $("close-editor").addEventListener("click",closeEditor);
  $("editor-scrim").addEventListener("click",closeEditor);
  $("record-editor").addEventListener("keydown",e=>{if(e.key==="Escape"&&!$("record-editor").hidden){e.preventDefault();closeEditor();}});
  $("type").addEventListener("change",valueHint);
  $("delete-in-editor").addEventListener("click",()=>{const record=selected&&model.draft.find(r=>S.key(r)===selected);if(!record||locked())return;if(model.formDirty){status("Stage or discard unfinished fields before deleting a row.","error");return;}deletion={key:S.key(record),record:JSON.stringify(record),epoch,opener:$("delete-in-editor")};deleteDetails(record);$("delete-dialog").showModal();$("delete-cancel").focus();});
  // C15: filters, sort and the visible page are kept in the address (query) so a reload or a
  // shared link shows the same list; unrelated query parameters are left untouched.
  const PAGE=50;let shown=PAGE;
  function readListState(){const q=new URLSearchParams(location.search);$("filter").value=q.get("q")||"";const type=q.get("type")||"";if(["A","AAAA","CNAME","TXT"].includes(type))$("record-type-filter").value=type;$("pending-only").checked=q.get("pending")==="1";const sort=q.get("sort")||"";if([...$("record-sort").options].some(o=>o.value===sort))$("record-sort").value=sort;}
  function writeListState(){try{const url=new URL(location.href);const set=(k,v)=>{if(v)url.searchParams.set(k,v);else url.searchParams.delete(k);};set("q",$("filter").value);set("type",$("record-type-filter").value);set("pending",$("pending-only").checked?"1":"");set("sort",$("record-sort").value);if(url.href!==location.href)history.replaceState(history.state,"",url.href);}catch{}}
  const listChanged=()=>{shown=PAGE;writeListState();render();};
  $("record-type-filter").addEventListener("change",listChanged);
  $("pending-only").addEventListener("change",listChanged);
  $("record-sort").addEventListener("change",listChanged);
  $("reset-filters").addEventListener("click",()=>{$("filter").value="";$("record-type-filter").value="";$("pending-only").checked=false;listChanged();$("filter").focus();});
  $("show-more").addEventListener("click",()=>{const next=shown;shown+=PAGE;render();$("rows").querySelectorAll("tr")[next]?.querySelector("button")?.focus();});
  $("empty-new").addEventListener("click",()=>$("new-record").click());
  $("empty-import").addEventListener("click",()=>$("open-import").click());
  const svgIcon=(path,size=16)=>{const s=document.createElementNS("http://www.w3.org/2000/svg","svg");s.setAttribute("viewBox","0 0 24 24");s.setAttribute("width",size);s.setAttribute("height",size);s.setAttribute("aria-hidden","true");s.setAttribute("focusable","false");const p=document.createElementNS("http://www.w3.org/2000/svg","path");p.setAttribute("d",path);s.append(p);return s;};
  function copyButton(text){
    const b=document.createElement("button");b.type="button";b.className="icon-button copy-name";b.setAttribute("aria-label","Copy name");b.title="Copy name";b.append(svgIcon("M9 9h10v10H9zM5 15V5h10",16));
    b.addEventListener("click",async e=>{e.stopPropagation();try{await navigator.clipboard.writeText(text);b.classList.add("copied");status("Name copied.","success");setTimeout(()=>b.classList.remove("copied"),1500);}catch{status("The name could not be copied. Select it and copy it instead.","error");}});
    return b;
  }
  // Loading and error states (C32/C39): the page frame stays; a failed load keeps the last good
  // records, says why, and offers Try again. The connection indicator says what is true.
  let loadError=null,loading=false,lastLoaded="";
  function connectionState(){const state=loading&&!model.base?"checking":loadError?"error":connected&&model.fresh?"ok":connected?"stale":"unknown";
    $("connection").textContent={checking:"Loading records…",error:"DNS server unreachable",ok:"Records loaded",stale:"Refresh needed",unknown:"Disconnected"}[state];$("connection").dataset.state=state;
    window.dispatchEvent(new CustomEvent("secdns:connection",{detail:{state}}));}
  function recordsState(){
    const box=$("records-state");box.replaceChildren();
    if(loading&&!model.base){const l=document.createElement("div");l.className="loading-state";l.setAttribute("role","status");const spin=document.createElement("span");spin.className="spinner";const t=document.createElement("span");t.textContent="Loading records…";l.append(spin,t);
      const sk=document.createElement("div");sk.className="skeleton-list";sk.setAttribute("aria-hidden","true");for(let i=0;i<4;i++){const r=document.createElement("span");r.className="skeleton-row";sk.append(r);}box.append(l,sk);return;}
    if(!loadError)return;
    const card=document.createElement("div");card.className="error-state";card.setAttribute("role","alert");const head=document.createElement("div");head.className="state-head";const h=document.createElement("h2");h.textContent=model.base?"Records could not be refreshed":"Records could not be loaded";head.append(svgIcon("M12 8v5m0 4h.01M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18Z",20),h);
    const cause=document.createElement("p");cause.textContent=message(loadError);card.append(head,cause);
    if(model.base&&lastLoaded){const last=document.createElement("p");last.className="hint";stamp(last,lastLoaded,"Showing the records last loaded {time}. Your unsaved changes are kept.");card.append(last);}
    else if(model.base){const last=document.createElement("p");last.className="hint";last.textContent="Showing the records loaded earlier. Your unsaved changes are kept.";card.append(last);}
    const actions=document.createElement("div");actions.className="actions";
    const again=document.createElement("button");again.type="button";again.className="primary";again.id="records-retry";again.append(svgIcon("M20 12a8 8 0 1 1-2.3-5.7M20 4v4h-4",16),document.createTextNode("Try again"));again.addEventListener("click",retryLoad);actions.append(again);
    if(model.dirty()||model.pending){const link=document.createElement("a");link.href="#pending-actions";link.textContent="Go to your unsaved changes";actions.append(link);}
    card.append(actions);box.append(card);
  }
  async function retryLoad(){if(busy)return;if(connected){$("refresh").click();return;}if(window.secDNSAgent?.active){await loadAfterSignIn();$("records-retry")?.focus();}}
  function renderRow(record,removed){
    const k=S.key(record),tr=document.createElement("tr"),info=document.createElement("td"),title=document.createElement("div");tr.dataset.recordKey=k;title.className="record-name";breakable(title,record.name);
    const nameLine=document.createElement("div");nameLine.className="record-name-line";nameLine.append(title,copyButton(record.name));info.append(nameLine);info.className="record-info";
    const original=model.base?.records.find(r=>S.key(r)===k),pending=!removed&&(!original||JSON.stringify(original)!==JSON.stringify(record));
    if(removed){tr.className="row-removed";const marker=document.createElement("span");marker.className="draft-marker removal-marker";marker.textContent="Will be deleted";info.append(marker);}
    else if(pending){const mark=document.createElement("span");mark.className="draft-marker";mark.textContent="Pending";info.append(mark);}
    const typeCell=document.createElement("td"),valueCell=document.createElement("td"),ttlCell=document.createElement("td");typeCell.textContent=record.type;typeCell.translate=false;typeCell.className="record-type";valueCell.className="record-values";ttlCell.className="record-ttl";
    for (const value of record.values) {const d=document.createElement("div");d.className="record-value";if(value==="")d.textContent="(empty string)";else if(removed)d.textContent=value;else if(record.type==="A"||record.type==="AAAA"){d.classList.add("record-ip");d.textContent=value;}else if(record.type==="CNAME"){d.classList.add("record-fqdn");breakable(d,value);}else d.textContent=value;valueCell.append(d);}
    if (!removed&&record.expires_at) {const d=document.createElement("div");const expired=Date.parse(record.expires_at)<=Date.now();d.className=expired?"record-expired":"record-expiry";stamp(d,record.expires_at,expired?"Expired · retained {time}":"Expires {time}");valueCell.append(d);}
    ttlCell.textContent=record.ttl_seconds+" s";tr.append(info,typeCell,valueCell,ttlCell);
    const actions=document.createElement("td");actions.className="record-actions";
    if(removed||pending)actions.append(undoButton(record));
    if(!removed){
      const change=document.createElement("button"),remove=document.createElement("button");change.type="button";remove.type="button";change.className="row-edit";remove.className="row-delete";
      const label=document.createElement("span");label.className="btn-label";label.textContent="Edit";change.append(label,svgIcon("M9 6l6 6-6 6",18));remove.textContent="Delete";
      change.setAttribute("aria-label","Edit "+record.name+" "+record.type);remove.setAttribute("aria-label","Delete "+record.name+" "+record.type);
      change.addEventListener("click",()=>{if(!locked()) edit(record,false,true);});
      remove.addEventListener("click",()=>{if(locked())return;if(model.formDirty){status("Stage or discard unfinished fields before deleting a row.","error");return;}deletion={key:k,record:JSON.stringify(record),epoch,opener:remove};deleteDetails(record);$("delete-dialog").showModal();$("delete-cancel").focus();});
      actions.append(change,remove);
    }
    tr.append(actions);return tr;
  }
  function render() {
    $("workspace").hidden = !model.base;
    connectionState();recordsState();
    $("disconnect").hidden = !connected || !!window.secDNSAgent?.active; $("login").hidden = connected || document.body.dataset.recordGateway === "true";
    $("base-version").textContent = "Base revision " + (model.base?.revision || "—");
    $("current-version").textContent = "Observed current " + (model.current?.revision || "—");
    const diff = S.changes(model.base?.records || [], model.draft);
    $("change-count").textContent = `${diff.added} added · ${diff.changed} changed · ${diff.removed} removed`;
    $("receipt").textContent = model.receipt ? "Acknowledged operation " + model.receipt.operation_id + " at revision " + model.receipt.revision + " · " + model.receipt.committed_at + ". This receipt is not a current-state snapshot." : "";
    $("saved-details").hidden=!model.receipt;
    const origin=model.draftProvenance;$("draft-provenance-details").hidden=!origin;$("draft-provenance").textContent=origin?"Operator-supplied strict candidate · ruleset "+origin.rulesetID+" · source SHA-256 "+origin.sourceSHA256+" · content SHA-256 "+origin.contentSHA256+" · "+(model.edits===origin.editCounter?"unchanged after transfer; the tuple will be submitted":"locally edited; the original tuple will not be submitted")+". The source and profile are not authenticated by the snapshot server.":"";
    const active=document.activeElement,focusKey=active?.closest?.("#rows tr")?.dataset.recordKey,focusClass=active?.classList?.[0];
    $("rows").replaceChildren();
    const filter = $("filter").value.toLowerCase(), typeFilter=$("record-type-filter").value, onlyPending=$("pending-only").checked;
    const matches=record=>(!typeFilter||record.type===typeFilter)&&[record.name,record.type,...record.values].some(v => v.toLowerCase().includes(filter));
    const items=[];
    for (const record of model.draft) {
      if (!matches(record)) continue;
      if (onlyPending) {const original=model.base?.records.find(r=>S.key(r)===S.key(record));if(original&&JSON.stringify(original)===JSON.stringify(record))continue;}
      items.push({record,removed:false});
    }
    const count=items.length;
    // Records marked for deletion stay listed (struck through) until the change is applied, each with Undo.
    if (model.base) for (const record of model.base.records) { if (model.draft.some(r=>S.key(r)===S.key(record))||!matches(record)) continue; items.push({record,removed:true}); }
    const sort=$("record-sort").value,isPending=x=>{if(x.removed)return 0;const o=model.base?.records.find(r=>S.key(r)===S.key(x.record));return !o||JSON.stringify(o)!==JSON.stringify(x.record)?0:1;};
    if(sort==="name")items.sort((a,b)=>a.record.name.localeCompare(b.record.name)||a.record.type.localeCompare(b.record.type));
    else if(sort==="type")items.sort((a,b)=>a.record.type.localeCompare(b.record.type)||a.record.name.localeCompare(b.record.name));
    else if(sort==="ttl")items.sort((a,b)=>a.record.ttl_seconds-b.record.ttl_seconds||a.record.name.localeCompare(b.record.name));
    else if(sort==="pending")items.sort((a,b)=>isPending(a)-isPending(b));
    // Pending and removed rows are always listed, even beyond the first page, so Undo stays reachable.
    const visible=items.filter((item,i)=>i<shown||item.removed||isPending(item)===0);
    for(const item of visible)$("rows").append(renderRow(item.record,item.removed));
    const more=items.length-visible.length;$("show-more-wrap").hidden=more<=0;$("show-more").textContent="Show {n} more".replace("{n}",String(Math.min(more,PAGE)));$("show-more-info").textContent="Showing {shown} of {total}".replace("{shown}",String(visible.length)).replace("{total}",String(items.length));
    if(focusKey&&(document.activeElement===document.body||!document.activeElement)){const row=$("rows").querySelector('tr[data-record-key="'+CSS.escape(focusKey)+'"]');const again=row&&((focusClass&&row.querySelector("."+CSS.escape(focusClass)))||row.querySelector("button"));again?.focus();}
    $("count").textContent=count===model.draft.length?String(count):count+" of "+model.draft.length;
    $("results-count").textContent=`${count} of ${model.draft.length} records`+(onlyPending?" | Pending changes, including records that will be deleted.":" | Changes are reviewed before they are applied.");
    $("reset-filters").hidden=!filter&&!typeFilter&&!onlyPending;
    // C37: no records at all is an empty state with its two ways forward; filters are not shown.
    const none=!!model.base&&!model.draft.length&&!model.base.records.length;
    $("records-empty").hidden=!none;document.querySelector(".console-record-tools").hidden=none;$("results-count").hidden=none;document.querySelector(".console-record-table").hidden=none;
    $("empty").hidden=none||items.length>0;$("empty").textContent=model.draft.length?"No records match these filters. Reset filters to see all records.":model.base?.records.length?"All records are marked for removal. Review changes before applying.":"No records yet. Add a record or import an export to get started.";
    $("comparison").textContent=JSON.stringify({base:model.base?.records||[],draft:model.draft,current:model.current?.records||[]},null,2);renderComparison();controls();
  }
  function undoButton(record) {
    const b=document.createElement("button");b.type="button";b.className="row-undo";b.textContent="Undo";b.setAttribute("aria-label","Undo changes to "+record.name+" "+record.type);
    b.addEventListener("click",()=>{if(locked()||model.formDirty){if(model.formDirty)status("Stage or discard unfinished fields before deleting a row.","error");return;}const k=S.key(record);if(model.undo(k)){if(selected===k)edit(null,true);render();status("Change undone. The record is back to its saved version.","success");$("rows").querySelector('tr[data-record-key="'+CSS.escape(k)+'"] button')?.focus();}});
    return b;
  }
  // C23: the delete confirmation names the record it deletes (name, type and every value).
  function deleteDetails(record) {
    const list=$("delete-record");list.replaceChildren();
    for (const [label,value] of [["Name",record.name],["Type",record.type],[record.values.length===1?"Value":"Values",record.values.map(v=>v===""?"(empty string)":v).join("\n")]]) {
      const term=document.createElement("dt"),detail=document.createElement("dd");term.textContent=label;detail.textContent=value;detail.translate=false;if(label!=="Name")detail.className="record-value";list.append(term,detail);
    }
  }
  $("delete-cancel").addEventListener("click",()=>$("delete-dialog").close());
  $("delete-dialog").addEventListener("close",()=>{const opener=deletion?.opener,k=deletion?.key;deletion=null;if(!connected)return;const undo=k&&$("rows").querySelector('tr[data-record-key="'+CSS.escape(k)+'"] .row-undo');if(opener?.isConnected&&!opener.disabled)opener.focus();else if(undo)undo.focus();else if(!$("review").disabled)$("review").focus();else $("new-record").focus();});
  $("delete-confirm").addEventListener("click",()=>{
    const target=deletion,record=target&&model.draft.find(item=>S.key(item)===target.key);
    $("delete-dialog").close();
    if(!target||target.epoch!==epoch||locked()||model.formDirty||!record||JSON.stringify(record)!==target.record){status("The draft changed. Review the current record before marking it for deletion.","error");return;}
    model.remove(target.key);if(selected===target.key)edit(null,true);deletion={key:target.key};render();status("Record marked for deletion. Review changes before applying; Undo restores it.");
  });
  async function request(method, body, target = endpoint.href) {
    const captured=epoch, controller=new AbortController();requests.add(controller);const timeout=setTimeout(()=>controller.abort(),30000);
    try {
      const response=await fetch(target,{method,headers:{...(window.secDNSAgent?.headers(token,method)||{Authorization:"Bearer "+token}),...(body?{"Content-Type":"application/json"}:{})},body,credentials:window.secDNSAgent?.credentials()||"omit",cache:"no-store",redirect:"error",signal:controller.signal});
      if(captured!==epoch)throw new DOMException("Disconnected","AbortError");
      // Authentication status is authoritative even if the response body is broken.
      if(response.status===401||response.status===403){const error=new Error("authentication");error.status=response.status;throw error;}
      let data;try{data=await response.json();}catch{throw new Error("unexpected_response");}
      if(captured!==epoch)throw new DOMException("Disconnected","AbortError");
      if(!response.ok){const e=new Error("unexpected_response");e.status=response.status;const allowed={400:["invalid_snapshot_request"],413:["snapshot_too_large"],409:["identity_conflict","revision_conflict","operation_conflict","receipt_capacity","revision_exhausted","operator_provenance_unavailable","rrset_schema_required","removal_confirmation_required","removal_confirmation_mismatch"],503:["snapshot_unavailable","removal_check_unavailable"]};if(allowed[response.status]?.includes(data?.error))e.message=data.error;e.definitive=([400,409,413].includes(response.status)&&e.message!=="unexpected_response")||e.message==="removal_check_unavailable";throw e;}
      const names=["SecDNS-Operator-Provenance-Profile","SecDNS-Operator-Provenance-Source-SHA256","SecDNS-Operator-Provenance-Content-SHA256"],present=names.map(name=>response.headers.has(name));
      let provenance=null;if(present.some(Boolean)){if(!present.every(Boolean))throw new Error("unexpected_response");provenance={profile:response.headers.get(names[0]),source_sha256:response.headers.get(names[1]),content_sha256:response.headers.get(names[2])};if(!S.operatorProvenance(provenance))throw new Error("unexpected_response");}
      return {data,provenance,rrsetCapability:response.headers.get("SecDNS-RRset-Mutations")};
    } finally {clearTimeout(timeout);requests.delete(controller); }
  }
  // Long DNS names may wrap only after a dot (never inside a label); addresses never wrap.
  // Long DNS names wrap only after a dot: each label is one unbreakable unit (never split at a
  // hyphen); an over-long label is cut with an ellipsis and the full name is in the title and Copy.
  function breakable(el, text) {el.textContent="";const parts=String(text).split(".");parts.forEach((part,i)=>{const label=document.createElement("span");label.className="dns-label";label.textContent=part+(i<parts.length-1?".":"");if(label.textContent)el.append(label);if(i<parts.length-1&&part!=="")el.append(document.createElement("wbr"));});el.title=String(text);}
  async function fetchCurrent() {
    const id=++getID, captured=epoch;
    loading=true;connectionState();if(!model.base)recordsState();
    try{const result=await request("GET");if(captured!==epoch||id!==getID)return false;loading=false;loadError=null;lastLoaded=new Date().toISOString();const previousBase=model.base;model.accept(result.data,result.provenance,result.rrsetCapability);if(model.base!==previousBase&&!model.formDirty)edit(null,true);render();return true;}
    catch(e){if(captured===epoch&&id===getID){loading=false;if(e.message!=="authentication"&&e.name!=="AbortError")loadError=e;model.fresh=false;if(e.message==="authentication"){if(e.status===401&&window.secDNSAgent?.active)window.secDNSAgent.expire();else disconnect(false);status(message(e),"error");}render();throw e;}return false;}
  }
  function disconnect(show=true) {
    epoch++;getID++;for(const r of requests)r.abort();requests.clear();
    if(model.pending?.status==="sending")model.uncertain();
    token="";$("token").value="";connected=false;busy=false;model.fresh=false;loading=false;$("review-dialog").close();$("delete-dialog").close();render();if(show)status("Disconnected. Local draft and operation recovery remain in this page.");
  }
  $("connect-form").addEventListener("submit",async e=>{
    e.preventDefault();if(busy)return;const entered=$("token").value.trim();$("token").value="";if(!entered)return;try{await window.secDNSAgent?.switchToLegacy();}catch{status("Could not end the agent session. Legacy access was not started.","error");return;}token=entered;
    const captured=epoch;busy=true;controls();status("Loading current snapshot…");
    try{await fetchCurrent();if(captured!==epoch)return;connected=true;status(model.pending?"Reconnected. Pending operation retained; no automatic submission.":"Records loaded.","success",!model.pending);}
    catch(error){if(captured===epoch){token="";connected=false;status(message(error),"error");}}
    finally{if(captured===epoch){busy=false;render();}}
  });
  $("disconnect").addEventListener("click",()=>{if(window.secDNSAgent?.active)void window.secDNSAgent.logout().catch(()=>{});disconnect();});
 window.addEventListener("agentexpired",()=>{disconnect(false);status("Authentication session ended. Local draft and pending recovery are preserved.","error");});
 async function loadAfterSignIn(){if(busy)return;token="";const captured=epoch;try{await fetchCurrent();if(captured!==epoch)return;connected=true;if(restoreDraft())return;status(model.pending?"Signed in. Pending changes preserved; nothing was submitted.":"Records loaded.","success",!model.pending);}catch(e){if(loadError)status("","",true);else status(message(e),"error");}finally{render();}}
 window.addEventListener("agentconnected",loadAfterSignIn);
  // Unsaved work kept in this tab while the owner confirmed with WithMy ID (or signed in again):
  // the draft, its base, an unfinished record form and an uncertain submitted change.
  window.secDNSAgent?.drafts?.register("records",()=>{
    const kept=model.exportDraft(),form=model.formDirty&&!$("record-editor").hidden?{selected,name:$("name").value,type:$("type").value,ttl:$("ttl").value,values:[...$("values").querySelectorAll("textarea")].map(v=>v.value),expiryMode:$("expiry-mode").value,expiry:$("expiry").value}:null;
    if(!kept&&!form)return null;return {model:kept,form};
  });
  function restoreDraft(){
    const saved=window.secDNSAgent?.drafts?.take("records");if(!saved||typeof saved!=="object")return false;
    try{
      if(saved.model)model.importDraft(saved.model,[endpoint.href,endpoint.href+"/rrset"]);
      const f=saved.form;
      if(f&&typeof f==="object"&&typeof f.name==="string"&&["A","AAAA","CNAME","TXT"].includes(f.type)&&Array.isArray(f.values)&&f.values.every(v=>typeof v==="string")){
        const record=f.selected?model.draft.find(r=>S.key(r)===f.selected):null;edit(record||null,true,true);
        if(!record){$("name").value=f.name;$("type").value=f.type;}$("ttl").value=String(f.ttl);$("values").replaceChildren();for(const v of f.values.length?f.values:[""])valueRow(v);$("expiry-mode").value=f.expiryMode==="absolute"?"absolute":"permanent";$("expiry").value=typeof f.expiry==="string"?f.expiry:"";model.touch();
      }
      render();status(model.pending?.status==="uncertain"?"Your unsaved changes were kept while you signed in. A submitted change is still unconfirmed; use Check submitted change.":"Your unsaved changes were kept while you signed in. Review them before applying.","success");return true;
    }catch(e){render();status(message(new Error("draft_restore_refused")),"error");return true;}
  }
  function randomID(){if(!globalThis.crypto?.getRandomValues)throw new Error("randomness_unavailable");const random=crypto.getRandomValues(new Uint8Array(24));return Array.from(random,x=>x.toString(16).padStart(2,"0")).join("");}
  $("open-import").addEventListener("click",event=>{
    if(typeof BroadcastChannel!=="function"||!globalThis.crypto?.getRandomValues)return;
    event.preventDefault();importChannel?.close();importChannelID=randomID();importChannel=new BroadcastChannel("secdns-routeros-draft-"+importChannelID);
    const channel=importChannel,channelID=importChannelID,targetPath=location.pathname,sourcePath=previewURL.pathname;
    channel.addEventListener("message",event=>{
      if(channel!==importChannel||channelID!==importChannelID||!S.exactDraftHandoff(event.data,channelID,sourcePath,targetPath,Date.now()))return;
      let accepted=false,error="";
      try{if(!connected||busy||requests.size)throw new Error("editor_unavailable");model.importCandidate(event.data,channelID,sourcePath,targetPath,Date.now());edit(null,true);render();status("Exact candidate loaded into the local draft. Review every change before any replacement.","success");accepted=true;}
      catch(e){error=["handoff_reconciliation_required","handoff_identity_conflict","invalid_draft_handoff"].includes(e.message)?e.message:"editor_unavailable";status(message(new Error(error)),"error");}
      channel.postMessage({kind:"secdns.routeros-exact-draft-result.v1",channel_id:channelID,request_id:event.data.request_id,accepted,...(accepted?{}:{error})});
    });
    const target=new URL(previewURL.href);target.hash=new URLSearchParams({draft_handoff:channelID,target:targetPath,...(model.base?{ruleset:model.base.ruleset_id}:{})}).toString();window.open(target.href,"_blank","noopener,noreferrer");
  });
  window.addEventListener("pagehide",()=>{importChannel?.close();importChannel=null;importChannelID="";disconnect(false);});
  window.addEventListener("pageshow",e=>{if(e.persisted)disconnect();});
  window.addEventListener("beforeunload",e=>{if((model.dirty()||model.pending)&&!window.secDNSAgent?.leaving){e.preventDefault();e.returnValue="";}});
  $("filter").addEventListener("input",listChanged);
  $("new-record").addEventListener("click",()=>edit(null,false,true));
  $("add-value").addEventListener("click",()=>{if(locked())return;valueRow("");model.touch();controls();});
  $("editor").addEventListener("input",()=>{model.touch();controls();});
  $("expiry-mode").addEventListener("change",()=>{model.touch();controls();});
  $("editor").addEventListener("submit",e=>{
    e.preventDefault();if(locked())return;clearRecordError();
    const record={name:$("name").value,type:$("type").value,values:[...$("values").querySelectorAll("textarea")].map(v=>v.value),ttl_seconds:Number($("ttl").value)};
    if($("expiry-mode").value==="absolute")record.expires_at=$("expiry").value;
    const issues=S.draftIssues(record,model.draft,selected);if(issues.length){showIssues(issues);return;}
    try{model.stage(record,selected);edit(null,true);render();status("Record staged locally. Review the proposal before sending.","success");}catch(error){if(error.issue)showIssues([error.issue]);else status(message(error),"error");}
  });
  $("refresh").addEventListener("click",async()=>{if(busy||!connected)return;const captured=epoch;try{const accepted=await fetchCurrent();if(accepted&&captured===epoch)status(model.pending?.status==="uncertain"?"Records refreshed. The change is still unconfirmed; use Check submitted change to send the identical request and check its result safely.":model.pending?.status==="acknowledged"?"Changes saved. Review your remaining local edits before saving again.":model.dirty()?"Records refreshed. Your unsaved edits are preserved.":"Records refreshed.",model.pending?.status==="uncertain"?"error":"success");}catch(e){if(captured===epoch){if(loadError)status("","",true);else status(message(e),"error");}}finally{if(captured===epoch)render();}});
  $("adopt").addEventListener("click",()=>{if($("adopt").disabled)return;if(confirm("Discard all staged and unfinished edits and the previous attempt, then load the full current snapshot? Re-enter desired edits manually. A prior request may already have committed.")){try{model.adopt();edit(null,true);render();status("Loaded current snapshot as a new clean base.","success");}catch(e){status(message(e),"error");}}});
  $("clear").addEventListener("click",()=>{if(confirm("Clear all local drafts, pending request identity and receipt, then disconnect? This cannot cancel or undo any server operation. Closing or reloading also loses this recovery information.")){disconnect(false);model.clear();edit(null,true);render();status("Local work cleared. Reconnect explicitly to load a server snapshot.");}});
  function reviewValues(record) {
    const box=document.createElement("div");box.className="review-values";
    for(const value of record.values){const v=document.createElement("div");v.className="record-value";v.translate=false;v.textContent=value===""?"(empty string)":value;box.append(v);}
    const meta=document.createElement("div");meta.className="review-meta";meta.textContent="TTL "+record.ttl_seconds+" s";box.append(meta);
    if(record.expires_at){const e=document.createElement("div");e.className="review-meta";stamp(e,record.expires_at,"Expires {time}");box.append(e);}
    return box;
  }
  function reviewGroups(rows) {
    const out=[];
    for(const [kind,title] of [["removed","Will be deleted"],["added","Will be added"],["changed","Will be changed"]]){
      const group=rows.filter(r=>r.localChange===kind);if(!group.length)continue;
      const details=document.createElement("details");details.className="review-group review-group-"+kind;details.open=kind!=="removed"||group.length<=10;
      const summary=document.createElement("summary"),label=document.createElement("span"),count=document.createElement("span");label.textContent=title;count.className="count-chip change-"+kind;count.textContent=String(group.length);summary.append(label,count);details.append(summary);
      for(const row of group){
        const record=row.draft||row.base,item=document.createElement("article"),head=document.createElement("div"),name=document.createElement("strong"),type=document.createElement("span"),undo=document.createElement("button");
        item.className="review-row";item.dataset.recordKey=row.key;head.className="review-row-head";name.className="record-name";breakable(name,record.name);type.className="review-type";type.textContent=record.type;type.translate=false;
        undo.type="button";undo.className="row-undo";undo.textContent="Undo";undo.setAttribute("aria-label","Undo changes to "+record.name+" "+record.type);
        undo.addEventListener("click",()=>{if(busy||model.pending)return;model.undo(row.key);render();if(model.dirty()&&!model.formDirty){openReview();status("Change undone. Review the remaining changes.","success");}else{$("review-dialog").close();status("Change undone. Nothing is left to apply.","success");}});
        head.append(name,type,undo);item.append(head);
        if(kind==="changed"){const pair=document.createElement("div");pair.className="review-change";for(const [label,version] of [["Before",row.base],["After",row.draft]]){const side=document.createElement("div"),h=document.createElement("span");h.className="review-label";h.textContent=label;side.append(h,reviewValues(version));pair.append(side);}item.append(pair);}
        else item.append(reviewValues(record));
        details.append(item);
      }
      out.push(details);
    }
    return out;
  }
  $("review").addEventListener("click",()=>{if(!$("review").disabled)openReview();});
  function openReview(){
    reviewedEdit=model.review(endpoint.href);const proposal=model.proposal(endpoint.href),d=S.changes(model.base.records,model.draft);
    $("review-title").textContent=proposal.mode==="rrset"?"Apply one record change?":"Apply record changes?";
    $("review-description").replaceChildren();for(const [kind,n,label] of [["added",d.added,"{n} added"],["changed",d.changed,"{n} changed"],["removed",d.removed,"{n} removed"]]){const chip=document.createElement("span");chip.className="count-chip"+(n?" change-"+kind:"");chip.textContent=label.replace("{n}",String(n));$("review-description").append(chip);}
    $("review-scope").textContent=proposal.mode==="rrset"?"Other records remain unchanged.":"This sends the complete record list, including retained expired records. The server checks that no newer changes conflict before saving.";
    $("review-technical").textContent=`Base revision ${model.base.revision}. ${proposal.mode==="rrset"?"Conditional single-record operation":"Complete snapshot replacement"}.`;
    $("review-records").replaceChildren(...reviewGroups(S.comparisonRows(model.base.records,model.draft,model.current?.records||null).filter(r=>r.localChange!=="unchanged")));
    // Replacing the record list so that records disappear is destructive: pin the impact above
    // the scrolling change list, make the action a danger button naming the count, and above a
    // threshold (5 records or 20% of the list) require typing the count or REPLACE.
    const danger=proposal.mode==="replacement"&&d.removed>0,total=model.base.records.length,typed=danger&&(d.removed>=5||d.removed*5>=total),plural=n=>n===1?"record":"records";
    reviewGuard={danger,typed,removed:d.removed};
    $("review-danger").hidden=!danger;$("review-typed").value="";$("review-typed").hidden=$("review-typed-label").hidden=!typed;
    if(danger){
      $("review-title").textContent="Replace your records?";
      $("review-danger-title").textContent=`This replaces your records: ${d.removed} removed, ${d.added} added, ${d.changed} changed`;
      $("review-danger-detail").textContent=`${d.removed} of ${total} current ${plural(total)} will be deleted and stop resolving. Only the ${model.draft.length} ${plural(model.draft.length)} in this list will remain.`;
      $("review-typed-label").textContent=`Type ${d.removed} (or REPLACE) to confirm`;
    }
    // Any change that removes records is a danger action, also a single deletion.
    $("review-confirm").className=d.removed>0?"danger-solid":"primary";
    $("review-confirm").textContent=danger?`Replace — remove ${d.removed} ${plural(d.removed)}`:d.removed>0?`Apply — delete ${d.removed} ${plural(d.removed)}`:proposal.mode==="rrset"?"Apply record change":"Apply changes";
    reviewGuardSync();if(!$("review-dialog").open)$("review-dialog").showModal();if(typed)$("review-typed").focus();else $("review-cancel").focus();
  }
  function reviewGuardMet(){if(!reviewGuard.typed)return true;const v=$("review-typed").value.trim();return v===String(reviewGuard.removed)||v.toUpperCase()==="REPLACE";}
  function reviewGuardSync(){$("review-confirm").disabled=!reviewGuardMet();}
  $("review-typed").addEventListener("input",reviewGuardSync);
  $("review-cancel").addEventListener("click",()=>$("review-dialog").close());
  $("review-dialog").addEventListener("cancel",e=>{if(busy)e.preventDefault();});
  async function send(retry) {
    if(busy||!connected||(window.secDNSAgent && !window.secDNSAgent.allows("records:write")))return;
    if(!retry){if(reviewedEdit!==model.review(endpoint.href)){status("The draft changed. Review it again.","error");return;}try{if(!globalThis.crypto?.getRandomValues)throw new Error("randomness_unavailable");const random=crypto.getRandomValues(new Uint8Array(24));const id=Array.from(random,x=>x.toString(16).padStart(2,"0")).join("");model.freeze(id,endpoint.href,reviewedEdit);}catch(e){status(message(e),"error");return;}}
    else if(model.pending?.status!=="uncertain")return;
    const pending=model.pending,captured=epoch;pending.status="sending";getID++;busy=true;controls();$("review-dialog").close();status("Saving the reviewed changes…");
    try{
      const result=await request("POST",pending.body,pending.endpoint);if(captured!==epoch)return;model.acknowledge(result.data,result.provenance);render();
      try{await fetchCurrent();if(captured===epoch)status(model.pending?"Changes saved. Review your remaining local edits before saving again.":"Records saved.","success");}
      catch(e){if(captured===epoch)status("Saved; current state could not be loaded. The receipt and draft are retained. Fetch current before another proposal.","error");}
    }catch(e){if(captured!==epoch)return;if(e.definitive){pending.status="rejected";model.fresh=false;if(e.message==="identity_conflict")model.identityBlocked=true;status(message(e),"error");}else{model.uncertain();status(message(e)+" "+messages.uncertain,"error");}if(e.message==="authentication"){if(e.status===401&&window.secDNSAgent?.active)window.secDNSAgent.expire();else disconnect(false);}}
    finally{if(captured===epoch){busy=false;render();}}
  }
  $("review-confirm").addEventListener("click",()=>{if(!reviewGuardMet())return;void send(false);});$("retry").addEventListener("click",()=>void send(true));
  $("show-unchanged").addEventListener("change",renderComparison);
  readListState();edit(null,true);render();
  // The sticky records toolbar's height positions the sticky table header below it.
  if(typeof ResizeObserver==="function")new ResizeObserver(()=>document.body.style.setProperty("--records-sticky-h",$("records-sticky").offsetHeight+"px")).observe($("records-sticky"));
})();

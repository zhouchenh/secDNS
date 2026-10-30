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
    $("workspace").classList.toggle("editing",!$("record-editor").hidden);
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
  function valueRow(text) {
    const row = document.createElement("div"); row.className = "value-row";
    const input = document.createElement("textarea"); input.value = text; input.setAttribute("aria-label", "Record value"); input.spellcheck = false;
    const remove = document.createElement("button"); remove.type = "button"; remove.textContent = "Remove";
    remove.addEventListener("click", () => { if (locked()) return; row.remove(); model.touch(); controls(); });
    row.append(input,remove); $("values").append(row);
  }
  function clearRecordError(){ $("record-error").hidden=true;$("record-error").textContent="";for(const field of $("editor").querySelectorAll("[aria-invalid]")){field.removeAttribute("aria-invalid");const described=(field.getAttribute("aria-describedby")||"").split(/\s+/).filter(id=>id&&id!=="record-error");if(described.length)field.setAttribute("aria-describedby",described.join(" "));else field.removeAttribute("aria-describedby");}}
  function edit(record = null, force = false, open = false) {
    if (!force && model.formDirty && !confirm("Discard unfinished record fields? The staged snapshot draft is retained.")) return;
    clearRecordError();
    selected = record ? S.key(record) : null; model.formDirty = false;$("record-editor").hidden=!open;
    $("editor-title").textContent = record ? "Edit record" : "New record";$("stage").textContent=record?"Update changes":"Add to changes";
    $("name").value = record?.name || ""; $("type").value = record?.type || "A"; $("ttl").value = String(record?.ttl_seconds ?? 300);
    $("values").replaceChildren(); for (const value of record?.values || [""]) valueRow(value);
    $("expiry-mode").value = record?.expires_at ? "absolute" : "permanent"; $("expiry").value = record?.expires_at || ""; controls();if(open)$("editor-title").focus();
  }
  window.addEventListener("beforeunload",event=>{if((model.dirty()||model.pending)&&!window.secDNSAgent?.leaving){event.preventDefault();event.returnValue="";}});
  $("close-editor").addEventListener("click",()=>{if(model.formDirty&&!confirm("Discard unfinished fields? Staged changes are retained."))return;edit(null,true);$("new-record").focus();});
  $("record-type-filter").addEventListener("change",render);
  $("pending-only").addEventListener("change",render);
  $("reset-filters").addEventListener("click",()=>{$("filter").value="";$("record-type-filter").value="";$("pending-only").checked=false;render();$("filter").focus();});
  function render() {
    $("workspace").hidden = !model.base;
    $("connection").textContent = connected ? (model.fresh?"Records loaded":"Refresh needed") : "Disconnected";
    $("disconnect").hidden = !connected || !!window.secDNSAgent?.active; $("login").hidden = connected || document.body.dataset.recordGateway === "true";
    $("base-version").textContent = "Base revision " + (model.base?.revision || "—");
    $("current-version").textContent = "Observed current " + (model.current?.revision || "—");
    const diff = S.changes(model.base?.records || [], model.draft);
    $("change-count").textContent = `${diff.added} added · ${diff.changed} changed · ${diff.removed} removed`;
    $("receipt").textContent = model.receipt ? "Acknowledged operation " + model.receipt.operation_id + " at revision " + model.receipt.revision + " · " + model.receipt.committed_at + ". This receipt is not a current-state snapshot." : "";
    $("saved-details").hidden=!model.receipt;
    const origin=model.draftProvenance;$("draft-provenance-details").hidden=!origin;$("draft-provenance").textContent=origin?"Operator-supplied strict candidate · ruleset "+origin.rulesetID+" · source SHA-256 "+origin.sourceSHA256+" · content SHA-256 "+origin.contentSHA256+" · "+(model.edits===origin.editCounter?"unchanged after transfer; the tuple will be submitted":"locally edited; the original tuple will not be submitted")+". The source and profile are not authenticated by the snapshot server.":"";
    $("count").textContent = String(model.draft.length); $("rows").replaceChildren();
    const filter = $("filter").value.toLowerCase(), typeFilter=$("record-type-filter").value; let count = 0;
    for (const record of model.draft) {
      if (typeFilter && record.type!==typeFilter) continue;
      if ($("pending-only").checked) {const original=model.base?.records.find(r=>S.key(r)===S.key(record));if(original&&JSON.stringify(original)===JSON.stringify(record))continue;}
      if (![record.name,record.type,...record.values].some(v => v.toLowerCase().includes(filter))) continue; count++;
      const tr = document.createElement("tr"), info = document.createElement("td"), title = document.createElement("div");tr.dataset.recordKey=S.key(record); title.className = "record-name"; breakable(title, record.name); info.append(title);const original=model.base?.records.find(r=>S.key(r)===S.key(record));if(!original||JSON.stringify(original)!==JSON.stringify(record)){const pending=document.createElement("span");pending.className="draft-marker";pending.textContent="Pending";info.append(pending);} const valueCell=document.createElement("td");
      for (const value of record.values) {const d = document.createElement("div");d.className="record-value";if(value==="")d.textContent="(empty string)";else if(record.type==="A"||record.type==="AAAA"){d.classList.add("record-ip");d.textContent=value;}else if(record.type==="CNAME"){d.classList.add("record-fqdn");breakable(d,value);}else d.textContent=value;valueCell.append(d);}
      if (record.expires_at) {const d=document.createElement("div");const expired=Date.parse(record.expires_at)<=Date.now();d.className=expired?"record-expired":"record-expiry";stamp(d,record.expires_at,expired?"Expired · retained {time}":"Expires {time}");valueCell.append(d);}
      const typeCell=document.createElement("td"),ttlCell=document.createElement("td");typeCell.textContent=record.type;typeCell.translate=false;ttlCell.textContent=record.ttl_seconds+" s";tr.append(info,typeCell,valueCell,ttlCell);
      const actions=document.createElement("td"), change=document.createElement("button"), remove=document.createElement("button");change.textContent="Edit";remove.textContent="Delete";change.setAttribute("aria-label","Edit "+record.name+" "+record.type);remove.setAttribute("aria-label","Delete "+record.name+" "+record.type);
      if(!original||JSON.stringify(original)!==JSON.stringify(record))actions.append(undoButton(record));
      change.addEventListener("click",()=>{if(!locked()) edit(record,false,true);});
      remove.addEventListener("click",()=>{if(locked())return;if(model.formDirty){status("Stage or discard unfinished fields before deleting a row.","error");return;}deletion={key:S.key(record),record:JSON.stringify(record),epoch,opener:remove};deleteDetails(record);$("delete-dialog").showModal();$("delete-cancel").focus();});
      actions.append(change,remove);tr.append(actions);$("rows").append(tr);
    }
    // Records marked for deletion stay listed (struck through) until the change is applied, each with Undo.
    if (model.base) for (const record of model.base.records) {
      if (model.draft.some(r=>S.key(r)===S.key(record))) continue;
      if (typeFilter && record.type!==typeFilter) continue;
      if (![record.name,record.type,...record.values].some(v => v.toLowerCase().includes(filter))) continue;
      const tr=document.createElement("tr");tr.className="row-removed";tr.dataset.recordKey=S.key(record);
      const info=document.createElement("td"),title=document.createElement("div");title.className="record-name";breakable(title,record.name);const marker=document.createElement("span");marker.className="draft-marker removal-marker";marker.textContent="Will be deleted";info.append(title,marker);
      const typeCell=document.createElement("td");typeCell.textContent=record.type;typeCell.translate=false;const valueCell=document.createElement("td");for(const value of record.values){const d=document.createElement("div");d.className="record-value";d.textContent=value===""?"(empty string)":value;valueCell.append(d);}
      const ttlCell=document.createElement("td");ttlCell.textContent=record.ttl_seconds+" s";const actions=document.createElement("td");actions.append(undoButton(record));tr.append(info,typeCell,valueCell,ttlCell,actions);$("rows").append(tr);
    }
    $("count").textContent=count===model.draft.length?String(count):count+" of "+model.draft.length;
    $("results-count").textContent=`${count} of ${model.draft.length} records`+($("pending-only").checked?" | Pending changes, including records that will be deleted.":" | Changes are reviewed before they are applied.");
    $("reset-filters").hidden=!filter&&!typeFilter&&!$("pending-only").checked;
    $("empty").hidden=count>0;$("empty").textContent=model.draft.length?"No records match these filters. Reset filters to see all records.":model.base?.records.length?"All records are marked for removal. Review changes before applying.":"No records yet. Add a record or import an export to get started.";
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
  function breakable(el, text) {el.textContent="";const parts=String(text).split(".");parts.forEach((part,i)=>{el.append(part+(i<parts.length-1?".":""));if(i<parts.length-1&&part!=="")el.append(document.createElement("wbr"));});}
  async function fetchCurrent() {
    const id=++getID, captured=epoch;
    try{const result=await request("GET");if(captured!==epoch||id!==getID)return false;const previousBase=model.base;model.accept(result.data,result.provenance,result.rrsetCapability);if(model.base!==previousBase&&!model.formDirty)edit(null,true);render();return true;}
    catch(e){if(captured===epoch&&id===getID){model.fresh=false;if(e.message==="authentication"){if(e.status===401&&window.secDNSAgent?.active)window.secDNSAgent.expire();else disconnect(false);status(message(e),"error");}render();throw e;}return false;}
  }
  function disconnect(show=true) {
    epoch++;getID++;for(const r of requests)r.abort();requests.clear();
    if(model.pending?.status==="sending")model.uncertain();
    token="";$("token").value="";connected=false;busy=false;model.fresh=false;$("review-dialog").close();$("delete-dialog").close();render();if(show)status("Disconnected. Local draft and operation recovery remain in this page.");
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
 window.addEventListener("agentconnected",async()=>{if(busy)return;token="";const captured=epoch;try{await fetchCurrent();if(captured!==epoch)return;connected=true;if(restoreDraft())return;status(model.pending?"Signed in. Pending changes preserved; nothing was submitted.":"Records loaded.","success",!model.pending);}catch(e){status(message(e),"error");}finally{render();}});
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
  $("filter").addEventListener("input",render);
  $("new-record").addEventListener("click",()=>edit(null,false,true));
  $("add-value").addEventListener("click",()=>{if(locked())return;valueRow("");model.touch();controls();});
  $("editor").addEventListener("input",()=>{model.touch();controls();});
  $("expiry-mode").addEventListener("change",()=>{model.touch();controls();});
  $("editor").addEventListener("submit",e=>{
    e.preventDefault();if(locked())return;clearRecordError();
    const record={name:$("name").value,type:$("type").value,values:[...$("values").querySelectorAll("textarea")].map(v=>v.value),ttl_seconds:Number($("ttl").value)};
    if($("expiry-mode").value==="absolute")record.expires_at=$("expiry").value;
    try{model.stage(record,selected);edit(null,true);render();status("Record staged locally. Review the proposal before sending.","success");}catch(error){if(error.issue){const issue=error.issue,field=issue.field==="values"?$("values").querySelectorAll("textarea")[issue.index||0]:$(issue.field);$("record-error").textContent=issue.text;$("record-error").hidden=false;if(field){field.setAttribute("aria-invalid","true");field.setAttribute("aria-describedby",[...(field.getAttribute("aria-describedby")||"").split(/\s+/).filter(Boolean),"record-error"].join(" "));field.focus();}controls();}else status(message(error),"error");}
  });
  $("refresh").addEventListener("click",async()=>{if(busy||!connected)return;const captured=epoch;try{const accepted=await fetchCurrent();if(accepted&&captured===epoch)status(model.pending?.status==="uncertain"?"Records refreshed. The change is still unconfirmed; use Check submitted change to send the identical request and check its result safely.":model.pending?.status==="acknowledged"?"Changes saved. Review your remaining local edits before saving again.":model.dirty()?"Records refreshed. Your unsaved edits are preserved.":"Records refreshed.",model.pending?.status==="uncertain"?"error":"success");}catch(e){if(captured===epoch)status(message(e),"error");}finally{if(captured===epoch)render();}});
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
  edit(null,true);render();
})();

(() => {
  "use strict";
  const S = globalThis.SnapshotEditor, model = new S.Model(), $ = id => document.getElementById(id);
  const endpoint = new URL("../snapshot", document.currentScript.src);
  if (endpoint.origin !== location.origin) throw new Error("Invalid editor origin");
  $("endpoint").textContent = endpoint.origin + endpoint.pathname;
  let token = "", epoch = 0, getID = 0, connected = false, busy = false, selected = null, reviewedEdit = null;
  const requests = new Set();
  function status(text, kind = "") { $("status").textContent = text; $("status").className = kind; }
  const messages = {
    invalid_snapshot_request:"The proposal is invalid. Your draft is preserved; correct it after reconciliation.",
    snapshot_too_large:"The complete proposal exceeds the size limit. Your draft is preserved.",
    revision_conflict:"The server changed since your base revision. Compare snapshots, then explicitly discard/reload and manually re-enter desired edits.",
    identity_conflict:"The server identity or lineage differs. Writing is blocked. Clear local work only after reviewing it, then reconnect explicitly.",
    operation_conflict:"This operation ID conflicts with another request. The frozen attempt is preserved; no replacement ID was generated.",
    receipt_capacity:"The operation receipt ledger is full. Operator intervention is required.",
    revision_exhausted:"The revision range is exhausted. Operator intervention is required.",
    snapshot_unavailable:"The store is unavailable. Local work is preserved.",
    authentication:"Authentication failed. Reconnect with a token; local work and pending recovery are preserved.",
    stale_snapshot_response:"An older snapshot response was ignored. Fetch current state again.",
    duplicate_record:"That name and type already exist in the draft. Edit the existing row.",
    reconciliation_required:"Stage unfinished fields and reconcile current state before preparing another replacement.",
    uncertain:"The operation outcome is uncertain. Retry only the same frozen operation; disconnecting does not roll it back.",
    invalid_snapshot_response:"The server returned an invalid snapshot. Local work is preserved."
  };
  const message = e => messages[e.message] || "Unexpected response or connection failure. Local work is preserved.";
  const locked = () => busy || !connected || !!model.pending || model.identityBlocked;
  function controls() {
    for (const c of $("editor").querySelectorAll("input, select, textarea, button")) c.disabled = locked();
    $("name").disabled = $("type").disabled = locked() || !!selected;
    $("expiry").disabled = locked() || $("expiry-mode").value === "permanent";
    $("new-record").disabled = locked();
    for (const b of $("rows").querySelectorAll("button")) b.disabled = locked();
    $("review").disabled = locked() || !model.fresh || !model.dirty() || model.formDirty;
    $("retry").hidden = !model.pending || model.pending.status !== "uncertain";
    $("retry").disabled = busy || !connected || model.identityBlocked;
    $("adopt").disabled = busy || !connected || !model.current || !model.fresh || model.identityBlocked || ["sending","uncertain"].includes(model.pending?.status);
    $("refresh").disabled = busy || !connected;
    $("connect").disabled = busy;
    $("review-confirm").disabled = busy;
    $("review-cancel").disabled = busy;
    $("clear").disabled = busy;
  }
  function valueRow(text) {
    const row = document.createElement("div"); row.className = "value-row";
    const input = document.createElement("textarea"); input.value = text; input.setAttribute("aria-label", "Record value"); input.spellcheck = false;
    const remove = document.createElement("button"); remove.type = "button"; remove.textContent = "Remove";
    remove.addEventListener("click", () => { if (locked()) return; row.remove(); model.touch(); controls(); });
    row.append(input,remove); $("values").append(row);
  }
  function edit(record = null, force = false) {
    if (!force && model.formDirty && !confirm("Discard unfinished record fields? The staged snapshot draft is retained.")) return;
    selected = record ? S.key(record) : null; model.formDirty = false;
    $("editor-title").textContent = record ? "Edit draft record" : "Create record";
    $("name").value = record?.name || ""; $("type").value = record?.type || "A"; $("ttl").value = String(record?.ttl_seconds ?? 300);
    $("values").replaceChildren(); for (const value of record?.values || [""]) valueRow(value);
    $("expiry-mode").value = record?.expires_at ? "absolute" : "permanent"; $("expiry").value = record?.expires_at || ""; controls();
  }
  function render() {
    $("workspace").hidden = !model.base;
    $("connection").textContent = connected ? "Connected · snapshot API" : "Disconnected";
    $("disconnect").hidden = !connected; $("login").hidden = connected;
    $("base-version").textContent = "Base revision " + (model.base?.revision || "—");
    $("current-version").textContent = "Observed current " + (model.current?.revision || "—");
    const diff = S.changes(model.base?.records || [], model.draft);
    $("change-count").textContent = `${diff.added} added · ${diff.changed} changed · ${diff.removed} removed`;
    $("receipt").textContent = model.receipt ? "Acknowledged operation " + model.receipt.operation_id + " at revision " + model.receipt.revision + " · " + model.receipt.committed_at + ". This receipt is not a current-state snapshot." : "";
    $("count").textContent = String(model.draft.length); $("rows").replaceChildren();
    const filter = $("filter").value.toLowerCase(); let count = 0;
    for (const record of model.draft) {
      if (![record.name,record.type,...record.values].some(v => v.toLowerCase().includes(filter))) continue; count++;
      const tr = document.createElement("tr"), info = document.createElement("td"), title = document.createElement("div"); title.className = "record-name"; title.textContent = record.name; info.append(title);
      for (const value of record.values) {const d = document.createElement("div");d.className="record-value";d.textContent=value===""?"(empty string)":value;info.append(d);}
      if (record.expires_at) {const d=document.createElement("div");const expired=Date.parse(record.expires_at)<=Date.now();d.className=expired?"record-expired":"record-expiry";d.textContent=(expired?"Expired · retained ":"Expires ")+record.expires_at;info.append(d);}
      tr.append(info);for(const text of [record.type,record.ttl_seconds+" s"]){const td=document.createElement("td");td.textContent=text;tr.append(td);}
      const actions=document.createElement("td"), change=document.createElement("button"), remove=document.createElement("button");change.textContent="Edit";remove.textContent="Delete";
      change.addEventListener("click",()=>{if(!locked()) edit(record);});
      remove.addEventListener("click",()=>{if(locked())return;if(model.formDirty){status("Stage or discard unfinished fields before deleting a row.","error");return;}if(confirm("Stage deletion of "+record.name+" · "+record.type+"? Nothing is sent until the complete replacement is confirmed.")){model.remove(S.key(record));if(selected===S.key(record))edit(null,true);render();}});
      actions.append(change,remove);tr.append(actions);$("rows").append(tr);
    }
    $("empty").hidden=count>0;$("empty").textContent=model.draft.length?"No draft records match this filter.":"The draft is empty.";
    $("comparison").textContent=JSON.stringify({base:model.base?.records||[],draft:model.draft,current:model.current?.records||[]},null,2);controls();
  }
  async function request(method, body) {
    const captured=epoch, controller=new AbortController();requests.add(controller);const timeout=setTimeout(()=>controller.abort(),30000);
    try {
      const response=await fetch(endpoint.href,{method,headers:{Authorization:"Bearer "+token,...(body?{"Content-Type":"application/json"}:{})},body,credentials:"omit",cache:"no-store",redirect:"error",signal:controller.signal});
      if(captured!==epoch)throw new DOMException("Disconnected","AbortError");
      // Authentication status is authoritative even if the response body is broken.
      if(response.status===401||response.status===403){const error=new Error("authentication");error.status=response.status;throw error;}
      let data;try{data=await response.json();}catch{throw new Error("unexpected_response");}
      if(captured!==epoch)throw new DOMException("Disconnected","AbortError");
      if(!response.ok){const e=new Error("unexpected_response");e.status=response.status;const allowed={400:["invalid_snapshot_request"],413:["snapshot_too_large"],409:["identity_conflict","revision_conflict","operation_conflict","receipt_capacity","revision_exhausted"],503:["snapshot_unavailable"]};if(allowed[response.status]?.includes(data?.error))e.message=data.error;e.definitive=[400,409,413].includes(response.status)&&e.message!=="unexpected_response";throw e;}
      return data;
    } finally {clearTimeout(timeout);requests.delete(controller); }
  }
  async function fetchCurrent() {
    const id=++getID, captured=epoch;
    try{const data=await request("GET");if(captured!==epoch||id!==getID)return false;const previousBase=model.base;model.accept(data);if(model.base!==previousBase&&!model.formDirty)edit(null,true);render();return true;}
    catch(e){if(captured===epoch&&id===getID){model.fresh=false;if(e.message==="authentication"){disconnect(false);status(message(e),"error");}render();throw e;}return false;}
  }
  function disconnect(show=true) {
    epoch++;getID++;for(const r of requests)r.abort();requests.clear();
    if(model.pending?.status==="sending")model.uncertain();
    token="";$("token").value="";connected=false;busy=false;model.fresh=false;$("review-dialog").close();render();if(show)status("Disconnected. Local draft and operation recovery remain in this page.");
  }
  $("connect-form").addEventListener("submit",async e=>{
    e.preventDefault();if(busy)return;token=$("token").value.trim();$("token").value="";if(!token)return;
    const captured=epoch;busy=true;controls();status("Loading current snapshot…");
    try{await fetchCurrent();if(captured!==epoch)return;connected=true;status(model.pending?"Reconnected. Pending operation retained; no automatic submission.":"Snapshot loaded.","success");}
    catch(error){if(captured===epoch){token="";connected=false;status(message(error),"error");}}
    finally{if(captured===epoch){busy=false;render();}}
  });
  $("disconnect").addEventListener("click",()=>disconnect());
  window.addEventListener("pagehide",()=>disconnect(false));
  window.addEventListener("pageshow",e=>{if(e.persisted)disconnect();});
  window.addEventListener("beforeunload",e=>{if(model.dirty()||model.pending){e.preventDefault();e.returnValue="";}});
  $("filter").addEventListener("input",render);
  $("new-record").addEventListener("click",()=>edit());
  $("add-value").addEventListener("click",()=>{if(locked())return;valueRow("");model.touch();controls();});
  $("editor").addEventListener("input",()=>{model.touch();controls();});
  $("expiry-mode").addEventListener("change",()=>{model.touch();controls();});
  $("editor").addEventListener("submit",e=>{
    e.preventDefault();if(locked())return;
    const record={name:$("name").value,type:$("type").value,values:[...$("values").querySelectorAll("textarea")].map(v=>v.value),ttl_seconds:Number($("ttl").value)};
    if($("expiry-mode").value==="absolute")record.expires_at=$("expiry").value;
    try{model.stage(record,selected);edit(null,true);render();status("Record staged locally. Review the complete replacement before sending.","success");}catch(error){status(message(error),"error");}
  });
  $("refresh").addEventListener("click",async()=>{if(busy||!connected)return;const captured=epoch;try{const accepted=await fetchCurrent();if(accepted&&captured===epoch)status(model.pending?.status==="uncertain"?"Current snapshot fetched. The operation outcome is still uncertain; retry the same operation.":model.pending?.status==="acknowledged"?"Saved; newer local edits require reconciliation.":"Current snapshot fetched. Your staged and unfinished edits were preserved.",model.pending?.status==="uncertain"?"error":"success");}catch(e){if(captured===epoch)status(message(e),"error");}finally{if(captured===epoch)render();}});
  $("adopt").addEventListener("click",()=>{if($("adopt").disabled)return;if(confirm("Discard all staged and unfinished edits and the previous attempt, then load the full current snapshot? Re-enter desired edits manually. A prior request may already have committed.")){try{model.adopt();edit(null,true);render();status("Loaded current snapshot as a new clean base.","success");}catch(e){status(message(e),"error");}}});
  $("clear").addEventListener("click",()=>{if(confirm("Clear all local drafts, pending request identity and receipt, then disconnect? This cannot cancel or undo any server operation. Closing or reloading also loses this recovery information.")){disconnect(false);model.clear();edit(null,true);render();status("Local work cleared. Reconnect explicitly to load a server snapshot.");}});
  $("review").addEventListener("click",()=>{if($("review").disabled)return;reviewedEdit=model.edits;const d=S.changes(model.base.records,model.draft);$("review-description").textContent=`Base revision ${model.base.revision}: ${d.added} added, ${d.changed} changed, ${d.removed} removed. ${model.draft.length} total record sets will be submitted.`;$("review-dialog").showModal();});
  $("review-cancel").addEventListener("click",()=>$("review-dialog").close());
  $("review-dialog").addEventListener("cancel",e=>{if(busy)e.preventDefault();});
  async function send(retry) {
    if(busy||!connected)return;
    if(!retry){if(reviewedEdit!==model.edits){status("The draft changed. Review it again.","error");return;}try{if(!globalThis.crypto?.getRandomValues)throw new Error("randomness_unavailable");const random=crypto.getRandomValues(new Uint8Array(24));const id=Array.from(random,x=>x.toString(16).padStart(2,"0")).join("");model.freeze(id,endpoint.href);}catch(e){status(message(e),"error");return;}}
    else if(model.pending?.status!=="uncertain")return;
    const pending=model.pending,captured=epoch;pending.status="sending";getID++;busy=true;controls();$("review-dialog").close();status("Submitting the frozen replacement…");
    try{
      const result=await request("POST",pending.body);if(captured!==epoch)return;model.acknowledge(result);render();
      try{await fetchCurrent();if(captured===epoch)status(model.pending?"Saved; newer local edits require reconciliation.":"Replacement acknowledged and latest saved records loaded.","success");}
      catch(e){if(captured===epoch)status("Saved; current state could not be loaded. The receipt and draft are retained. Fetch current before another proposal.","error");}
    }catch(e){if(captured!==epoch)return;if(e.definitive){pending.status="rejected";model.fresh=false;if(e.message==="identity_conflict")model.identityBlocked=true;status(message(e),"error");}else{model.uncertain();status(message(e)+" "+messages.uncertain,"error");}if(e.message==="authentication")disconnect(false);}
    finally{if(captured===epoch){busy=false;render();}}
  }
  $("review-confirm").addEventListener("click",()=>void send(false));$("retry").addEventListener("click",()=>void send(true));
  edit(null,true);render();
})();

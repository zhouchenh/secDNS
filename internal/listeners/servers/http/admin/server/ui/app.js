(() => {
  "use strict";
  const $ = id => document.getElementById(id);
  const endpoint = new URL("../records", document.currentScript.src);
  if (endpoint.origin !== location.origin) throw new Error("Invalid editor origin");
  $("endpoint").textContent = endpoint.origin + endpoint.pathname;
  let token = "", generation = 0, records = [], selected = null, pendingDelete = null;
  let busy = false, ready = false, dirty = false;
  const requests = new Set();
  const types = ["A", "AAAA", "CNAME", "TXT"];
  function status(message, kind = "") { $("status").hidden=!message; $("status").textContent = message; $("status").className = kind; }
  function controls() {
    for (const input of $("editor").querySelectorAll("input, select, textarea, button")) input.disabled = busy;
    $("name").disabled = $("type").disabled = busy || !!selected;
    $("save").disabled = busy || !ready || (window.secDNSAgent && !window.secDNSAgent.allows("records:write"));
    $("refresh").disabled = busy;
    $("new-record").disabled = busy || (window.secDNSAgent && !window.secDNSAgent.allows("records:write"));
    $("delete-confirm").disabled = busy || (window.secDNSAgent && !window.secDNSAgent.allows("records:write"));
    $("delete-cancel").disabled = busy;
    for (const b of $("rows").querySelectorAll("button")) b.disabled = busy || !ready || (window.secDNSAgent && !window.secDNSAgent.allows("records:write"));
  }
  function valueRow(value) {
    const row = document.createElement("div"); row.className = "value-row";
    const input = document.createElement("textarea"); input.value = value;
    input.setAttribute("aria-label", "Record value"); input.spellcheck = false;
    const remove = document.createElement("button"); remove.type = "button"; remove.textContent = "Remove";
    remove.addEventListener("click", () => { row.remove(); dirty = true; });
    row.append(input, remove); $("values").append(row);
  }
  function expiryUI() {
    const mode = $("expiry-mode").value, editable = mode === "absolute" || mode === "relative";
    $("expiry").hidden = !editable; $("expiry-label").hidden = !editable;
    $("expiry").required = editable; $("expiry").type = mode === "relative" ? "number" : "text";
    if (mode === "relative") { $("expiry").min = "1"; $("expiry").step = "1"; }
    else { $("expiry").removeAttribute("min"); $("expiry").removeAttribute("step"); }
    $("expiry-label").textContent = mode === "relative" ? "Seconds from now" : "RFC3339 timestamp (nanoseconds accepted)";
    $("expiry-help").textContent = mode === "keep" ? "Unchanged: " + (selected?.expires_at || "Permanent") : mode === "permanent" ? "Permanent records do not expire from the store." : mode === "absolute" ? "Use an explicit timezone, for example 2030-01-01T12:00:00.123456789Z. Past timestamps are rejected." : "The server calculates expiration when it receives this request.";
  }
  function edit(record = null, open = false) {
    if (dirty && !window.confirm("Discard the unsaved record draft?")) return;
    $("record-editor").hidden=!open;$("workspace").classList.toggle("editing",open);
    selected = record; dirty = false;
    $("editor-title").textContent = record ? "Edit record" : "Create record";
    $("name").value = record?.name || ""; $("type").value = record?.type || "A";
    $("name").disabled = $("type").disabled = !!record;
    $("ttl").value = String(record?.ttl_seconds ?? 60);
    $("values").replaceChildren(); for (const value of record?.values || [""]) valueRow(value);
    $("expiry-mode").querySelector('[value="keep"]').disabled = !record;
    $("expiry-mode").value = record?.expires_at ? "keep" : "permanent";
    $("expiry").value = ""; expiryUI(); controls();if(open)$("editor-title").focus();
  }
  function render() {
    const filter = $("filter").value.toLowerCase();
    const visible = records.filter(r => [r.name, r.type, ...r.values].some(v => v.toLowerCase().includes(filter)));
    $("rows").replaceChildren(); $("count").textContent = String(records.length);
    $("empty").hidden = visible.length > 0;
    $("empty").textContent = records.length ? "No records match this filter." : "No records yet. Create the first record to get started.";
    for (const record of visible) {
      const tr = document.createElement("tr"), info = document.createElement("td");
      const name = document.createElement("div"); name.className = "record-name"; name.textContent = record.name; info.append(name);
      for (const value of record.values) { const v = document.createElement("div"); v.className = "record-value"; v.textContent = value === "" ? '(empty string)' : value; info.append(v); }
      if (record.expires_at) { const e = document.createElement("div"); e.className = "record-expiry"; e.textContent = "Expires " + record.expires_at; info.append(e); }
      tr.append(info);
      for (const text of [record.type, String(record.ttl_seconds) + " s"]) { const td = document.createElement("td"); td.textContent = text; tr.append(td); }
      const actions = document.createElement("td");
      const editButton = document.createElement("button"); editButton.textContent = "Edit"; editButton.setAttribute("aria-label","Edit "+record.name+" "+record.type); editButton.addEventListener("click", () => edit(record,true));
      const remove = document.createElement("button"); remove.textContent = "Delete"; remove.setAttribute("aria-label","Delete "+record.name+" "+record.type); remove.addEventListener("click", () => {
        pendingDelete = record; $("delete-description").textContent = record.name + " · " + record.type; $("delete-dialog").showModal();
      }); actions.append(editButton, remove); tr.append(actions); $("rows").append(tr);
    } controls();
  }
  function messageFor(error) {
    return ({400:"Invalid record or expired timestamp. Check the draft; your edits are preserved.",401:"Authentication required. Sign in or reconnect.",403:"Access denied. Check your account permissions.",409:"This name has an incompatible record set. Resolve the conflict before saving.",503:"The record store is unavailable. Your draft is preserved; check the server before retrying."})[error.status] || "Request failed. Check the connection and refresh before retrying; a lost response may still mean the server saved the change.";
  }
  async function request(method = "GET", payload, suffix = "") {
    const current = generation, controller = new AbortController(); requests.add(controller);
    try {
      const response = await fetch(endpoint.href + suffix, {method, headers:{...(window.secDNSAgent?.headers(token,method)||{Authorization:"Bearer "+token}), ...(payload ? {"Content-Type":"application/json"} : {})}, body:payload ? JSON.stringify(payload) : undefined, credentials:window.secDNSAgent?.credentials()||"omit", cache:"no-store", redirect:"error", signal:controller.signal});
      if (current !== generation) throw new DOMException("Disconnected", "AbortError");
      if (!response.ok) { const error = new Error("Request rejected"); error.status = response.status; throw error; }
      const result = await response.json();
      if (current !== generation) throw new DOMException("Disconnected", "AbortError");
      return result;
    } finally { requests.delete(controller); }
  }
  async function refresh() {
    const response = await request();
    const data = response?.records;
    if (!Array.isArray(data) || !data.every(r => r && typeof r.name === "string" && types.includes(r.type) && Array.isArray(r.values) && r.values.every(v => typeof v === "string") && Number.isInteger(r.ttl_seconds) && (r.expires_at === undefined || typeof r.expires_at === "string"))) throw new Error("Invalid record response");
    records = data; ready = true; render();
  }
  function disconnect() {
    generation++; for (const c of requests) c.abort(); requests.clear(); token = "";
    records = []; selected = pendingDelete = null; ready = busy = dirty = false;
    $("token").value = $("filter").value = ""; $("delete-dialog").close(); edit(); render();
    $("workspace").hidden = $("disconnect").hidden = true; $("login").hidden = false;
    $("connection").textContent = "Disconnected"; status("");
  }
  $("connect-form").addEventListener("submit", async event => {
    event.preventDefault(); if (busy) return;
    const entered=$("token").value.trim();$("token").value="";if(!entered)return;try{await window.secDNSAgent?.switchToLegacy();}catch{status("Could not end the agent session. Legacy access was not started.","error");return;}token=entered;
    const current = generation; busy = true; status("Connecting…");
    try { await refresh(); if (current !== generation) return; $("login").hidden = true; $("workspace").hidden = $("disconnect").hidden = false; $("connection").textContent = "Connected · " + endpoint.pathname; status("Connected.", "success"); }
    catch (e) { if (current === generation) { token = ""; status(messageFor(e), "error"); } }
    finally { if (current === generation) { busy = false; controls(); } }
  });
  $("disconnect").addEventListener("click", () => { if(window.secDNSAgent?.active){void window.secDNSAgent.logout().catch(()=>{});return;} if (!dirty || window.confirm("Disconnect and discard the unsaved draft?")) disconnect(); });
  window.addEventListener("agentexpired",()=>{generation++;for(const c of requests)c.abort();requests.clear();token="";ready=false;busy=false;$("login").hidden=false;$("connection").textContent="Sign-in required  -  draft preserved";controls();});
 window.addEventListener("agentconnected",async()=>{token="";try{await refresh();$("login").hidden=true;$("workspace").hidden=$("disconnect").hidden=false;$("connection").textContent="Agent session";status("");$("disconnect").hidden=true;}catch(e){status(messageFor(e),"error");}controls();});
 window.addEventListener("pagehide", disconnect);
  $("filter").addEventListener("input", render);
  $("close-editor").addEventListener("click",()=>{if(!confirm("Close the editor and discard unsaved fields?"))return;dirty=false;edit();$("new-record").focus();});
  $("new-record").addEventListener("click", () => edit(null,true));
  $("add-value").addEventListener("click", () => { valueRow(""); dirty = true; });
  $("editor").addEventListener("input", () => { dirty = true; });
  $("expiry-mode").addEventListener("change", () => { dirty = true; $("expiry").value = ""; expiryUI(); });
  $("refresh").addEventListener("click", async () => {
    if (busy) return; const current = generation; busy = true; controls();
    try { await refresh(); status("Records refreshed.", "success"); }
    catch(e) { if (current === generation) { ready = false; status(messageFor(e), "error"); } }
    finally { if (current === generation) { busy = false; controls(); } }
  });
  async function mutate(method, payload, suffix) {
    if (busy || !ready) return; const current = generation; busy = true; controls(); let saved = false;
    try {
      await request(method, payload, suffix); saved = true;
      if (current !== generation) return;
      if (method === "POST" || (selected && pendingDelete && selected.name === pendingDelete.name && selected.type === pendingDelete.type)) { dirty = false; edit(); }
      $("delete-dialog").close(); pendingDelete = null;
      await refresh(); status(method === "POST" ? "Saved." : "Deleted.", "success");
    } catch(e) { if (current === generation) { if (saved) ready = false; status(saved ? "Saved, but the record list could not be refreshed. Refresh before making another change." : messageFor(e), "error"); } }
    finally { if (current === generation) { busy = false; controls(); } }
  }
  $("editor").addEventListener("submit", event => {
    event.preventDefault();
    const values = [...$("values").querySelectorAll("textarea")].map(v => v.value);
    if (!values.length) { status("Add at least one value. An empty TXT string is allowed.", "error"); return; }
    const payload = {name:selected?.name || $("name").value, type:selected?.type || $("type").value, values, ttl_seconds:Number($("ttl").value)};
    const mode = $("expiry-mode").value;
    if (mode === "relative") { const seconds = Number($("expiry").value); if (!Number.isSafeInteger(seconds) || seconds <= 0) { status("Enter a positive whole number of seconds.", "error"); return; } payload.expires_in_seconds = seconds; }
    else payload.expires_at = mode === "keep" ? selected?.expires_at || null : mode === "absolute" ? $("expiry").value : null;
    void mutate("POST", payload);
  });
  $("delete-cancel").addEventListener("click", () => { pendingDelete = null; $("delete-dialog").close(); });
  $("delete-dialog").addEventListener("cancel", event => { if (busy) event.preventDefault(); else pendingDelete = null; });
  $("delete-confirm").addEventListener("click", () => { if (pendingDelete) void mutate("DELETE", undefined, "/" + encodeURIComponent(pendingDelete.name) + "/" + encodeURIComponent(pendingDelete.type)); });
  edit(); controls();
})();

(() => {
  "use strict";
  const script = new URL(document.currentScript.src);
  const base = new URL("../", script);
  let allowedOrigin=false, publicState=null, ssoMode=false;  // ssoMode: agent sign-in is never offered on the SSO path
  let actor = null, csrf = "", epoch = 0, timer = null, warningTimer=null;
  // Why the last session ended ("expired", "ended", "signed_out", "busy"), and when; the
  // signed-out card states it. "busy" is the sign-in service refusing a new session (503).
  let ended = null, leaving = false;
  // Session-scoped drafts: pages register a saver; before a WithMy ID round trip (step-up or
  // signing in again) their unsaved work is kept in this tab's sessionStorage, keyed by page,
  // for at most 30 minutes, and restored on return. Signing out clears every saved draft.
  const DRAFTS = "secdns.draft.", DRAFT_TTL = 30 * 60000, savers = new Map();
  const draftKey = () => DRAFTS + location.pathname;
  const readDrafts = () => { try { const raw = sessionStorage.getItem(draftKey()); if (!raw) return null; const entry = JSON.parse(raw); if (!entry || entry.v !== 1 || entry.page !== location.pathname || !Number.isFinite(entry.at) || Date.now() - entry.at > DRAFT_TTL || Date.now() < entry.at - 60000 || !entry.items || typeof entry.items !== "object") { sessionStorage.removeItem(draftKey()); return null; } return entry; } catch { return null; } };
  const writeDrafts = entry => { try { if (!entry || (!Object.keys(entry.items).length && !entry.intent)) sessionStorage.removeItem(draftKey()); else sessionStorage.setItem(draftKey(), JSON.stringify(entry)); return true; } catch { return false; } };
  const clearDrafts = () => { try { for (let i = sessionStorage.length - 1; i >= 0; i--) { const k = sessionStorage.key(i); if (k && k.startsWith(DRAFTS)) sessionStorage.removeItem(k); } } catch { /* storage unavailable */ } };
  // The only places a round trip may return to: this console's own pages (same origin, a
  // plain path under the console base). Never derived from anything but location.pathname.
  const returnPath = () => { const p = location.pathname; return p.startsWith(base.pathname) && /^\/[A-Za-z0-9._~\/-]*$/.test(p) && !p.includes("//") && !/\/\.\.?(\/|$)/.test(p) ? p : base.pathname + "ui/"; };
  const drafts = Object.freeze({
    register(name, save) { if (typeof name === "string" && typeof save === "function") savers.set(name, save); },
    async preserve(intent = null) {
      const items = {};
      for (const [name, save] of savers) { try { const value = await save(); if (value !== undefined && value !== null) items[name] = value; } catch { return false; } }
      return writeDrafts({ v: 1, page: location.pathname, at: Date.now(), items, intent: intent && typeof intent.action === "string" ? { action: intent.action, at: Date.now() } : null });
    },
    // Each saved item and the intent are handed out once.
    take(name) { const entry = readDrafts(); if (!entry || !Object.hasOwn(entry.items, name)) return null; const value = entry.items[name]; delete entry.items[name]; writeDrafts(entry); return value; },
    takeIntent() { const entry = readDrafts(); if (!entry || !entry.intent) return null; const intent = entry.intent; entry.intent = null; writeDrafts(entry); return intent; },
    pending() { return !!readDrafts(); },
    clear: clearDrafts
  });
  const panel = document.createElement("section"); panel.className = "card"; panel.id="agent-access"; panel.hidden = true;
  const title = document.createElement("h2"); title.textContent = "Agent access";
  const description = document.createElement("p"); description.textContent = "Use a named agent credential. Its permissions remain separate from human administration.";
  const form = document.createElement("form"), label = document.createElement("label"), input = document.createElement("input"), button = document.createElement("button");
  input.id = "agent-credential"; input.type = "password"; input.autocomplete = "off"; input.required = true; input.spellcheck = false;
  label.htmlFor = input.id; label.textContent = "Agent credential"; button.textContent = "Sign in as agent"; button.className = "primary";
  const note = document.createElement("p"); note.role = "status"; note.setAttribute("aria-live", "polite");
  const identity = document.createElement("p"); identity.id = "agent-identity"; identity.hidden = true;
  const logout = document.createElement("button"); logout.id = "agent-logout"; logout.type = "button"; logout.textContent = "Sign out agent"; logout.hidden = true;
  form.append(label,input,button); panel.append(title,description,form,note); const login=document.getElementById("login");if(login)login.before(panel);else document.querySelector("main")?.prepend(panel);
  const warning=document.createElement("p");warning.id="auth-session-warning";warning.role="status";warning.setAttribute("aria-live","polite");
  document.querySelector("header")?.append(identity,logout,warning);
  const fire = name => window.dispatchEvent(new Event(name));
  const localClear = () => { epoch++; actor = null; csrf = ""; input.value = ""; identity.textContent = ""; identity.hidden = logout.hidden = true; form.hidden = false;panel.hidden=!allowedOrigin||ssoMode; clearTimeout(timer);clearTimeout(warningTimer);warning.textContent=""; };
  async function api(path, options = {}) {
    const controller = new AbortController(), timeout = setTimeout(() => controller.abort(), 10000);
    try {
      const response = await fetch(new URL("auth/"+path,base), {...options, signal:controller.signal, credentials:options.credentials || "same-origin", cache:"no-store", redirect:"error"});
      if (!response.ok) { void response.body?.cancel(); const error=new Error(response.status===401?"Sign-in expired or rejected.":"Agent access is unavailable or not permitted.");error.status=response.status;throw error; }
      const reader=response.body.getReader();let bytes=0,parts=[];
      for (;;) {const {value,done}=await reader.read();if(done)break;bytes+=value.length;if(bytes>16384){await reader.cancel();throw new Error("Unexpected authentication response.");}parts.push(value);}
      const all=new Uint8Array(bytes);let at=0;for(const part of parts){all.set(part,at);at+=part.length;}try{return JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(all));}catch{throw new Error("Unexpected authentication response.");}
    } finally {clearTimeout(timeout);}
  }
  function accept(data) {
    if(!Number.isFinite(Date.parse(data.expires_at))||!Number.isFinite(Date.parse(data.idle_expires_at))||data.record_role!=="writable_authority"||!["agent","human"].includes(data.principal_type)||typeof data.csrf!=="string"||!Array.isArray(data.scopes)||!data.scopes.includes("ui:view"))throw new Error("Unexpected authentication response.");
    actor=data;csrf=data.csrf;ended=null;panel.hidden=true;logout.textContent=data.principal_type==="human"?"Sign out":"Sign out agent";form.hidden=true;identity.hidden=logout.hidden=false;
    identity.textContent=`${data.principal_type==="human"?"Human":"Agent"} · ${data.display_name} · realm ${data.realm_id} · node ${data.node_id} · ${data.scopes.includes("records:write")?"Edit access":"Read-only access"} | ${data.scopes.join(" · ")} · expires ${new Date(Math.min(Date.parse(data.expires_at),Date.parse(data.idle_expires_at))).toISOString()}`;
    clearTimeout(timer);const remaining=Math.min(Date.parse(data.expires_at),Date.parse(data.idle_expires_at))-Date.now();
    clearTimeout(warningTimer);warning.textContent="";if(data.principal_type==="human")warningTimer=setTimeout(()=>{warning.textContent="Your session expires in two minutes. Continue working or sign in again; local drafts are preserved.";},Math.max(0,remaining-120000));
    timer=setTimeout(()=>{localClear();ended={reason:"expired",at:Date.now()};note.textContent="Session expired. Sign in again; local work is preserved.";fire("agentexpired");},Math.max(0,remaining));
  }
  window.secDNSAgent={
    get state(){return publicState;},
    get active(){return actor!==null;},
    get kind(){return actor?.principal_type || "";},
    acceptSession(data){if(!allowedOrigin)throw new Error("Secure origin required.");accept(data);fire("agentconnected");},
    get name(){return actor?.display_name || "";},
    // When this session last verified the owner (a fresh WithMy ID sign-in), as epoch ms; 0 if unknown.
    get authenticatedAt(){const t=Date.parse(actor?.authenticated_at||"");return Number.isFinite(t)?t:0;},
    get sso(){return actor?.sso===true;},
    get ended(){return ended;},
    get leaving(){return leaving;},
    drafts,
    get role(){return actor?.scopes.includes("records:write")?(actor.principal_type==="human"?"Administrator":"Agent - edit access"):"Read-only agent";},
    allows(scope){return !actor || (actor.scopes.includes(scope)&&(scope!=="records:write"||actor.record_role==="writable_authority"));},
    headers(token,method){return actor ? (method==="GET"?{}:{"X-SecDNS-CSRF":csrf,"Content-Type":"application/json"}) : {Authorization:"Bearer "+token,"X-SecDNS-Legacy-Access":"1"};},
    credentials(){return actor?"same-origin":"omit";},
    clear:localClear,
    expire(){if(actor){localClear();ended={reason:"ended",at:Date.now()};note.textContent="Session expired. Sign in again; local work is preserved.";fire("agentexpired");}},
    async switchToLegacy(){
      clearDrafts();
      if(allowedOrigin){
        let current=null;try{current=await api("session");}catch(error){if(error.status!==401)throw error;}
        if(current)await api("logout",{method:"POST",headers:{"Content-Type":"application/json","X-SecDNS-CSRF":current.csrf}});
      }
      localClear();fire("agentexpired");
    },
    // A session issued through single sign-on also ends the edge/identity-provider session afterwards,
    // whether or not the console logout succeeded. Only the one fixed same-origin path is ever followed.
    async logout(){const value=csrf,sso=actor?.sso===true&&actor?.sign_out_url==="/oauth2/sign_out?rd=%2F";localClear();clearDrafts();ended={reason:"signed_out",at:Date.now()};try{await api("logout",{method:"POST",headers:{"Content-Type":"application/json","X-SecDNS-CSRF":value}});}finally{fire("agentexpired");if(sso)location.assign("/oauth2/sign_out?rd=%2F");}},
    // Step-up: a fresh WithMy ID sign-in that comes back to this page. Unsaved work (and the
    // refused action, as an intent replayed once on return) is kept first; then this console
    // session ends and the edge signs out, returning to this page, where WithMy ID asks the
    // owner to sign in again. Freshness stays server-enforced (auth_time within 5 minutes).
    async stepUp(intent=null){
      if(!actor||actor.sso!==true||actor.sign_out_url!=="/oauth2/sign_out?rd=%2F")throw new Error("Confirming with WithMy ID is unavailable here.");
      if(!await drafts.preserve(intent))throw new Error("Your unsaved changes are too large to keep while you confirm. Apply or discard them first.");
      const value=csrf,destination="/oauth2/sign_out?rd="+encodeURIComponent(returnPath());leaving=true;localClear();
      try{await api("logout",{method:"POST",headers:{"Content-Type":"application/json","X-SecDNS-CSRF":value}});}catch{/* the edge sign-out below still ends the session */}finally{location.assign(destination);}
    },
    // Signing in again after the console session ended: keep unsaved work, then load this
    // page again through the edge (which returns here after any WithMy ID sign-in).
    async signInAgain(){await drafts.preserve(null);leaving=true;location.assign(returnPath());},
    // After the sign-in service refused a new session (all session slots in use), try the
    // exchange again in place; nothing is reloaded and local work stays in the page.
    async retrySSO(){if(actor||!publicState||publicState.sso_login!==true)return false;const captured=epoch;try{const data=await api("login/sso",{method:"POST",headers:{"Content-Type":"application/json"},body:"{}"});if(captured!==epoch)return false;accept(data);note.textContent="Signed in with single sign-on.";fire("agentconnected");return true;}catch(error){if(captured===epoch){ended={reason:error.status===503?"busy":"ended",at:Date.now()};fire("authended");}return false;}},
  };
  form.addEventListener("submit",async event=>{
    event.preventDefault();if(!allowedOrigin){input.value="";note.textContent="Agent sign-in requires the configured HTTPS origin.";return;}let credential=input.value;input.value="";if(!credential)return;button.disabled=true;const captured=++epoch;
    try {
      // Resolve an expired cookie before exchange. Switching an existing session
      // is explicit: sign out that session before presenting the new credential.
      let previous=null;try{previous=await api("session");}catch{}
      if(captured!==epoch)return;
      if(previous)await api("logout",{method:"POST",headers:{"Content-Type":"application/json","X-SecDNS-CSRF":previous.csrf}});
      if(captured!==epoch)return;
      const data=await api("agent-session",{method:"POST",credentials:"same-origin",headers:{Authorization:"Bearer "+credential,"Content-Type":"application/json"}});credential="";if(captured!==epoch)return;accept(data);note.textContent=data.scopes.includes("records:read")&&!data.scopes.includes("records:write")?"Read-only record access: this agent cannot submit record changes.":"Signed in with the displayed agent permissions.";fire("agentconnected");}
    catch(error){credential="";if(captured===epoch){note.textContent=error.message;actor=null;csrf="";}}
    finally{credential="";button.disabled=false;}
  });
  logout.addEventListener("click",()=>window.secDNSAgent.logout().catch(error=>{note.textContent=error.message;}));
  // Explicit user activity only; no polling keeps an idle session alive.
  let lastActivity=0;
  const activity=()=>{if(!actor||Date.now()-lastActivity<60000)return;lastActivity=Date.now();const captured=epoch;api("activity",{method:"POST",headers:{"Content-Type":"application/json","X-SecDNS-CSRF":csrf}}).then(()=>api("session")).then(data=>{if(captured===epoch)accept(data);}).catch(()=>{if(captured===epoch){localClear();ended={reason:"ended",at:Date.now()};fire("agentexpired");}});};
  window.addEventListener("pointerdown",activity);window.addEventListener("keydown",activity);
  window.addEventListener("pagehide",localClear);
  const initialEpoch=epoch;
  // Same-origin credentials: behind the single sign-on edge, an anonymous state
  // request is redirected to sign-in. The response never contains credentials.
  // With a valid edge assertion and no console session, exchange it once for the
  // owner's normal session; otherwise the console's own sign-in stays available.
  const ssoLogin=()=>api("login/sso",{method:"POST",headers:{"Content-Type":"application/json"},body:"{}"}).then(data=>{if(initialEpoch!==epoch)return;accept(data);note.textContent="Signed in with single sign-on.";fire("agentconnected");},error=>{if(initialEpoch===epoch&&error.status===503){ended={reason:"busy",at:Date.now()};fire("authended");}throw error;});
  api("state",{credentials:"same-origin"}).then(state=>{publicState=state;window.dispatchEvent(new CustomEvent("authstate",{detail:state}));allowedOrigin=state.agent_access===true&&typeof state.public_origin==="string"&&location.origin===state.public_origin;ssoMode=state.sso_login===true;panel.hidden=!allowedOrigin||ssoMode;if(allowedOrigin&&initialEpoch===epoch)return api("session").then(data=>{if(initialEpoch!==epoch)return;accept(data);fire("agentconnected");}).catch(error=>{if(error.status===401&&state.sso_login===true&&state.human_access===true&&initialEpoch===epoch)return ssoLogin();}).catch(()=>{});}).catch(()=>{});
})();

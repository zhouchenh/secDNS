(() => {
  "use strict";
  const script = new URL(document.currentScript.src);
  const base = new URL("../", script);
  let allowedOrigin=false;
  let actor = null, csrf = "", epoch = 0, timer = null;
  const panel = document.createElement("section"); panel.className = "card"; panel.hidden = true;
  const title = document.createElement("h2"); title.textContent = "Agent access";
  const description = document.createElement("p"); description.textContent = "Use a named agent credential. Its permissions remain separate from human administration.";
  const form = document.createElement("form"), label = document.createElement("label"), input = document.createElement("input"), button = document.createElement("button");
  input.id = "agent-credential"; input.type = "password"; input.autocomplete = "off"; input.required = true; input.spellcheck = false;
  label.htmlFor = input.id; label.textContent = "Agent credential"; button.textContent = "Sign in as agent"; button.className = "primary";
  const note = document.createElement("p"); note.role = "status"; note.setAttribute("aria-live", "polite");
  const identity = document.createElement("p"); identity.id = "agent-identity"; identity.hidden = true;
  const logout = document.createElement("button"); logout.type = "button"; logout.textContent = "Sign out agent"; logout.hidden = true;
  form.append(label,input,button); panel.append(title,description,form,note); const login=document.getElementById("login");if(login)login.before(panel);else document.querySelector("main")?.prepend(panel);
  document.querySelector("header")?.append(identity,logout);
  const fire = name => window.dispatchEvent(new Event(name));
  const localClear = () => { epoch++; actor = null; csrf = ""; input.value = ""; identity.textContent = ""; identity.hidden = logout.hidden = true; form.hidden = false; clearTimeout(timer); };
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
    if(!Number.isFinite(Date.parse(data.expires_at))||!Number.isFinite(Date.parse(data.idle_expires_at))||data.record_role!=="writable_authority"||data.principal_type!=="agent"||typeof data.csrf!=="string"||!Array.isArray(data.scopes)||!data.scopes.includes("ui:view"))throw new Error("Unexpected authentication response.");
    actor=data;csrf=data.csrf;form.hidden=true;identity.hidden=logout.hidden=false;
    identity.textContent=`Agent · ${data.display_name} · realm ${data.realm_id} · node ${data.node_id} · Writable authority | ${data.scopes.join(" · ")} · expires ${new Date(Math.min(Date.parse(data.expires_at),Date.parse(data.idle_expires_at))).toISOString()}`;
    clearTimeout(timer);const remaining=Math.min(Date.parse(data.expires_at),Date.parse(data.idle_expires_at))-Date.now();
    timer=setTimeout(()=>{localClear();note.textContent="Session expired. Sign in again; local work is preserved.";fire("agentexpired");},Math.max(0,remaining));
  }
  window.secDNSAgent={
    get active(){return actor!==null;},
    get name(){return actor?.display_name || "";},
    allows(scope){return !actor || (actor.scopes.includes(scope)&&(scope!=="records:write"||actor.record_role==="writable_authority"));},
    headers(token,method){return actor ? (method==="GET"?{}:{"X-SecDNS-CSRF":csrf,"Content-Type":"application/json"}) : {Authorization:"Bearer "+token,"X-SecDNS-Legacy-Access":"1"};},
    credentials(){return actor?"same-origin":"omit";},
    clear:localClear,
    async switchToLegacy(){
      if(allowedOrigin){
        let current=null;try{current=await api("session");}catch(error){if(error.status!==401)throw error;}
        if(current)await api("logout",{method:"POST",headers:{"Content-Type":"application/json","X-SecDNS-CSRF":current.csrf}});
      }
      localClear();fire("agentexpired");
    },
    async logout(){const value=csrf;localClear();try{await api("logout",{method:"POST",headers:{"Content-Type":"application/json","X-SecDNS-CSRF":value}});}finally{fire("agentexpired");}}
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
  const activity=()=>{if(!actor||Date.now()-lastActivity<60000)return;lastActivity=Date.now();const captured=epoch;api("activity",{method:"POST",headers:{"Content-Type":"application/json","X-SecDNS-CSRF":csrf}}).then(()=>api("session")).then(data=>{if(captured===epoch)accept(data);}).catch(()=>{if(captured===epoch){localClear();fire("agentexpired");}});};
  window.addEventListener("pointerdown",activity);window.addEventListener("keydown",activity);
  window.addEventListener("pagehide",localClear);
  const initialEpoch=epoch;
  api("state",{credentials:"omit"}).then(state=>{allowedOrigin=state.agent_access===true&&typeof state.public_origin==="string"&&location.origin===state.public_origin;panel.hidden=!allowedOrigin;if(allowedOrigin&&initialEpoch===epoch)return api("session").then(data=>{if(initialEpoch!==epoch)return;accept(data);fire("agentconnected");}).catch(()=>{});}).catch(()=>{});
})();

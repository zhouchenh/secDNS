(() => {
  "use strict";
  const base=new URL("../",document.currentScript.src);
  let origin="",challenge="",step="start",replacement=false,busy=false,epoch=0,humanWasActive=false;
  const card=document.createElement("section");card.className="card";card.hidden=true;card.id="human-access";
  const title=document.createElement("h2");title.textContent="Sign in to secDNS";
  const help=document.createElement("p");help.textContent="Use your owner account and authenticator. Agent access remains separate below. Sessions end when secDNS restarts; sign in again.";
  const form=document.createElement("form"),mode=document.createElement("select");mode.id="human-mode";
  for(const [value,text] of [["login","Sign in"],["setup","Set up owner"],["code","Recover with saved code"],["local","Recover with local grant"]]){const o=document.createElement("option");o.value=value;o.textContent=text;mode.append(o);}
  const modeLabel=document.createElement("label");modeLabel.htmlFor=mode.id;modeLabel.textContent="Account action";form.append(modeLabel,mode);
  const fields={};
  for(const [name,text,type,autocomplete] of [["username","Username","text","username"],["name","Display name","text","name"],["password","Password","password","current-password"],["grant","One-use local grant","password","off"],["recovery","Saved recovery code","password","off"],["code","Authenticator code","text","one-time-code"]]){
    const wrap=document.createElement("div"),label=document.createElement("label"),input=document.createElement("input");input.id="human-"+name;input.type=type;input.autocomplete=autocomplete;label.htmlFor=input.id;label.textContent=text;input.maxLength=name==="password"?1024:128;if(name==="code"){input.inputMode="numeric";input.maxLength=6;input.pattern="[0-9]{6}";}wrap.append(label,input);form.append(wrap);fields[name]={wrap,input};
  }
  const seed=document.createElement("p");seed.id="human-seed";seed.hidden=true;
  const submit=document.createElement("button");submit.type="submit";submit.className="primary";submit.textContent="Continue";
  const cancel=document.createElement("button");cancel.type="button";cancel.textContent="Cancel";
  const note=document.createElement("p");note.role="status";note.setAttribute("aria-live","polite");
  const recovery=document.createElement("textarea");recovery.id="human-recovery-codes";recovery.readOnly=true;recovery.hidden=true;recovery.setAttribute("aria-label","Save these recovery codes once");
  const dismiss=document.createElement("button");dismiss.type="button";dismiss.textContent="I saved my recovery codes";dismiss.hidden=true;
  form.append(seed,submit,cancel);card.append(title,help,form,note,recovery,dismiss);document.querySelector("main")?.prepend(card);
  function reset(){epoch++;challenge="";step="start";replacement=false;seed.textContent="";seed.hidden=true;for(const v of Object.values(fields))v.input.value="";recovery.value="";recovery.hidden=dismiss.hidden=true;download.hidden=true;render();}
  function render(){const initial=step==="start";mode.disabled=!initial||busy;for(const [name,v] of Object.entries(fields)){const visible=name==="code"?!initial:name==="username"||name==="password"?initial:name==="name"||name==="grant"?initial&&["setup","local"].includes(mode.value):initial&&mode.value==="code";v.wrap.hidden=!visible;v.input.required=visible;v.input.disabled=!visible||busy;}fields.password.input.autocomplete=["setup","local"].includes(mode.value)?"new-password":"current-password";submit.disabled=busy;submit.textContent=initial?"Continue":"Verify authenticator";}
  async function request(path,body,authenticated=false){if(location.origin!==origin)throw new Error("Use the configured HTTPS portal.");const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),20000);try{const r=await fetch(new URL("auth/"+path,base),{method:body?"POST":"GET",headers:body?{...(authenticated?window.secDNSAgent.headers("","POST"):{}),"Content-Type":"application/json"}:{},body:body?JSON.stringify(body):undefined,credentials:"same-origin",cache:"no-store",redirect:"error",signal:controller.signal});if(!r.ok){void r.body?.cancel();throw new Error("Sign-in could not be completed. Check your details or wait before trying again.");}const reader=r.body.getReader();let bytes=0,parts=[];for(;;){const {done,value}=await reader.read();if(done)break;bytes+=value.length;if(bytes>16384){await reader.cancel();throw new Error("Unexpected authentication response.");}parts.push(value);}const data=new Uint8Array(bytes);let at=0;for(const p of parts){data.set(p,at);at+=p.length;}try{return JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(data));}catch{throw new Error("Unexpected authentication response.");}}finally{clearTimeout(timer);}}
  mode.addEventListener("change",reset);cancel.addEventListener("click",()=>{reset();note.textContent="Cancelled. Existing authentication methods are unchanged unless confirmation already completed.";});dismiss.addEventListener("click",()=>{recovery.value="";recovery.hidden=dismiss.hidden=true;note.textContent="Signed in. Keep your saved recovery codes private.";});
  form.addEventListener("submit",async e=>{e.preventDefault();if(busy||location.origin!==origin)return;busy=true;render();const captured=epoch;let body={};try{
    if(step==="start"){
      await window.secDNSAgent.switchToLegacy();
      body={username:fields.username.input.value.trim(),password:fields.password.input.value};fields.password.input.value="";
      let path="login/password";if(mode.value==="setup"||mode.value==="local"){path=mode.value==="setup"?"setup/begin":"recovery/local";body.name=fields.name.input.value.trim();body.grant=fields.grant.input.value;fields.grant.input.value="";}else if(mode.value==="code"){path="recovery/code";body.code=fields.recovery.input.value;fields.recovery.input.value="";}
      const result=await request(path,body);body={};if(captured!==epoch)return;if(typeof result.challenge!=="string"||result.challenge.length!==102||(result.secret!==undefined&&!/^[A-Z2-7]{32}$/.test(result.secret)))throw new Error("Unexpected authentication response.");challenge=result.challenge;step="otp";
      if(result.secret){seed.textContent="Add this key to your authenticator: "+result.secret;seed.hidden=false;note.textContent="Confirm a current code to activate the new authenticator. Existing methods remain active until confirmation.";}else note.textContent="Enter a current authenticator code. Password alone does not sign you in.";
      render();fields.code.input.focus();
    }else{
      body={challenge,code:fields.code.input.value};fields.code.input.value="";const result=await request(replacement?"totp/confirm":"login/totp",body,replacement);body={};if(captured!==epoch)return;challenge="";seed.textContent="";seed.hidden=true;window.secDNSAgent.acceptSession(result);step="start";
      if(Array.isArray(result.recovery_codes)){recovery.value=result.recovery_codes.join("\n");recovery.hidden=dismiss.hidden=false;note.textContent="Save all ten recovery codes now. Each works once and will not be shown again.";}else note.textContent="Signed in as human owner.";
    }
  }catch(error){body={};if(captured===epoch)note.textContent=error.message;}finally{body={};busy=false;render();}});
  const security=document.createElement("section");security.hidden=true;security.id="human-security";
  const securityTitle=document.createElement("h3");securityTitle.textContent="Account security";
  const recent=document.createElement("p");recent.textContent="Sensitive changes require password and authenticator verification within the last five minutes. Use a new authenticator code; accepted codes cannot be reused.";
  const currentPassword=document.createElement("input");currentPassword.type="password";currentPassword.autocomplete="current-password";currentPassword.id="human-reauth-password";
  const currentLabel=document.createElement("label");currentLabel.htmlFor=currentPassword.id;currentLabel.textContent="Current password";
  const currentCode=document.createElement("input");currentCode.inputMode="numeric";currentCode.autocomplete="one-time-code";currentCode.maxLength=6;currentCode.id="human-reauth-code";
  const codeLabel=document.createElement("label");codeLabel.htmlFor=currentCode.id;codeLabel.textContent="Current authenticator code";
  const newPassword=document.createElement("input");newPassword.type="password";newPassword.autocomplete="new-password";newPassword.id="human-new-password";
  const newLabel=document.createElement("label");newLabel.htmlFor=newPassword.id;newLabel.textContent="New password (15-256 characters)";
  security.append(securityTitle,recent,currentLabel,currentPassword,codeLabel,currentCode,newLabel,newPassword);
  for(const [text,path,kind] of [["Verify identity","reauth/password-totp","reauth"],["Change password","password","password"],["Replace authenticator","totp/begin","totp"],["Replace recovery codes","recovery-codes/regenerate","codes"],["Sign out other human sessions","sessions/revoke-others","sessions"]]){
    const b=document.createElement("button");b.type="button";b.textContent=text;security.append(b);
    b.addEventListener("click",async()=>{if(busy||window.secDNSAgent.kind!=="human")return;busy=true;b.disabled=true;const captured=epoch;let body={};try{if(kind==="reauth"){body={password:currentPassword.value,code:currentCode.value};currentPassword.value=currentCode.value="";}else if(kind==="password"){body={password:newPassword.value};newPassword.value="";}const result=await request(path,body,true);body={};if(captured!==epoch||window.secDNSAgent.kind!=="human")return;if(kind==="totp"){replacement=true;challenge=result.challenge;step="otp";seed.textContent="Add this key to your authenticator: "+result.secret;seed.hidden=false;form.hidden=false;render();}if(result.principal_type)window.secDNSAgent.acceptSession(result);if(result.recovery_codes){recovery.value=result.recovery_codes.join("\n");recovery.hidden=dismiss.hidden=false;note.textContent="Previous recovery codes are invalid. Save these new codes now.";}else note.textContent="Security action completed.";}catch(error){body={};if(captured===epoch&&window.secDNSAgent.kind==="human")note.textContent=error.message;}finally{busy=false;b.disabled=false;if(window.secDNSAgent.kind!=="human")reset();}});
  }
  const auditButton=document.createElement("button");auditButton.type="button";auditButton.textContent="View recent security events";const audit=document.createElement("pre");audit.hidden=true;audit.id="human-audit";security.append(auditButton,audit);
  auditButton.addEventListener("click",async()=>{if(busy||window.secDNSAgent.kind!=="human")return;const captured=epoch;try{const result=await request("audit",undefined,true);if(captured!==epoch||window.secDNSAgent.kind!=="human")return;audit.textContent=result.events.map(e=>e.At+" "+e.Action).join("\n");audit.hidden=false;}catch(error){note.textContent=error.message;}});
  const download=document.createElement("button");download.type="button";download.textContent="Download recovery codes";download.hidden=true;card.insertBefore(download,dismiss);
  download.addEventListener("click",()=>{if(!recovery.value)return;const blob=new Blob([recovery.value+"\n"],{type:"text/plain"});const u=URL.createObjectURL(blob),a=document.createElement("a");a.href=u;a.download="secdns-recovery-codes.txt";a.click();setTimeout(()=>URL.revokeObjectURL(u),0);});
  const codesVisibility=new MutationObserver(()=>{download.hidden=recovery.hidden;});codesVisibility.observe(recovery,{attributes:true,attributeFilter:["hidden"]});
  card.append(security);
  const sessionChanged=()=>{const human=window.secDNSAgent?.kind==="human";if(humanWasActive&&!human)reset();humanWasActive=human;security.hidden=!human;audit.textContent="";audit.hidden=true;form.hidden=!security.hidden;title.textContent=security.hidden?"Sign in to secDNS":"Human account";currentPassword.value=currentCode.value=newPassword.value="";};
  window.addEventListener("agentconnected",sessionChanged);window.addEventListener("agentexpired",()=>{sessionChanged();if(!busy)reset();});
  window.addEventListener("pagehide",reset);
  const applyState=state=>{if(state?.human_access===true&&typeof state.public_origin==="string"&&location.origin===state.public_origin){origin=state.public_origin;card.hidden=false;mode.value=state.setup_required?"setup":"login";render();}};
  window.addEventListener("authstate",event=>applyState(event.detail));if(window.secDNSAgent.state)applyState(window.secDNSAgent.state);
})();

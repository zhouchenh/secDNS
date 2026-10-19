(() => {
 "use strict";
 const header=document.querySelector("body>header"), main=document.querySelector("main");
 if(!header||!main)return;
 const context=document.createElement("div");context.className="console-context";
 const label=document.createElement("strong");label.textContent="This instance";
 context.append(label,document.createTextNode(" · "+location.host));header.prepend(context);
 // Reuse existing authentication UI and its handlers; never recreate credentials or sessions.
 window.addEventListener("beforeunload",event=>{if(document.body.dataset.consolePage==="import"&&(document.getElementById("source")?.value||document.getElementById("file")?.files?.length)){event.preventDefault();event.returnValue="";}});
 const importLink=document.querySelector('.console-sidebar a[href$="/ui/import-preview/"]'), handoff=document.getElementById("open-import");
 if(importLink&&handoff){importLink.title="Open import review in a separate page; keep this draft";importLink.addEventListener("click",event=>{event.preventDefault();handoff.click();});}
 const account=document.getElementById("console-account"),human=document.getElementById("human-access"),agent=document.getElementById("agent-access"),passkeys=document.getElementById("passkey-access");
 if(!human||!agent)return;
 const originalTitle=document.title;
 const screen=document.createElement("section");screen.id="console-auth-screen";screen.setAttribute("role","main");screen.hidden=true;
 const brand=document.createElement("div");brand.className="auth-brand";brand.textContent="secDNS";
 const surface=document.createElement("div");surface.className="auth-surface";
 const agentToggle=document.createElement("button");agentToggle.type="button";agentToggle.className="auth-secondary";agentToggle.textContent="Agent access";
 const returnButton=document.createElement("button");returnButton.type="button";returnButton.className="auth-return";returnButton.textContent="Back to DNS records";
 const signout=document.createElement("button");signout.type="button";signout.className="auth-secondary";signout.textContent="Sign out";signout.addEventListener("click",()=>window.secDNSAgent.logout().catch(()=>{}));
 screen.append(brand,surface,agentToggle,returnButton,signout);surface.append(human,agent);if(passkeys)surface.append(passkeys);document.body.append(screen);
 let accountOpen=false,agentOpen=false;
 const display=()=>{
  const state=window.secDNSAgent?.state;
  const humanEnabled=state?.human_access===true&&!human.hidden;
  const enabled=state?.agent_access===true&&state.public_origin===location.origin;
  if(!humanEnabled){
   for(const node of [human,agent,passkeys])if(node&&node.parentElement===surface)main.prepend(node);
   screen.hidden=true;document.body.classList.remove("auth-screen-open");document.title=originalTitle;return;
  }
  for(const node of [human,agent,passkeys])if(node&&node.parentElement!==surface)surface.append(node);
  const active=window.secDNSAgent?.active;
  const ceremony=!!human.querySelector('#human-recovery-codes:not([hidden]),#human-qr:not([hidden])');
  const show=enabled&&(!active||accountOpen||ceremony);
  document.title=show?(active?"Account security":agentOpen?"Agent access":"Sign in")+" - secDNS":originalTitle;
  screen.hidden=!show;document.body.classList.toggle("auth-screen-open",show);
  screen.dataset.access=agentOpen?"agent":"human";
  agentToggle.hidden=!!active||!humanEnabled;agentToggle.textContent=agentOpen?"Back to human sign in":"Agent access";
  returnButton.hidden=!active||ceremony;signout.hidden=!active||ceremony;
  if(account)account.textContent=window.secDNSAgent?.kind==="human"?"Account security":"Sign in";
 };
 agentToggle.addEventListener("click",()=>{agentOpen=!agentOpen;display();(agentOpen?document.getElementById("agent-credential"):document.getElementById("human-username"))?.focus();});
 returnButton.addEventListener("click",()=>{accountOpen=false;display();account?.focus();});
 account?.addEventListener("click",()=>{accountOpen=true;agentOpen=window.secDNSAgent?.kind==="agent";display();const title=human.querySelector("h2");title?.setAttribute("tabindex","-1");title?.focus();});
 window.addEventListener("agentconnected",()=>{agentOpen=false;display();});
 window.addEventListener("agentexpired",()=>{accountOpen=false;agentOpen=false;display();});
 window.addEventListener("authstate",display);window.addEventListener("humanflowchange",display);
 display();
})();

(() => {
 "use strict";
 const header=document.querySelector("body>header"), main=document.querySelector("main");
 if(!header||!main)return;
 const context=document.createElement("div");context.className="console-context";
 const label=document.createElement("strong");label.textContent="DNS administration";
 context.append(label,document.createTextNode(" · "+location.host));header.prepend(context);
 // Reuse existing authentication UI and its handlers; never recreate credentials or sessions.
 window.addEventListener("beforeunload",event=>{if(document.body.dataset.consolePage==="import"&&(document.getElementById("source")?.value||document.getElementById("file")?.files?.length)){event.preventDefault();event.returnValue="";}});
 const importLink=document.querySelector('.console-sidebar a[href$="/ui/import-preview/"]'), handoff=document.getElementById("open-import");
 if(importLink&&handoff){importLink.title="Open import review in a separate page; keep this draft";importLink.addEventListener("click",event=>{event.preventDefault();handoff.click();});}
 const account=document.getElementById("console-account"),human=document.getElementById("human-access"),agent=document.getElementById("agent-access"),passkeys=document.getElementById("passkey-access");
 if(!human||!agent)return;
 const identity=document.getElementById("agent-identity"),logout=[...header.querySelectorAll("button")].find(b=>b.textContent.startsWith("Sign out"));
 const sessionDetails=document.createElement("details");sessionDetails.id="session-details";const detailsTitle=document.createElement("summary");detailsTitle.textContent="Advanced session details";sessionDetails.append(detailsTitle);if(identity)sessionDetails.append(identity);
 const accountMenu=document.createElement("details");accountMenu.className="account-menu";accountMenu.id="account-menu";accountMenu.hidden=true;
 const accountSummary=document.createElement("summary");accountSummary.id="account-summary";
 const accountName=document.createElement("strong"),accountRole=document.createElement("span");accountSummary.append(accountName,accountRole);
 const menuPanel=document.createElement("div");menuPanel.className="account-menu-panel";
 const securityButton=document.createElement("button");securityButton.type="button";securityButton.textContent="Account settings";
 securityButton.addEventListener("click",()=>{accountMenu.open=false;account?.click();});menuPanel.append(securityButton);if(logout)menuPanel.append(logout);accountMenu.append(accountSummary,menuPanel);header.append(accountMenu);
 accountMenu.addEventListener("keydown",e=>{if(e.key==="Escape"){accountMenu.open=false;accountSummary.focus();}});
 document.addEventListener("click",e=>{if(!accountMenu.contains(e.target))accountMenu.open=false;});
 const sessionUI=()=>{const active=window.secDNSAgent?.active;accountMenu.hidden=!active;accountName.textContent=window.secDNSAgent?.name||"Account";accountRole.textContent=window.secDNSAgent?.role||"";const parent=window.secDNSAgent?.kind==="human"?document.getElementById("human-security"):agent;if(parent&&sessionDetails.parentElement!==parent)parent.append(sessionDetails);if(!active){accountMenu.open=false;sessionDetails.open=false;}};
 window.addEventListener("agentconnected",sessionUI);window.addEventListener("agentexpired",sessionUI);sessionUI();

 const originalTitle=document.title;
 const screen=document.createElement("section");screen.id="console-auth-screen";screen.setAttribute("role","main");screen.hidden=true;
 const brand=document.createElement("div");brand.className="auth-brand";brand.textContent="secDNS";
 const surface=document.createElement("div");surface.className="auth-surface";
 const agentToggle=document.createElement("button");agentToggle.type="button";agentToggle.className="auth-secondary";agentToggle.textContent="Agent access";
 const returnButton=document.createElement("button");returnButton.type="button";returnButton.className="auth-return";returnButton.textContent="Back to "+({records:"DNS records",import:"import",followers:"replication status"}[document.body.dataset.consolePage]||"workspace");
 const signout=document.createElement("button");signout.type="button";signout.className="auth-secondary";signout.textContent="Sign out";signout.addEventListener("click",()=>window.secDNSAgent.logout().catch(()=>{}));
 screen.append(brand,surface,agentToggle,returnButton,signout);surface.append(human,agent);if(passkeys)surface.append(passkeys);document.body.append(screen);
 const selectedNav=document.querySelector(".console-sidebar a[aria-current]");
 let accountOpen=false,agentOpen=false;
 const display=()=>{
  const state=window.secDNSAgent?.state;
  const humanEnabled=state?.human_access===true&&!human.hidden;
  const enabled=state?.agent_access===true&&state.public_origin===location.origin;
  if(!humanEnabled){
   for(const node of [human,agent,passkeys])if(node&&node.parentElement===surface)main.prepend(node);
   screen.hidden=true;document.body.classList.remove("auth-screen-open","account-screen-open");document.title=originalTitle;label.textContent="DNS administration";return;
  }
  for(const node of [human,agent,passkeys])if(node&&node.parentElement!==surface)surface.append(node);
  const active=window.secDNSAgent?.active;
  const ceremony=!!human.querySelector('#human-recovery-codes:not([hidden]),#human-qr:not([hidden])');
  const show=enabled&&(!active||accountOpen||ceremony);
  document.title=show?(active?"Account security":agentOpen?"Agent access":"Sign in")+" - secDNS":originalTitle;
  if(account){if(show&&active){account.setAttribute("aria-current","page");selectedNav?.removeAttribute("aria-current");}else{account.removeAttribute("aria-current");selectedNav?.setAttribute("aria-current","page");}}
  label.textContent=show&&active?"Account security":"DNS administration";
  screen.hidden=!show;document.body.classList.toggle("auth-screen-open",show&&!active);document.body.classList.toggle("account-screen-open",show&&!!active);
  screen.dataset.access=agentOpen?"agent":"human";
  agentToggle.hidden=!!active||!humanEnabled;agentToggle.textContent=agentOpen?"Back to human sign in":"Agent access";
  returnButton.hidden=!active||ceremony;signout.hidden=true;
  if(account)account.textContent=window.secDNSAgent?.kind==="human"?"Account security":"Sign in";
 };
 agentToggle.addEventListener("click",()=>{agentOpen=!agentOpen;display();(agentOpen?document.getElementById("agent-credential"):document.getElementById("human-username"))?.focus();});
 returnButton.addEventListener("click",()=>{accountOpen=false;display();account?.focus();});
 account?.addEventListener("click",()=>{accountOpen=true;agentOpen=window.secDNSAgent?.kind==="agent";if(agentOpen)agent.hidden=false;display();const title=(agentOpen?agent:human).querySelector("h2");window.scrollTo(0,0);title?.setAttribute("tabindex","-1");title?.focus({preventScroll:true});});
 window.addEventListener("agentconnected",()=>{agentOpen=false;display();});
 window.addEventListener("agentexpired",()=>{accountOpen=false;agentOpen=false;display();});
 window.addEventListener("authstate",display);window.addEventListener("humanflowchange",display);
 display();
})();

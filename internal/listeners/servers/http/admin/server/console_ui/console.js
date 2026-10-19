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
 const account=document.getElementById("console-account");
 if(account){
  const access=document.createElement("details");access.className="console-access";access.id="console-access";
  const summary=document.createElement("summary");summary.textContent="Sign in & account security";access.append(summary);
  const cards=[...main.querySelectorAll(":scope > section")].filter(el=>el.id==="human-access"||el.id==="login"||el.querySelector("h2")?.textContent==="Agent access");
  if(cards.length){main.prepend(access);for(const card of cards)access.append(card);access.open=!window.secDNSAgent?.active;
   account.addEventListener("click",()=>{access.open=true;access.scrollIntoView({block:"start",behavior:"smooth"});summary.focus();});
   // Collapse only an empty access panel. Visible enrollment/recovery UI stays open.
   const collapseEmpty=()=>{if(cards.every(card=>card.hidden))access.open=false;};
   const visibility=new MutationObserver(collapseEmpty);
   for(const card of cards)visibility.observe(card,{attributes:true,attributeFilter:["hidden"]});
   window.addEventListener("agentconnected",collapseEmpty);
   collapseEmpty();
   window.addEventListener("agentexpired",()=>{access.open=true;});
  }else account.hidden=true;
 }
})();

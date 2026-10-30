(() => {
 "use strict";
 // One console shell for every page: a 56 px top bar (navigation toggle below 1024 px,
 // section, environment badge, status slot, user menu) and the existing authentication
 // screens. Authentication behaviour is unchanged: this file only places the elements
 // that agent.js, human.js and passkey.js create, and never creates credentials or sessions.
 const header=document.querySelector("body>header"), main=document.querySelector("main");
 if(!header||!main)return;
 const I=()=>window.secDNSI18n;
 const svg=(path,size=18)=>{const s=document.createElementNS("http://www.w3.org/2000/svg","svg");s.setAttribute("viewBox","0 0 24 24");s.setAttribute("width",size);s.setAttribute("height",size);s.setAttribute("aria-hidden","true");s.setAttribute("focusable","false");const p=document.createElementNS("http://www.w3.org/2000/svg","path");p.setAttribute("d",path);s.append(p);return s;};
 const node=(tag,cls,text)=>{const e=document.createElement(tag);if(cls)e.className=cls;if(text!==undefined)e.textContent=text;return e;};
 main.id=main.id||'console-main';
 const skip=node('a','console-skip','Skip to content');skip.href='#'+main.id;document.body.prepend(skip);skip.addEventListener('click',event=>{event.preventDefault();const target=document.getElementById('console-auth-screen');const destination=target&&!target.hidden?target:main;destination.setAttribute('tabindex','-1');destination.focus();destination.scrollIntoView({block:'start'});});

 // --- navigation: a fixed sidebar from 1024 px, a drawer below -------------------------
 const sidebar=document.querySelector('.console-sidebar');
 const backdrop=node('div','console-nav-backdrop');backdrop.hidden=true;
 const menu=node('button','topbar-icon console-menu-toggle');menu.type='button';menu.setAttribute('aria-expanded','false');menu.setAttribute('aria-label','Open navigation');menu.append(svg("M4 6h16M4 12h16M4 18h16"));
 // While the drawer is open the page behind it is inert (C42): not focusable, not read out.
 const setNav=open=>{if(!sidebar)return;sidebar.classList.toggle('menu-open',open);backdrop.hidden=!open;main.inert=open;document.getElementById('console-auth-screen')?.toggleAttribute('inert',open);menu.setAttribute('aria-expanded',String(open));menu.setAttribute('aria-label',open?'Close navigation':'Open navigation');document.body.classList.toggle('nav-open',open);if(open)sidebar.querySelector('a,button:not([hidden])')?.focus();};
 if(sidebar){sidebar.id='console-navigation';menu.setAttribute('aria-controls',sidebar.id);sidebar.after(backdrop);
  menu.addEventListener('click',()=>setNav(!sidebar.classList.contains('menu-open')));backdrop.addEventListener('click',()=>{setNav(false);menu.focus();});
  sidebar.addEventListener('keydown',event=>{if(event.key==='Escape'&&sidebar.classList.contains('menu-open')){setNav(false);menu.focus();}});
  sidebar.addEventListener('click',event=>{if(event.target.closest('a'))setNav(false);});
  matchMedia('(min-width: 1024px)').addEventListener('change',e=>{if(e.matches)setNav(false);});}
 else menu.hidden=true;

 // --- top bar ----------------------------------------------------------------------------
 header.classList.add('topbar');
 const selectedNav=document.querySelector(".console-sidebar a[aria-current]");
 const section=selectedNav?selectedNav.textContent.trim():"DNS administration";
 const foot=document.querySelector('.console-sidebar-foot');
 const context=node("div","console-context topbar-context");
 const label=node("strong","topbar-title",section);
 const badge=node("span","env-badge",foot?.querySelector('strong')?.textContent.trim()||"");badge.hidden=!badge.textContent;
 const scope=foot?.querySelector('span')?.textContent.trim();if(scope)badge.title=scope;
 context.append(label,badge);
 // Truthful connection state (C32): pages report what they observed; the badge dot follows it.
 window.addEventListener('secdns:connection',e=>{const state=e.detail?.state;if(!state)return;badge.dataset.state=state;});
 const status=node("div","topbar-status");status.setAttribute('aria-live','polite');
 for(const old of [...header.children]){if(old.tagName==="STRONG")old.remove();else if(old.id==="connection"||old.id==="authentication")status.append(old);}
 const followerLink=header.querySelector(':scope>a');if(followerLink)followerLink.classList.add('topbar-link');
 header.prepend(menu,context,status);
 // Reuse existing authentication UI and its handlers; never recreate credentials or sessions.
 window.addEventListener("beforeunload",event=>{if(document.body.dataset.consolePage==="import"&&!window.secDNSAgent?.leaving&&(document.getElementById("source")?.value||document.getElementById("file")?.files?.length)){event.preventDefault();event.returnValue="";}});
 const importLink=document.querySelector('.console-sidebar a[href$="/ui/import-preview/"]'), handoff=document.getElementById("open-import");
 if(importLink&&handoff){importLink.title="Open import review in a separate page; keep this draft";importLink.addEventListener("click",event=>{event.preventDefault();handoff.click();});}

 // --- user menu: identity, Account security, Theme, Language, Sign out ---------------------
 const account=document.getElementById("console-account"),human=document.getElementById("human-access"),agent=document.getElementById("agent-access"),passkeys=document.getElementById("passkey-access");
 const userMenu=node("div","user-menu");userMenu.id="account-menu";
 const userButton=node("button","user-menu-button");userButton.type="button";userButton.id="account-summary";userButton.setAttribute("aria-expanded","false");userButton.setAttribute("aria-controls","user-menu-panel");userButton.setAttribute("aria-label","Account menu");
 const avatar=node("span","avatar");avatar.setAttribute("aria-hidden","true");avatar.append(svg("M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8Zm-7 8a7 7 0 0 1 14 0",16));
 const who=node("span","who"),accountName=node("strong","who-name"),accountRole=node("span","who-role");accountName.setAttribute("translate","no");who.append(accountName,accountRole);
 userButton.append(avatar,who,svg("M6 9l6 6 6-6",16));
 const panel=node("div","user-menu-panel");panel.id="user-menu-panel";panel.hidden=true;
 const identityBlock=node("div","menu-identity"),idName=node("strong","menu-name"),idRole=node("span","menu-role"),idProvider=node("span","menu-provider","Signed in with WithMy ID");idName.setAttribute("translate","no");identityBlock.append(idName,idRole,idProvider);
 const securityButton=node("button","menu-item","Account security");securityButton.type="button";securityButton.prepend(svg("M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6l7-3Z",16));
 securityButton.addEventListener("click",()=>{closeMenu(false);account?.click();});
 const segmented=(labelText,name,options,onPick)=>{const group=node("div","menu-group");const id="menu-"+name+"-label";const caption=node("span","menu-label",labelText);caption.id=id;const seg=node("div","segmented");seg.setAttribute("role","radiogroup");seg.setAttribute("aria-labelledby",id);
  const buttons=options.map(([value,text,noTranslate])=>{const b=node("button","segment",text);b.type="button";b.setAttribute("role","radio");b.dataset.value=value;if(noTranslate){b.setAttribute("translate","no");b.lang=value;}b.addEventListener("click",()=>onPick(value));seg.append(b);return b;});
  seg.addEventListener("keydown",e=>{if(!["ArrowLeft","ArrowRight","ArrowUp","ArrowDown"].includes(e.key))return;e.preventDefault();const i=buttons.indexOf(document.activeElement);const next=buttons[(i+(e.key==="ArrowLeft"||e.key==="ArrowUp"?buttons.length-1:1))%buttons.length];next.focus();next.click();});
  group.append(caption,seg);return {group,buttons};};
 const theme=segmented("Theme","theme",[["system","System"],["light","Light"],["dark","Dark"]],value=>{I()?.setTheme(value);syncMenu();});
 const language=segmented("Language","language",[["en","English",true],["zh-Hant","繁體中文",true]],value=>{I()?.setLanguage(value);syncMenu();});
 const host=node("p","menu-foot",location.host);host.setAttribute("translate","no");
 const divider=node("hr","menu-divider");
 panel.append(identityBlock,securityButton,theme.group,language.group,divider,host);
 userMenu.append(userButton,panel);header.append(userMenu);
 const syncMenu=()=>{const current=I()?.getTheme()||"system",lang=I()?.lang||document.documentElement.lang;for(const b of theme.buttons){const on=b.dataset.value===current;b.setAttribute("aria-checked",String(on));b.tabIndex=on?0:-1;}for(const b of language.buttons){const on=b.dataset.value===lang;b.setAttribute("aria-checked",String(on));b.tabIndex=on?0:-1;}};
 const phone=matchMedia("(max-width: 639px)");
 const openMenu=()=>{syncMenu();panel.hidden=false;userButton.setAttribute("aria-expanded","true");userMenu.classList.add("open");if(phone.matches)main.inert=true;(panel.querySelector(".menu-item:not([hidden])")||panel.querySelector('[aria-checked="true"]'))?.focus();};
 const closeMenu=(focus=true)=>{if(panel.hidden)return;panel.hidden=true;if(!sidebar?.classList.contains('menu-open'))main.inert=false;userButton.setAttribute("aria-expanded","false");userMenu.classList.remove("open");if(focus)userButton.focus();};
 userButton.addEventListener("click",()=>panel.hidden?openMenu():closeMenu());
 userMenu.addEventListener("keydown",e=>{if(e.key==="Escape"){e.stopPropagation();closeMenu();}});
 document.addEventListener("click",e=>{if(!userMenu.contains(e.target))closeMenu(false);});
 window.addEventListener("secdns:language",syncMenu);window.addEventListener("secdns:theme",syncMenu);
 // Compatibility: older automation opens the menu through <details open>.
 Object.defineProperty(userMenu,"open",{get:()=>!panel.hidden,set:v=>v?openMenu():closeMenu(false)});

 if(!human||!agent){identityBlock.hidden=securityButton.hidden=true;accountName.textContent="";accountRole.textContent="";userMenu.classList.add("anonymous");return;}
 const identity=document.getElementById("agent-identity"),logout=document.getElementById("agent-logout")||[...header.querySelectorAll("button")].find(b=>b.textContent.startsWith("Sign out"));
 if(logout){logout.classList.add("menu-item","menu-signout");panel.insertBefore(logout,divider.nextSibling);}
 const warning=document.getElementById("auth-session-warning");if(warning)status.append(warning);
 const sessionDetails=document.createElement("details");sessionDetails.id="session-details";const detailsTitle=document.createElement("summary");detailsTitle.textContent="Advanced session details";sessionDetails.append(detailsTitle);if(identity)sessionDetails.append(identity);
 const sessionUI=()=>{const active=!!window.secDNSAgent?.active;const name=window.secDNSAgent?.name||"";const role=window.secDNSAgent?.role||"";
  userMenu.classList.toggle("anonymous",!active);accountName.textContent=active?name:"";accountRole.textContent=active?role:"";idName.textContent=name;idRole.textContent=role;
  identityBlock.hidden=securityButton.hidden=!active;idProvider.hidden=!(active&&window.secDNSAgent?.kind==="human"&&window.secDNSAgent?.state?.sso_login===true);
  if(logout)logout.hidden=!active;
  avatar.replaceChildren();if(active&&name){avatar.textContent=[...name.trim()][0]?.toUpperCase()||"";}else avatar.append(svg("M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8Zm-7 8a7 7 0 0 1 14 0",16));
  const parent=window.secDNSAgent?.kind==="human"?document.getElementById("human-security"):agent;if(parent&&sessionDetails.parentElement!==parent)parent.append(sessionDetails);if(!active){closeMenu(false);sessionDetails.open=false;}};
 window.addEventListener("agentconnected",sessionUI);window.addEventListener("agentexpired",sessionUI);window.addEventListener("authstate",sessionUI);sessionUI();

 // --- authentication screens (sign-in, signed-out, account security); logic unchanged ----
 const originalTitle=document.title;
 const screen=document.createElement("section");screen.id="console-auth-screen";screen.setAttribute("role","main");screen.hidden=true;
 const brand=node("div","auth-brand");const brandName=node("span","auth-brand-name");brandName.append(node("span","brand-mark"),document.createTextNode("secDNS"));brandName.setAttribute("translate","no");
 const langPill=node("div","lang-pill");langPill.setAttribute("role","group");langPill.setAttribute("aria-label","Language");
 for(const [value,text] of [["en","EN"],["zh-Hant","繁中"]]){const b=node("button","lang-pill-option",text);b.type="button";b.lang=value;b.dataset.value=value;b.setAttribute("translate","no");b.addEventListener("click",()=>{I()?.setLanguage(value);syncPill();});langPill.append(b);}
 const syncPill=()=>{const lang=I()?.lang||document.documentElement.lang;for(const b of langPill.children)b.setAttribute("aria-pressed",String(b.dataset.value===lang));};
 window.addEventListener("secdns:language",syncPill);syncPill();
 brand.append(brandName,langPill);
 const surface=document.createElement("div");surface.className="auth-surface";
 const agentToggle=document.createElement("button");agentToggle.type="button";agentToggle.className="auth-secondary";agentToggle.textContent="Agent access";
 const returnButton=document.createElement("button");returnButton.type="button";returnButton.className="auth-return";returnButton.textContent="Back to "+({records:"DNS records",import:"import",followers:"replication status"}[document.body.dataset.consolePage]||"workspace");
 const signout=document.createElement("button");signout.type="button";signout.className="auth-secondary";signout.textContent="Sign out";signout.addEventListener("click",()=>window.secDNSAgent.logout().catch(()=>{}));
 screen.append(brand,surface,returnButton,signout);surface.append(human,agent,agentToggle);if(passkeys)surface.append(passkeys);document.body.append(screen);
 let accountOpen=false,agentOpen=false;
 const display=()=>{
  const state=window.secDNSAgent?.state;
  const humanEnabled=state?.human_access===true&&!human.hidden;
  const enabled=state?.agent_access===true&&state.public_origin===location.origin;
  if(!humanEnabled){
   for(const n of [human,agent,passkeys])if(n&&n.parentElement===surface)main.prepend(n);
   screen.hidden=true;document.body.classList.remove("auth-screen-open","account-screen-open");document.title=originalTitle;label.textContent=section;return;
  }
  for(const n of [human,agent,passkeys])if(n&&n.parentElement!==surface)surface.append(n);
  surface.append(agentToggle);
  const active=window.secDNSAgent?.active;
  const ceremony=!!human.querySelector('#human-recovery-codes:not([hidden]),#human-qr:not([hidden])');
  const show=enabled&&(!active||accountOpen||ceremony);
  document.title=show?(active?"Account security":agentOpen?"Agent access":"Sign in")+" - secDNS":originalTitle;
  if(account){if(show&&active){account.setAttribute("aria-current","page");selectedNav?.removeAttribute("aria-current");}else{account.removeAttribute("aria-current");selectedNav?.setAttribute("aria-current","page");}}
  if(show&&active)securityButton.setAttribute("aria-current","page");else securityButton.removeAttribute("aria-current");
  label.textContent=show&&active?"Account security":section;
  screen.hidden=!show;document.body.classList.toggle("auth-screen-open",show&&!active);document.body.classList.toggle("account-screen-open",show&&!!active);
  screen.dataset.access=agentOpen?"agent":"human";
  agentToggle.hidden=!!active||!humanEnabled||window.secDNSAgent?.state?.sso_login===true;agentToggle.textContent=agentOpen?"Back to human sign in":"Agent access";
  // Single sign-on: Account security is a standard page of the shell; the navigation (its own
  // entry closes the page in place) replaces the separate Back button.
  returnButton.hidden=!active||ceremony||state?.sso_login===true;signout.hidden=true;
  if(account)account.textContent=window.secDNSAgent?.kind==="human"?"Account security":"Sign in";
 };
 agentToggle.addEventListener("click",()=>{agentOpen=!agentOpen;display();(agentOpen?document.getElementById("agent-credential"):document.getElementById("human-username"))?.focus();});
 returnButton.addEventListener("click",()=>{accountOpen=false;display();userButton.focus();});
 account?.addEventListener("click",()=>{accountOpen=true;agentOpen=window.secDNSAgent?.kind==="agent";if(agentOpen)agent.hidden=false;display();const title=(agentOpen?agent:human).querySelector("h2");window.scrollTo(0,0);title?.setAttribute("tabindex","-1");title?.focus({preventScroll:true});window.dispatchEvent(new Event("accountopen"));});
 // While Account security is open, the current page's own navigation entry closes it in place
 // (no reload, so unsaved work stays); other entries navigate as usual.
 selectedNav?.addEventListener("click",event=>{if(!accountOpen||screen.hidden)return;event.preventDefault();accountOpen=false;display();setNav(false);document.getElementById(main.id)?.focus?.();});
 window.addEventListener("agentconnected",()=>{agentOpen=false;display();});
 window.addEventListener("agentexpired",()=>{accountOpen=false;agentOpen=false;display();});
 window.addEventListener("authstate",display);window.addEventListener("humanflowchange",display);
 display();
})();

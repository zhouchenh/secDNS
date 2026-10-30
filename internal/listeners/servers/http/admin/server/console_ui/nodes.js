(() => {
 "use strict";
 // Nodes, DNS health and Routing. Node identities come from the server's own node inventory
 // (data-nodes on <main>, composed by nodes_ui.go from the same list the node API accepts);
 // this file holds no node names or addresses. Status is one of four states (OK, Degraded,
 // Down, Unknown), always shown as colour token + icon + word.
 const base=new URL("../../",location.href), main=document.querySelector('main'), page=main.dataset.nodePage;
 let inventory=[];try{inventory=JSON.parse(main.dataset.nodes||"[]").filter(n=>n&&typeof n.id==="string");}catch{inventory=[];}
 const ids=inventory.map(n=>n.id), byId=new Map(inventory.map(n=>[n.id,n]));
 // Display label of a node: its inventory ID and router ID (data; never translated).
 const names=Object.fromEntries(inventory.map(n=>[n.id,n.router_id?n.id+" · "+n.router_id:n.id]));
 const peerNode=address=>inventory.find(n=>n.router_id===address||n.ipv6===address)?.id||"";
 const titles={nodes:"Nodes",health:"DNS health",routing:"Routing"};
 const descriptions={nodes:"Availability and maintenance for your DNS nodes.",health:"Normal DNS and DNS64 checks, with route eligibility for IPv4 and IPv6.",routing:"BGP sessions and service announcements. Drain a node before maintenance; resume when ready."};
 document.getElementById('page-title').textContent=titles[page];document.title=titles[page]+" - secDNS";document.getElementById('page-description').textContent=descriptions[page];
 const grid=document.getElementById('node-grid'), message=document.getElementById('node-message'), refresh=document.getElementById('refresh-nodes'), dialog=document.getElementById('maintenance-dialog'), rollup=document.getElementById('node-rollup'), slot=document.getElementById('node-state');
 const samples=new Map(), failures=new Map(), operations=new Map();let epoch=0,busy=false,selection=null,signedIn=false;
 const el=(tag,text,cls)=>{const e=document.createElement(tag);if(text!==undefined)e.textContent=text;if(cls)e.className=cls;return e;};
 const data=(tag,text,cls)=>{const e=el(tag,text,cls);e.translate=false;return e;};
 const icon=(path,size=16)=>{const s=document.createElementNS("http://www.w3.org/2000/svg","svg");s.setAttribute("viewBox","0 0 24 24");s.setAttribute("width",size);s.setAttribute("height",size);s.setAttribute("aria-hidden","true");s.setAttribute("focusable","false");const p=document.createElementNS("http://www.w3.org/2000/svg","path");p.setAttribute("d",path);s.append(p);return s;};
 const ICON={ok:"M20 6 9 17l-5-5",degraded:"M12 9v4m0 4h.01M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z",down:"M18 6 6 18M6 6l12 12",unknown:"M9.1 9a3 3 0 0 1 5.8 1c0 2-3 3-3 3m.1 4h.01",chevron:"M9 6l6 6-6 6",back:"M15 18l-6-6 6-6",retry:"M20 12a8 8 0 1 1-2.3-5.7M20 4v4h-4"};
 const WORD={ok:"OK",degraded:"Degraded",down:"Down",unknown:"Unknown"};
 const RANK={down:0,degraded:1,unknown:2,ok:3};
 const date=t=>Number.isFinite(Date.parse(t))?(window.secDNSI18n?.date(t)||new Date(t).toLocaleString()):"Not observed";
 // A date inside a sentence; i18n.js renders it in the current language and again on a language switch.
 const stamp=(tag,t,template,cls)=>{const e=el(tag,template.split('{time}').join(date(t)),cls);if(Number.isFinite(Date.parse(t))){e.dataset.i18nAt=t;e.dataset.i18nTemplate=template;e.title=t;window.secDNSI18n?.stamp?.(e);}return e;};
 // Status badge: token + icon + word, with the specific condition next to it.
 function badge(state,small){const b=el('span',undefined,'status-badge status-'+state.level+(small?' status-small':''));b.append(icon(ICON[state.level],small?14:16),el('span',WORD[state.level],'status-word'));if(state.detail&&state.detail!==WORD[state.level])b.append(el('span',state.detail,'status-detail'));return b;}
 const freshSample=s=>!!s&&!s.stale&&s.reachable&&Date.now()-Date.parse(s.observed_at)<45000;
 function info(id){
  const s=samples.get(id),failure=failures.get(id),fresh=!!s&&!s.stale&&!failure&&Date.now()-Date.parse(s.observed_at)<45000;
  const enabled=(s?.profiles||[]).filter(p=>p.enabled!==false);
  let level,detail;
  if(!s){level='unknown';detail=failure?"No data yet":busy?"Checking…":"Not yet checked";}
  else if(!fresh){level='unknown';detail="Stale observation";}
  else if(!s.reachable){level='down';detail="Unreachable";}
  else if(!s.daemon.active){level='down';detail="DNS stopped";}
  else if(s.maintenance.withdraw){level='degraded';detail="Drained";}
  else if(!enabled.length){level='degraded';detail="Announcements disabled";}
  else if(enabled.every(p=>p.local_healthy===false||p.healthy===false)){level='down';detail="DNS checks failing";}
  else if(enabled.some(p=>p.local_healthy===false)){level='degraded';detail="DNS checks failing";}
  else if(enabled.some(p=>p.upstream_healthy===false)){level='degraded';detail="Upstream unavailable";}
  else if(enabled.some(p=>p.local_healthy==null||p.upstream_healthy==null||p.healthy==null)){level='unknown';detail="Health unknown";}
  else if(enabled.some(p=>!p.healthy)){level='degraded';detail="DNS checks failing";}
  else {level='ok';detail="Healthy";}
  return {id,s,failure,fresh,state:{level,detail}};
 }
 const ordered=()=>ids.map(info).sort((a,b)=>RANK[a.state.level]-RANK[b.state.level]||ids.indexOf(a.id)-ids.indexOf(b.id));
 // Why a node action is unavailable (C38): shown next to the disabled control and linked to it.
 function blockedReason(x){if(busy)return "Wait for the current check or operation to finish.";if(!x.s)return "No observation yet. Refresh to check this node.";if(!x.fresh)return "This observation is out of date. Refresh before changing this node.";if(!x.s.reachable)return "The node is unreachable. Refresh to check it again.";return "";}
 function nodeAction(x,actions){
  const s=x.s;if(!s)return;const b=el('button',s.maintenance.withdraw?'Resume announcements':'Drain node',s.maintenance.withdraw?'':'danger');b.type='button';b.dataset.nodeAction=x.id;b.dataset.focusKey='action-'+x.id;
  const reason=blockedReason(x);b.disabled=!!reason;b.addEventListener('click',()=>openAction(x.id,samples.get(x.id)));actions.append(b);return reason;
 }
 function reasonLine(reason,id,actions,buttons){
  if(!reason){for(const b of buttons)b?.removeAttribute('aria-describedby');return;}
  const line=el('p',undefined,'disabled-reason');line.id='reason-'+page+'-'+id;line.append(el('span',reason));
  if(!busy){const again=el('button','Refresh');again.type='button';again.className='link-button';again.dataset.focusKey='reason-refresh-'+id;again.addEventListener('click',load);line.append(again);}
  for(const b of buttons)if(b)b.setAttribute('aria-describedby',line.id);actions.append(line);
 }
 function nodeTitle(x,tag='h2'){const wrap=el('div',undefined,'node-identity'),title=data(tag,x.id);if(tag!=='strong')title.id='node-title-'+page+'-'+x.id;wrap.append(title);const n=byId.get(x.id);if(n?.router_id)wrap.append(data('span',n.router_id,'node-address'));return wrap;}
 function meta(x){const m=el('p',undefined,'meta');const s=x.s;m.append(el('span',x.id+" · DNS process: "+(s?(s.daemon.active?"Running":"Stopped"):"Unknown")),document.createTextNode(' · '),s&&Number.isFinite(Date.parse(s.observed_at))?stamp('span',s.observed_at,'Last checked: {time}'):el('span',x.failure?'No data yet':'Not yet checked'));return m;}
 const roleName=p=>p.role==='normal'?'Normal DNS':p.role==='dns64'?'DNS64':p.role;
 const familyName=f=>f===6?'IPv6':'IPv4';
 // Plain-language reason for a health observation; the adapter's code stays available as data.
 const REASONS={ready:"Ready",upstream_probe_timeout:"Upstream did not answer in time",upstream_probe_failed:"Upstream answered with an error",local_probe_timeout:"Local DNS did not answer in time",local_probe_failed:"Local DNS answered with an error",disabled:"Turned off in settings",stale_health:"Health result is out of date"};
 function reasonText(code){const e=el('span');if(!code){e.textContent='—';return e;}if(Object.hasOwn(REASONS,code)){e.append(el('span',REASONS[code]));}else e.append(el('span','Other condition'));const c=data('code',code,'reason-code');e.append(document.createTextNode(' '),c);return e;}
 function checkLevel(p,fresh){
  if(p.enabled===false)return {level:'unknown',word:'Disabled'};
  const failing=p.local_healthy===false||p.upstream_healthy===false||p.healthy===false;
  if(!fresh)return {level:'unknown',word:failing?'Last known: failing':p.healthy===true?'Last known: passing':'Unknown'};
  if(p.healthy==null&&p.local_healthy==null)return {level:'unknown',word:'Unknown'};
  if(failing)return {level:p.local_healthy===false?'down':'degraded',word:'Failing'};
  return {level:'ok',word:'Passing'};
 }
 function checkCell(p,fresh){const c=checkLevel(p,fresh),b=el('span',undefined,'status-badge status-small status-'+c.level);b.append(icon(ICON[c.level],14),el('span',c.word,'status-word'));return b;}
 function checksTable(x){
  const s=x.s,wrap=el('div',undefined,'table-wrap node-table-wrap');const t=el('table',undefined,'node-check-table'),head=el('thead'),hr=el('tr');
  for(const h of ['Service','Family','Local DNS','Upstream','Eligible','Announcement','Address','Details'])hr.append(el('th',h));head.append(hr);t.append(head);const body=el('tbody');
  for(const p of s.profiles||[]){const tr=el('tr'),fresh=x.fresh;const lv=v=>!fresh?'Unknown':v==null?'Unknown':v?'Passing':'Failing';
   const cells=[[el('span',roleName(p))],[el('span',familyName(p.family))],[el('span',lv(p.local_healthy),p.local_healthy===false&&fresh?'node-check-failed':'')],[el('span',!fresh?'Unknown':p.upstream_healthy==null?'Unknown':p.upstream_healthy?'Passing'+(Number.isFinite(p.upstream_age_seconds)?' · '+Math.round(p.upstream_age_seconds)+'s ago':''):'Failing',p.upstream_healthy===false&&fresh?'node-check-failed':'')],[checkCell(p,fresh)],[el('span',!fresh?'Unknown':p.advertised?'Advertised':'Withdrawn')],[data('code',p.prefix||'—')],[reasonText(p.reason)]];
   const labels=['Service','Family','Local DNS','Upstream','Eligible','Announcement','Address','Details'];
   cells.forEach((nodes,i)=>{const td=el('td');td.append(el('span',labels[i],'cell-label'),...nodes);tr.append(td);});body.append(tr);}
  if(!(s.profiles||[]).length){const tr=el('tr'),td=el('td','No observations available');td.colSpan=8;tr.append(td);body.append(tr);}
  t.append(body);wrap.append(t);return wrap;
 }
 function sessionBadge(state,fresh){const established=String(state).toLowerCase()==='established';const level=!fresh?'unknown':established?'ok':'degraded';const b=el('span',undefined,'status-badge status-small status-'+level);b.append(icon(ICON[level],14));b.append(data('span',state,'status-word'));if(!fresh)b.append(el('span','Historical','status-detail'));return b;}
 function peerTable(x){
  const s=x.s,wrap=el('div',undefined,'table-wrap node-table-wrap'),t=el('table',undefined,'node-peer-table'),head=el('thead'),hr=el('tr');
  const labels=['Peer','Address','Family','Session','Advertised prefixes'];for(const h of labels)hr.append(el('th',h));head.append(hr);t.append(head);const body=el('tbody');
  for(const p of s.peers||[]){const tr=el('tr'),peer=peerNode(p.address);
   const cells=[[peer?data('strong',peer):el('span','Unlisted peer')],[data('code',p.address,'node-observation-address')],[el('span',familyName(p.family))],[sessionBadge(p.state,x.fresh)],[x.fresh?((p.prefixes||[]).length?data('span',p.prefixes.join(', ')):el('span','None')):el('span','Unknown (stale)')]];
   cells.forEach((nodes,i)=>{const td=el('td');td.append(el('span',labels[i],'cell-label'),...nodes);tr.append(td);});body.append(tr);}
  if(!(s.peers||[]).length){const tr=el('tr'),td=el('td','No BGP peers reported');td.colSpan=5;tr.append(td);body.append(tr);}
  t.append(body);wrap.append(t);return wrap;
 }
 function summary(x){const s=x.s,box=el('dl',undefined,'node-summary');for(const [title,value] of [['DNS process',s.daemon.active?'Running':'Stopped'],['Announcements',s.maintenance.withdraw?'Administratively withdrawn':'Health controlled'],['Healthy checks',(s.profiles||[]).filter(p=>p.healthy===true).length+' / '+(s.profiles||[]).length],['BGP sessions',(s.peers||[]).filter(p=>String(p.state).toLowerCase()==='established').length+' / '+(s.peers||[]).length]]){const item=el('div');item.append(el('dt',title),el('dd',x.fresh?value:'Last sample: '+value));box.append(item);}return box;}
 function notes(x,card){if(x.failure)card.append(el('p',x.s?'Could not refresh this node. The values below are from the last observation and may be out of date.':'Could not refresh this node. No data yet.','node-error'));else if(x.s&&!x.fresh)card.append(el('p','Historical observation. Current checks and announcements are unknown; refresh to check again.','node-stale-note'));if(x.s?.errors?.length)card.append(data('p',x.s.errors.join(' · '),'node-error'));}
 function ops(id,card){for(const op of operations.get(id)||[])card.append(operationPanel(op));}

 // ---- page states: loading, error (with Try again), roll-up ----
 function pageState(list){
  slot.replaceChildren();grid.setAttribute('aria-busy',String(busy&&!samples.size));
  if(!signedIn){rollup.hidden=true;return;}
  if(!ids.length){const box=el('div',undefined,'empty-state');box.append(el('h2','No nodes configured'),el('p','This console has no node inventory. Node management appears here once nodes are configured.'));slot.append(box);rollup.hidden=true;return;}
  if(busy&&!samples.size&&!failures.size){const box=el('div',undefined,'loading-state');box.setAttribute('role','status');box.append(el('span',undefined,'spinner'),el('span','Checking {n} nodes…'.replace('{n}',String(ids.length))));slot.append(box);}
  const failed=ids.filter(id=>failures.has(id));
  if(failed.length&&!busy){
   const all=failed.length===ids.length&&!ids.some(id=>samples.has(id));const box=el('div',undefined,'error-state'+(all?'':' warn-state'));box.setAttribute('role','alert');
   const head=el('div',undefined,'state-head');head.append(icon(all?ICON.down:ICON.degraded,20),el('h2',all?'Couldn’t reach any node':'Some nodes could not be refreshed'));
   box.append(head,el('p',all?'The node status service did not answer. Nothing was changed. Values shown are unknown until a check succeeds.':'Not refreshed: {nodes}. Their last values are kept and marked out of date.'.replace('{nodes}',failed.join(', '))));
   const again=el('button','Try again','primary');again.type='button';again.dataset.focusKey='try-again';again.prepend(icon(ICON.retry,16));again.addEventListener('click',load);box.append(again);slot.append(box);
  }
  const counts={ok:0,degraded:0,down:0,unknown:0};for(const x of list)counts[x.state.level]++;
  rollup.replaceChildren();rollup.hidden=false;rollup.append(el('span','{n} nodes'.replace('{n}',String(ids.length)),'rollup-total'));
  for(const level of ['down','degraded','unknown','ok'])if(counts[level]){const c=el('span',undefined,'status-badge status-small status-'+level);c.append(icon(ICON[level],14),el('span',String(counts[level]),'rollup-count'),el('span',WORD[level],'status-word'));rollup.append(c);}
  window.dispatchEvent(new CustomEvent('secdns:connection',{detail:{state:busy&&!samples.size?'checking':ids.some(id=>samples.has(id)&&!failures.has(id))?'ok':failed.length?'error':'unknown'}}));
 }

 // ---- Nodes: list, then node detail with tabs (Overview / DNS health / Routing) ----
 const route=()=>{const p=new URLSearchParams(location.hash.slice(1));const node=p.get('node');return {node:byId.has(node)?node:'',tab:['overview','health','routing'].includes(p.get('tab'))?p.get('tab'):'overview'};};
 let lastRoute='';
 function nodesList(list){
  const ul=el('ul',undefined,'node-list');ul.setAttribute('aria-label','Nodes');
  for(const x of list){const li=el('li'),a=el('a',undefined,'node-row');a.href='#node='+encodeURIComponent(x.id);a.dataset.focusKey='row-'+x.id;a.dataset.nodeRow=x.id;
   const who=nodeTitle(x,'strong'),facts=el('span',undefined,'node-row-facts');
   if(x.s){facts.append(el('span',"DNS process: "+(x.s.daemon.active?"Running":"Stopped")),el('span','Healthy checks: {n}'.replace('{n}',(x.s.profiles||[]).filter(p=>p.healthy===true).length+' / '+(x.s.profiles||[]).length)),el('span','BGP sessions: {n}'.replace('{n}',(x.s.peers||[]).filter(p=>String(p.state).toLowerCase()==='established').length+' / '+(x.s.peers||[]).length)),stamp('span',x.s.observed_at,'Last checked: {time}'));}
   else facts.append(el('span',x.failure?'No data yet':busy?'Checking…':'Not yet checked'));
   a.append(who,badge(x.state),facts,icon(ICON.chevron,18));li.append(a);ul.append(li);}
  return ul;
 }
 function nodeDetail(x,tab){
  const card=el('section',undefined,'node-card node-detail');card.dataset.node=x.id;
  const back=el('a',undefined,'node-back');back.href='#';back.dataset.focusKey='back';back.append(icon(ICON.back,16),el('span','All nodes'));
  const header=el('div',undefined,'node-header'),title=nodeTitle(x);title.querySelector('h2').tabIndex=-1;card.setAttribute('aria-labelledby',title.querySelector('h2').id);
  const actions=el('div',undefined,'node-header-actions');const reason=nodeAction(x,actions);
  header.append(title,badge(x.state),actions);card.append(back,header,meta(x));
  if(x.s)reasonLine(reason,x.id,card,[actions.querySelector('[data-node-action]')]);
  notes(x,card);
  const tabs=el('div',undefined,'tabs');tabs.setAttribute('role','tablist');tabs.setAttribute('aria-label','Node details');
  const panes={overview:'Overview',health:'DNS health',routing:'Routing'};const buttons=[];
  for(const [key,label] of Object.entries(panes)){const b=el('button',label,'tab');b.type='button';b.setAttribute('role','tab');b.id='tab-'+key;b.setAttribute('aria-controls','panel-'+key);b.setAttribute('aria-selected',String(key===tab));b.tabIndex=key===tab?0:-1;b.dataset.focusKey='tab-'+key;b.addEventListener('click',()=>{location.hash='node='+encodeURIComponent(x.id)+(key==='overview'?'':'&tab='+key);});buttons.push(b);tabs.append(b);}
  tabs.addEventListener('keydown',e=>{if(!['ArrowLeft','ArrowRight','Home','End'].includes(e.key))return;e.preventDefault();const i=buttons.indexOf(document.activeElement);const n=e.key==='Home'?0:e.key==='End'?buttons.length-1:(i+(e.key==='ArrowLeft'?buttons.length-1:1))%buttons.length;buttons[n].focus();buttons[n].click();});
  const panel=el('div',undefined,'tab-panel');panel.setAttribute('role','tabpanel');panel.id='panel-'+tab;panel.setAttribute('aria-labelledby','tab-'+tab);panel.tabIndex=0;
  if(!x.s)panel.append(el('p',x.failure?'No data yet. Try again to check this node.':'Not yet checked'));
  else if(tab==='overview'){panel.append(summary(x));}
  else if(tab==='health'){panel.append(checksTable(x));const go=el('a','Open DNS health');go.href=new URL('ui/health/',base).pathname;panel.append(el('p',undefined,'hint'));panel.lastChild.append(go);}
  else {panel.append(el('h3','BGP peers'),peerTable(x));const go=el('a','Open Routing');go.href=new URL('ui/routing/',base).pathname;panel.append(el('p',undefined,'hint'));panel.lastChild.append(go);}
  card.append(tabs,panel);ops(x.id,card);return card;
 }
 // ---- DNS health: node x check matrix, failures first ----
 function healthMatrix(list){
  const keys=[];for(const role of ['normal','dns64'])for(const family of [4,6])keys.push([role,family]);
  for(const x of list)for(const p of x.s?.profiles||[])if(!keys.some(([r,f])=>r===p.role&&f===p.family))keys.push([p.role,p.family]);
  const wrap=el('div',undefined,'table-wrap health-matrix-wrap'),t=el('table',undefined,'health-matrix'),cap=el('caption','Each node’s checks; nodes with failures are listed first.','sr-only'),head=el('thead'),hr=el('tr');
  hr.append(el('th','Node'));hr.lastChild.scope='col';for(const [role,family] of keys){const th=el('th');th.scope='col';th.append(el('span',roleName({role})),document.createTextNode(' '),el('span',familyName(family)));hr.append(th);}hr.append(el('th','Settings'));head.append(hr);t.append(cap,head);
  const body=el('tbody');const why=[];
  for(const x of list){const tr=el('tr');tr.dataset.node=x.id;const th=el('th');th.scope='row';th.append(nodeTitle(x,'strong'),badge(x.state,true));if(x.s&&Number.isFinite(Date.parse(x.s.observed_at)))th.append(stamp('span',x.s.observed_at,'Last checked: {time}','meta'));tr.append(th);
   for(const [role,family] of keys){const td=el('td'),label=el('span',undefined,'cell-label');label.append(el('span',roleName({role})),document.createTextNode(' '),el('span',familyName(family)));td.append(label);const p=(x.s?.profiles||[]).find(q=>q.role===role&&q.family===family);
    if(!x.s)td.append(el('span',x.failure?'No data yet':busy?'Checking…':'Not yet checked','muted'));else if(!p)td.append(el('span','Not configured','muted'));else{td.append(checkCell(p,x.fresh));const c=checkLevel(p,x.fresh);if(c.level!=='ok'&&p.reason&&p.reason!=='ready')why.push([x.id,p,x.fresh]);}
    tr.append(td);}
   const set=el('td');set.append(el('span','Settings','cell-label'));if(x.s){const b=el('button','Health settings');b.type='button';b.dataset.nodeHealth=x.id;b.dataset.focusKey='health-'+x.id;const reason=blockedReason(x);b.disabled=!!reason;b.addEventListener('click',()=>window.dispatchEvent(new CustomEvent('nodehealthedit',{detail:x.id})));set.append(b);reasonLine(reason,x.id,set,[b]);}tr.append(set);body.append(tr);}
  t.append(body);wrap.append(t);
  const out=[wrap];
  if(why.length){const box=el('section',undefined,'health-reasons');box.append(el('h2','Why checks are not passing'));const ul=el('ul');for(const [id,p,fresh] of why){const li=el('li');li.append(data('strong',id),document.createTextNode(' · '),el('span',roleName(p)),document.createTextNode(' '),el('span',familyName(p.family)),document.createTextNode(': '),reasonText(p.reason));if(!fresh)li.append(document.createTextNode(' '),el('span','(last known)','muted'));ul.append(li);}box.append(ul);out.push(box);}
  for(const x of list)if((operations.get(x.id)||[]).length){const card=el('section',undefined,'node-card');card.dataset.node=x.id;card.append(nodeTitle(x));ops(x.id,card);out.push(card);}
  return out;
 }
 // ---- Routing: one section per node; Drain in the node header; per-node peer table ----
 function routingCard(x,openDetails){
  const card=el('section',undefined,'node-card');card.dataset.node=x.id;const header=el('div',undefined,'node-header'),title=nodeTitle(x);card.setAttribute('aria-labelledby',title.querySelector('h2').id);
  const actions=el('div',undefined,'node-header-actions');const reason=nodeAction(x,actions);
  if(x.s){const settings=el('button','BGP settings');settings.type='button';settings.dataset.nodeBgp=x.id;settings.dataset.focusKey='bgp-'+x.id;settings.disabled=!!reason;settings.addEventListener('click',()=>window.dispatchEvent(new CustomEvent('nodebgpedit',{detail:x.id})));actions.append(settings);}
  header.append(title,badge(x.state),actions);card.append(header,meta(x));if(x.s)reasonLine(reason,x.id,card,[...actions.querySelectorAll('button')]);notes(x,card);
  if(x.s){card.append(el('h3','BGP peers'),peerTable(x));const details=el('details',undefined,'node-health-details');details.dataset.node=x.id;details.open=openDetails.has(x.id);const sum=el('summary','Service announcements and DNS health');sum.dataset.focusKey='details-'+x.id;details.append(sum,checksTable(x));card.append(details);card.append(el('p','DNS continues running during a drain.','hint'));}
  ops(x.id,card);return card;
 }
 function render(){
  const focusKey=document.activeElement?.dataset?.focusKey;const openDetails=new Set([...grid.querySelectorAll('.node-health-details[open]')].map(e=>e.dataset.node));
  const list=ordered();pageState(list);grid.replaceChildren();
  if(signedIn&&ids.length){
   if(page==='nodes'){const r=route();const key=r.node+'|'+r.tab;if(r.node){grid.append(nodeDetail(info(r.node),r.tab));}else grid.append(nodesList(list));
    if(key!==lastRoute){const was=lastRoute;lastRoute=key;if(was!==''||r.node){const h=r.node?grid.querySelector('.node-detail h2'):null;if(r.node&&was.split('|')[0]===r.node)grid.querySelector('[role=tab][aria-selected=true]')?.focus();else if(h)h.focus();else if(was)grid.querySelector('[data-node-row="'+CSS.escape(was.split('|')[0])+'"]')?.focus();}}}
   else if(page==='health')grid.append(...healthMatrix(list));
   else for(const x of list)grid.append(routingCard(x,openDetails));
  }
  if(focusKey&&(document.activeElement===document.body||!document.activeElement)){const again=grid.querySelector('[data-focus-key="'+CSS.escape(focusKey)+'"]')||slot.querySelector('[data-focus-key="'+CSS.escape(focusKey)+'"]');again?.focus();}
 }
 window.addEventListener('hashchange',()=>{if(page==='nodes')render();});
 async function request(path,method='GET',body){const controller=new AbortController(),timeout=setTimeout(()=>controller.abort(),method==='GET'?35000:165000);try{const r=await fetch(new URL(path,base),{method,credentials:'same-origin',cache:'no-store',redirect:'error',headers:window.secDNSAgent.headers('',method),body:body?JSON.stringify(body):undefined,signal:controller.signal});let data;try{data=await r.json();}catch{throw new Error('The response could not be verified');}if(!r.ok){const reasons={health_revision_changed_refresh:'Settings changed since they were loaded. Reload current settings before another change',health_configuration_unavailable:'Health settings could not be reached',health_validation_failed:'Health settings validation failed. Reload current settings before another change',invalid_health_request:'The health settings request is invalid',invalid_health_revision_or_request:'The settings revision or request reference is invalid',invalid_health_confirmation:'The node confirmation is invalid',invalid_health_config:'Use the supported health ranges and allow two probe timeouts plus 500 milliseconds within each interval',bgp_revision_changed_refresh:'Configuration changed. Close this editor and reload the current settings',bgp_configuration_unavailable:'BGP configuration is unavailable',invalid_bgp_timers:'Use keepalive 3–30 seconds and hold 9–90 seconds, at least three times keepalive',one_peer_per_family_required:'Keep at least one peer enabled for each address family',bgp_validation_failed:'Candidate validation failed; refresh configuration before retrying',human_authentication_required:'Sign in again to continue',node_state_changed_refresh:'The node changed since the last observation',last_healthy_provider:'This node is the last healthy node serving a prefix it announces',fresh_node_observation_required:'A fresh reachable node observation is required',node_operation_in_progress:'Another node operation is in progress',operation_id_used_or_audit_unavailable:'This operation cannot be safely submitted',node_observation_unavailable:'The node could not be reached',operation_uncertain_refresh_do_not_retry:'The result could not be verified',operation_audit_incomplete_refresh_do_not_retry:'The operation receipt could not be completed'};const code=Object.hasOwn(reasons,data.error)?data.error:'unknown';const error=new Error(reasons[code]||'The operation is unavailable');error.status=r.status;error.code=code;
 const beforeApply={health_revision_changed_refresh:409,health_configuration_unavailable:503,invalid_health_config:400,invalid_health_request:400,invalid_health_revision_or_request:400,invalid_health_confirmation:400,bgp_revision_changed_refresh:409,bgp_configuration_unavailable:503,invalid_bgp_timers:400,one_peer_per_family_required:400,human_authentication_required:403,node_state_changed_refresh:409,last_healthy_provider:409,fresh_node_observation_required:409,node_operation_in_progress:409};error.outcome=beforeApply[code]===r.status?'rejected':'unconfirmed';throw error;}return data;}finally{clearTimeout(timeout);}}
 async function load(){if(busy||window.secDNSAgent?.kind!=='human')return;const version=epoch;busy=true;refresh.disabled=true;render();message.textContent='Checking {n} nodes…'.replace('{n}',String(ids.length));await Promise.all(ids.map(async id=>{try{const s=await request('nodes/'+id);if(version!==epoch)return;samples.set(id,s);failures.delete(id);}catch(e){if(version!==epoch)return;failures.set(id,'Could not refresh this node.');}finally{if(version===epoch)render();}}));if(version!==epoch)return;busy=false;refresh.disabled=false;render();message.textContent=failures.size===ids.length&&ids.length?'No node could be checked. Try again.':failures.size?'Some nodes could not be refreshed. Check individual observations below.':'All nodes checked.';}
 // Which other nodes keep serving a prefix: a fresh, reachable observation of a node that is not
 // drained and whose enabled profile for that prefix is healthy and advertised.
 const providers=(prefix,except)=>ids.filter(other=>{if(other===except||failures.has(other))return false;const s=samples.get(other);return freshSample(s)&&s.daemon?.active&&!s.maintenance?.withdraw&&(s.profiles||[]).some(p=>p.prefix===prefix&&p.enabled!==false&&p.healthy===true&&p.advertised===true);});
 function impact(id,s,drain){
  const box=document.getElementById('maintenance-impact'),block=document.getElementById('maintenance-block');box.replaceChildren();block.hidden=true;block.textContent='';
  const prefixes=[...new Set((s.profiles||[]).filter(p=>p.enabled!==false&&(drain?p.advertised===true:true)).map(p=>p.prefix).filter(Boolean))];
  box.append(el('h3',drain?'What changes':'What resumes'));
  if(!prefixes.length){box.append(el('p',drain?'This node announces no prefixes right now; nothing is withdrawn.':'This node has no enabled announcements.'));return true;}
  const list=el('ul',undefined,'impact-list');let blocked=[];
  for(const prefix of prefixes){const item=el('li'),code=el('code',prefix);code.translate=false;item.append(code);
   if(drain){const others=providers(prefix,id);const line=el('span',others.length?'Still served by '+others.join(', '):'No other healthy node serves this prefix',others.length?'impact-ok':'impact-bad');item.append(line);if(!others.length)blocked.push(prefix);}
   list.append(item);}
  box.append(el('p',drain?'Withdrawn from '+id+':':'Announced again from '+id+' once its DNS checks pass:'),list);
  if(drain&&blocked.length){block.textContent=id+' is the last healthy node serving '+blocked.join(', ')+'. Draining it would stop that service. Resume or repair another node first, or refresh if another node recovered.';block.hidden=false;return false;}
  return true;
 }
 let opener=null;
 function openAction(id,s){if(!s)return;const drain=!s.maintenance.withdraw;selection={id,action:drain?'drain':'resume',expected:s.maintenance.withdraw};opener=document.activeElement?.dataset?.focusKey||'action-'+id;
  document.getElementById('maintenance-title').textContent=drain?'Drain '+id+'?':'Resume '+id+'?';
  document.getElementById('maintenance-node').textContent=names[id];
  document.getElementById('maintenance-description').textContent=drain?'Withdraw this node’s candidate announcements. The backend verifies another healthy provider before proceeding.':'Allow this node to announce again after its DNS health checks pass.';
  const allowed=impact(id,s,drain),apply=document.getElementById('apply-maintenance');
  apply.textContent=(drain?'Drain ':'Resume ')+id;apply.className=drain?'danger-solid':'primary';apply.disabled=!allowed;selection.allowed=allowed;
  dialog.classList.toggle('danger-dialog',drain);dialog.showModal();document.getElementById('cancel-maintenance').focus();}
 document.getElementById('cancel-maintenance').onclick=()=>dialog.close();
 function operationPanel(op){const panel=el('section',undefined,'node-operation '+op.outcome);panel.setAttribute('aria-label',op.action+' operation result');panel.append(el('h3',op.action==='bgp-apply'?'BGP configuration result':op.action==='health-apply'?'Health settings result':'Maintenance result'),el('p',op.message));const details=el('details'),summary=el('summary','Operation details');details.append(summary,el('p','Results remain through Refresh. Reloading or leaving clears this receipt; server work may continue.'),el('p','Reference: '+op.requestID),stamp('p',op.submitted,'Submitted: {time}'));if(op.code)details.append(el('p','Response: '+op.code+' ('+op.status+')'));if(op.proposed)details.append(el('pre',JSON.stringify(op.proposed,null,2)));if(op.action==='drain'&&op.outcome==='confirmed'&&op.node){const s=samples.get(op.node);if(s?.maintenance?.withdraw){const resume=el('button','Resume announcements');resume.type='button';resume.disabled=busy;resume.dataset.focusKey='resume-'+op.node;resume.addEventListener('click',()=>openAction(op.node,samples.get(op.node)));panel.append(resume);}}panel.append(details);return panel;}
 function recordOperation(id,op){let rows=operations.get(id)||[];const old=rows.find(x=>x.requestID===op.requestID);if(old)Object.assign(old,op);else rows.push(op);operations.set(id,rows);render();}
 function outcome(result,requestID,action){const op=result?.operation;if(op?.request_id!==requestID||op?.action!==action)return 'unconfirmed';if(op.confirmed===true&&op.status==='confirmed')return 'confirmed';if(action==='bgp-apply'&&op.confirmed===false&&op.status==='rolled_back'&&result.bgp)return 'restored';return 'unconfirmed';}
 dialog.addEventListener('close',()=>{const button=grid.querySelector('[data-focus-key="'+CSS.escape(opener||'')+'"]')||grid.querySelector('[data-node-action="'+selection?.id+'"]');if(button&&!button.disabled)button.focus();});
 document.getElementById('maintenance-form').onsubmit=async e=>{e.preventDefault();if(!selection||busy||!selection.allowed)return;const selected=selection;dialog.close();busy=true;refresh.disabled=true;const version=epoch,id=crypto.randomUUID(),op={action:selected.action,node:selected.id,requestID:id,submitted:new Date().toISOString(),outcome:'applying',message:'Applying '+selected.action+' and verifying announcements…'};recordOperation(selected.id,op);message.textContent=op.message;try{const s=await request('nodes/'+selected.id+'/maintenance','POST',{action:selected.action,request_id:id,expected_withdraw:String(selected.expected),confirm_node:selected.id});if(version!==epoch)return;op.outcome=outcome(s,id,selected.action);op.message=op.outcome==='confirmed'?'Verified: '+selected.id+' '+(selected.action==='drain'?'announcements withdrawn.':'announcements resumed.'):'Operation unconfirmed. Refresh observes current state; it cannot confirm this operation. Do not repeat blindly.';if(op.outcome==='confirmed'){samples.set(selected.id,s);failures.delete(selected.id);}}catch(e){if(version!==epoch)return;op.outcome=e.outcome||'unconfirmed';op.code=e.code;op.status=e.status;op.message=op.outcome==='rejected'?'Rejected before apply: '+e.message+'.':'Operation unconfirmed: '+e.message+'. Refresh and inspect; do not repeat blindly.';}finally{if(version===epoch){busy=false;refresh.disabled=false;recordOperation(selected.id,op);message.textContent=op.message;grid.querySelector('[data-node-action="'+selected.id+'"]')?.focus();}}};
 window.addEventListener('beforeunload',e=>{if([...operations.values()].flat().some(o=>o.outcome==='applying'||o.outcome==='unconfirmed')){e.preventDefault();e.returnValue='';}});
 refresh.onclick=load;
 window.addEventListener('agentconnected',()=>{epoch++;busy=false;samples.clear();failures.clear();operations.clear();signedIn=window.secDNSAgent?.kind==='human';refresh.disabled=!signedIn;if(signedIn)load();else{render();message.textContent='Node management requires a human administrator session.';}});
 window.addEventListener('agentexpired',()=>{epoch++;busy=false;signedIn=false;samples.clear();failures.clear();operations.clear();render();refresh.disabled=true;dialog.close();message.textContent='Sign in to view node status.';});
 setInterval(()=>{if(!document.hidden&&samples.size&&!busy)render();},15000);
 window.secDNSNodeConsole={request,refresh:load,names,inventory:ids,recordOperation,outcome};
 if(window.secDNSAgent?.kind==='human'){signedIn=true;load();}
})();

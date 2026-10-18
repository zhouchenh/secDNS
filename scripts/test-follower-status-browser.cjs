'use strict';
// Synthetic loopback-only fixture; it never contacts a configured authority.
const assert=require('node:assert/strict'),http=require('node:http'),fs=require('node:fs'),path=require('node:path');
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const assets=path.join(__dirname,'../internal/listeners/servers/http/admin/server');
let calls=0,mode='normal',pending=null,origin='',malformed=null;
const sample=()=>({scope:'local_follower_workers',observed_at:'2026-10-18T12:00:00Z',stale_after_seconds:90,followers:[{store:'<img src=x onerror=alert(1)>',node_id:'node-one',ruleset_id:'rules',lineage_id:'lineage',authority_epoch:'epoch',accepted:true,revision:'18446744073709551615',content_sha256:'a'.repeat(64),last_accepted_at:null,last_contact_at:'2026-10-18T11:58:00Z',contact_freshness:'stale',connection:'backoff',error_category:'transport',store_state:'available'}]});
const server=http.createServer((req,res)=>{
 const send=(status,data)=>{res.writeHead(status,{'Content-Type':'application/json','Cache-Control':'no-store'});res.end(JSON.stringify(data));};
 if(req.url==='/admin/auth/state'){send(200,{agent_access:false,human_access:false});return;}
 if(req.url==='/admin/followers'){
  calls++;assert.equal(req.headers.authorization,'Bearer synthetic-admin');assert.equal(req.method,'GET');
  if(mode==='delayed'){pending=()=>send(200,sample());return;}
  if(mode==='failure'){send(503,{error:'status_unavailable'});return;}
  if(mode==='denied'){send(403,{error:'scope_required'});return;}
  send(200,malformed||sample());return;
 }
 const routes={'/admin/ui/followers/':'follower_ui/index.html','/admin/ui/followers/app.js':'follower_ui/app.js','/admin/ui/followers/style.css':'follower_ui/style.css','/admin/auth/agent.js':'auth_ui/agent.js','/admin/auth/human.js':'auth_ui/human.js','/admin/auth/passkey.js':'auth_ui/passkey.js','/admin/auth/auth.css':'auth_ui/auth.css'};
 const file=routes[req.url];if(!file){res.writeHead(404);res.end();return;}
 res.setHeader('Content-Type',file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':'text/html');res.end(fs.readFileSync(path.join(assets,file)));
});
(async()=>{
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));origin='http://127.0.0.1:'+server.address().port;
 const browser=await chromium.launch({headless:true});
 try{
  const context=await browser.newContext(),page=await context.newPage(),errors=[];
  page.on('pageerror',e=>errors.push(e.message));page.on('request',r=>assert.equal(new URL(r.url()).origin,origin));
  await page.goto(origin+'/admin/ui/followers/');assert.equal(calls,0);await page.locator('#token').fill('synthetic-admin');await page.getByRole('button',{name:'Connect',exact:true}).click();
  await page.getByText('Read-only local worker sample received.',{exact:true}).waitFor();assert.equal(calls,1);
  assert((await page.locator('#rows').textContent()).includes('18446744073709551615'));assert.equal(await page.locator('#rows img').count(),0);assert((await page.locator('#rows').textContent()).includes('Not observed in this process'));
  await page.waitForTimeout(300);assert.equal(calls,1,'no background refresh');
  for(const mutate of [
   d=>d.followers[0].revision='01',d=>d.followers[0].revision='18446744073709551616',
   d=>d.observed_at='10/18/2026',d=>d.observed_at=1,d=>d.observed_at='2026-02-30T12:00:00Z',
   d=>d.followers[0].content_sha256='A'.repeat(64),d=>d.followers[0].accepted=false,
   d=>d.followers[0].revision='0',d=>{d.followers[0].last_accepted_at='2026-10-18T11:57:00Z';d.followers[0].last_contact_at=null;}
  ]){malformed=sample();mutate(malformed);await page.locator('#refresh').click();await page.waitForFunction(()=>document.getElementById('status').textContent.startsWith('Invalid status response.'));assert((await page.locator('#rows').textContent()).includes('18446744073709551615'),'malformed response cannot replace prior sample');}
  malformed=null;
  mode='failure';await page.locator('#refresh').click();await page.waitForFunction(()=>document.getElementById('status').textContent.includes('current state is unknown'));assert((await page.locator('#rows').textContent()).includes('node-one'),'retain labelled previous sample');
  mode='delayed';await page.locator('#refresh').click();await page.waitForFunction(()=>document.getElementById('status').textContent.includes('Reading'));
  while(!pending)await new Promise(r=>setTimeout(r,5));await page.locator('#disconnect').click();pending();pending=null;await page.waitForTimeout(100);assert.equal(await page.locator('#rows').textContent(),'','late disconnected result discarded');
  mode='normal';await page.locator('#token').fill('synthetic-admin');await page.getByRole('button',{name:'Connect',exact:true}).click();await page.getByText('Read-only local worker sample received.',{exact:true}).waitFor();
  mode='delayed';await page.locator('#refresh').click();while(!pending)await new Promise(r=>setTimeout(r,5));await page.evaluate(()=>dispatchEvent(new Event('agentexpired')));pending();pending=null;await page.waitForTimeout(100);assert.equal(await page.locator('#rows').textContent(),'','expired result discarded');
  mode='denied';await page.locator('#token').fill('synthetic-admin');await page.getByRole('button',{name:'Connect',exact:true}).click();await page.getByText('Authentication or records:read permission is required.',{exact:true}).waitFor();assert.equal(await page.locator('#rows').textContent(),'');
  await page.setViewportSize({width:390,height:844});mode='normal';await page.locator('#token').fill('synthetic-admin');await page.getByRole('button',{name:'Connect',exact:true}).click();await page.getByText('Read-only local worker sample received.',{exact:true}).waitFor();assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'mobile fits');
  assert.equal(await page.evaluate(()=>localStorage.length+sessionStorage.length),0);assert.equal(await page.locator('#token').inputValue(),'');assert.deepEqual(errors,[]);console.log('PASS follower status: manual read, uint64 fidelity, inert labels, retained failure sample, disconnect/expiry race, denial, mobile, no persistence/external request');await context.close();
 }finally{await browser.close();await new Promise(resolve=>server.close(resolve));}
})().catch(e=>{console.error(e);server.close();process.exitCode=1;});
